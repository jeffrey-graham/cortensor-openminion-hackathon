"""Core CortensorSentinelAgent built on the OpenMinion 0.1 Python SDK."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from openminion import (
    APIRuntime,
    Agent,
    AgentOutputValidationError,
    AgentRunResult,
    Handoff,
    ProviderError,
    TurnTimeoutError,
    __version__ as OPENMINION_VERSION,
    subagent,
)
from openminion.api import TurnChunk, TurnResponse
from openminion.api.queries.runs import list_runs

from cortensor_sentinel.cortensor_compat import (
    apply_cortensor_adapter_fixes,
    build_sentinel_config,
)
from cortensor_sentinel.schemas import (
    ContractRiskReport,
    SentinelAuditRequest,
    VulnerabilityFinding,
)
from cortensor_sentinel.tools import (
    SAMPLE_CONTRACTS,
    analyze_contract_findings,
    audit_smart_contract_bytecode,
    generate_remediation_plan,
    inspect_liquidity_and_oracle_risk,
    verify_cortensor_rpc_health,
)


@dataclass
class SentinelExecutionTrace:
    openminion_version: str = OPENMINION_VERSION
    session_id: str = ""
    run_ids: list[str] = field(default_factory=list)
    tool_calls_forced: list[str] = field(default_factory=list)
    approved_tools: list[str] = field(default_factory=list)
    subagent_output: str | None = None
    handoff_output: str | None = None
    stream_chunk_kinds: list[str] = field(default_factory=list)
    retries_used: int = 0
    fallback_triggered: bool = False
    error_events: list[str] = field(default_factory=list)


class CortensorSentinelAgent:
    def __init__(
        self,
        work_dir: Path,
        *,
        provider: str = "cortensor",
        base_url: str = "http://127.0.0.1:8080/api/v2/completions",
        api_mode: str = "cortensor_completion",
        model: str = "gpt-oss-20b",
        session_ids: list[int] | None = None,
        apply_sdk_fixes: bool = True,
    ) -> None:
        self.work_dir = Path(work_dir)
        self.provider = provider
        self.base_url = base_url
        self.api_mode = api_mode
        self.model = model
        self.session_ids = session_ids or [101, 102]

        if apply_sdk_fixes:
            apply_cortensor_adapter_fixes()

        os.environ.setdefault("CORTENSOR_API_KEY", "cortensor-hackathon5-dev-key")
        self.config_path = build_sentinel_config(
            self.work_dir,
            provider=provider,
            base_url=base_url,
            api_mode=api_mode,
            model=model,
            session_ids=self.session_ids,
        )
        self.runtime = APIRuntime.from_config_path(
            str(self.config_path),
            home_root=self.work_dir,
            data_root=self.work_dir / "data",
        )

    def close(self) -> None:
        self.runtime.close()

    def __enter__(self) -> "CortensorSentinelAgent":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def audit_contract(
        self,
        request: SentinelAuditRequest,
        *,
        session_id: str = "sentinel-audit-session",
        max_retries: int = 2,
    ) -> tuple[ContractRiskReport, SentinelExecutionTrace]:
        trace = SentinelExecutionTrace(
            session_id=session_id,
            tool_calls_forced=["audit_smart_contract_bytecode"],
        )

        prompt = (
            f"Audit smart contract {request.contract_name} at {request.contract_address} "
            f"on chain {request.chain_id} and verify Cortensor endpoint {request.cortensor_endpoint}. "
            "Return JSON matching ContractRiskReport with contract_address, chain_id, "
            "overall_risk_score, severity, rpc_router_healthy, cortensor_session_id, findings, "
            "recommended_actions, and summary."
        )

        def _approve_tool(tool_name: str, _args: dict[str, Any], _approval_id: str) -> bool:
            trace.approved_tools.append(tool_name)
            return True

        attempt = 0
        while attempt <= max_retries:
            attempt += 1
            try:
                with Agent(
                    runtime=self.runtime,
                    agent_id="sentinel",
                    name="cortensor_sentinel",
                    session_id=session_id,
                    instructions=(
                        "You are Cortensor Sentinel, an on-chain smart-contract security and "
                        "Cortensor RPC/Router health verifier. Use the registered tools and return "
                        "strict JSON conforming to ContractRiskReport."
                    ),
                    tools=[
                        audit_smart_contract_bytecode,
                        verify_cortensor_rpc_health,
                        inspect_liquidity_and_oracle_risk,
                        generate_remediation_plan,
                    ],
                    forced_tools=["audit_smart_contract_bytecode"],
                    output_type=ContractRiskReport,
                ) as agent:
                    result: AgentRunResult[ContractRiskReport] = agent.run(
                        prompt,
                        approval_callback=_approve_tool,
                    )
                    if result.run_id:
                        trace.run_ids.append(result.run_id)
                    trace.retries_used = attempt - 1
                    return result.output, trace

            except AgentOutputValidationError as exc:
                trace.error_events.append(
                    f"attempt={attempt} AgentOutputValidationError: {exc.raw_text[:120]}"
                )
                if attempt <= max_retries:
                    continue
            except ProviderError as exc:
                trace.error_events.append(
                    f"attempt={attempt} ProviderError({exc.code}): {exc.message}"
                )
                if attempt <= max_retries and exc.code in {"TIMEOUT", "RATE_LIMITED", "EMPTY_PAYLOAD"}:
                    continue
            except TurnTimeoutError as exc:
                trace.error_events.append(
                    f"attempt={attempt} TurnTimeoutError: {exc}"
                )

            trace.fallback_triggered = True
            trace.retries_used = attempt - 1
            return self._deterministic_fallback_report(request), trace

        trace.fallback_triggered = True
        return self._deterministic_fallback_report(request), trace

    def run_subagent_specialist(
        self,
        contract_address: str,
        *,
        session_id: str = "sentinel-subagent-session",
    ) -> str:
        with Agent(
            runtime=self.runtime,
            agent_id="sentinel",
            name="sentinel_coordinator",
            session_id=session_id,
        ) as parent:
            specialist = subagent(
                parent,
                name="bytecode_specialist",
                instructions=(
                    "Inspect EVM bytecode and Cortensor session pool posture in two concise sentences."
                ),
                timeout_seconds=60,
            )
            res = specialist.run(
                f"Perform bounded bytecode & router check for {contract_address}."
            )
            return res.text

    def run_peer_handoff(
        self,
        endpoint_url: str = "http://127.0.0.1:8080/api/v2/completions",
        *,
        session_id: str = "sentinel-handoff-session",
    ) -> str:
        with Agent(
            runtime=self.runtime,
            agent_id="rpc_diagnoser",
            name="rpc_diagnoser",
            instructions="Diagnose Cortensor Router v2 session pools and precommit timeout headroom.",
        ) as diagnoser:
            with Agent(
                runtime=self.runtime,
                agent_id="sentinel",
                name="sentinel_coordinator",
                session_id=session_id,
                instructions="Delegate router health checks to rpc_diagnoser.",
                handoffs=[Handoff(target=diagnoser)],
                forced_tools=["transfer_to_rpc_diagnoser"],
            ) as coordinator:
                res = coordinator.run(
                    f"Delegate health verification for Cortensor endpoint {endpoint_url}.",
                    approval_callback=lambda _name, _args, _id: True,
                )
                return res.text

    def run_streamed_turn(
        self,
        message: str,
        *,
        session_id: str = "sentinel-stream-session",
        on_chunk: Callable[[TurnChunk], None] | None = None,
    ) -> tuple[TurnResponse, list[str]]:
        handle = self.runtime.submit_turn(
            payload={
                "message": message,
                "agent_id": "sentinel",
                "session_id": session_id,
                "timeout_seconds": 60.0,
                "deliver": False,
            }
        )
        chunk_kinds: list[str] = []
        for chunk in handle.stream():
            chunk_kinds.append(chunk.kind)
            if on_chunk is not None:
                on_chunk(chunk)
            if chunk.kind == "approval" and chunk.data.get("phase") == "requested":
                handle.resolve_approval(
                    approval_id=str(chunk.data["approval_id"]),
                    decision="allow_once",
                )
        response = handle.result(timeout_s=60.0)
        return response, chunk_kinds

    def inspect_session_runs(self, session_id: str) -> list[dict[str, Any]]:
        result = list_runs(None, session_id=session_id, runtime=self.runtime)
        return list(result.get("runs", []))

    @staticmethod
    def _deterministic_fallback_report(
        request: SentinelAuditRequest,
    ) -> ContractRiskReport:
        analysis = analyze_contract_findings(
            contract_address=request.contract_address,
            bytecode_or_source=request.source_or_bytecode
            or SAMPLE_CONTRACTS["CrossChainVaultV1"]["source"],
            chain_id=request.chain_id,
        )
        return ContractRiskReport(
            contract_address=request.contract_address,
            chain_id=request.chain_id,
            overall_risk_score=analysis["risk_score"],
            severity=analysis["overall_severity"],
            rpc_router_healthy=False,
            cortensor_session_id=0,
            findings=[VulnerabilityFinding(**f) for f in analysis["findings"]],
            recommended_actions=[
                "Deterministic local static analyzer executed because upstream Cortensor provider failed.",
                "Fix all CRITICAL/HIGH findings before mainnet deployment.",
            ],
            summary=(
                f"[DETERMINISTIC FALLBACK] Audited {request.contract_address}: "
                f"{analysis['finding_count']} findings, risk score {analysis['risk_score']}/100."
            ),
        )
