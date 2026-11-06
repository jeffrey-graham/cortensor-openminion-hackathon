"""End-to-end automated tests for CortensorSentinelAgent on OpenMinion 0.1.18."""

from __future__ import annotations

import json
from pathlib import Path

from cortensor_sentinel.agent import CortensorSentinelAgent
from cortensor_sentinel.mock_cortensor_server import running_mock_cortensor_server
from cortensor_sentinel.schemas import ContractRiskReport, SentinelAuditRequest
from cortensor_sentinel.tools import (
    SAMPLE_CONTRACTS,
    audit_smart_contract_bytecode,
    generate_remediation_plan,
    inspect_liquidity_and_oracle_risk,
    verify_cortensor_rpc_health,
)


def _make_request(contract_key: str, endpoint_url: str) -> SentinelAuditRequest:
    spec = SAMPLE_CONTRACTS[contract_key]
    return SentinelAuditRequest(
        contract_name=contract_key,
        contract_address=spec["address"],
        chain_id=spec["chain_id"],
        source_or_bytecode=spec["source"],
        pool_address=spec["pool_address"],
        token_pair=spec["token_pair"],
        cortensor_endpoint=endpoint_url,
    )


def test_deterministic_tools_execute_directly() -> None:
    for fn in (
        audit_smart_contract_bytecode,
        verify_cortensor_rpc_health,
        inspect_liquidity_and_oracle_risk,
        generate_remediation_plan,
    ):
        assert hasattr(fn, "tool_decl")
        assert hasattr(fn, "tool_family_spec")

    audit_json = json.loads(
        audit_smart_contract_bytecode(
            SAMPLE_CONTRACTS["CrossChainVaultV1"]["address"],
            SAMPLE_CONTRACTS["CrossChainVaultV1"]["source"],
            1,
        )
    )
    assert audit_json["finding_count"] == 4
    assert audit_json["overall_severity"] == "CRITICAL"
    assert audit_json["risk_score"] == 100


def test_vulnerable_and_hardened_audits_and_session_continuity(tmp_path: Path) -> None:
    with running_mock_cortensor_server(fault_mode="none") as server:
        with CortensorSentinelAgent(
            tmp_path / "sentinel",
            provider="cortensor",
            base_url=server.router_url,
            session_ids=[101, 102],
        ) as sentinel:
            req_vuln = _make_request("CrossChainVaultV1", server.router_url)
            report_vuln, trace_vuln = sentinel.audit_contract(
                req_vuln, session_id="shared-audit-session"
            )
            assert isinstance(report_vuln, ContractRiskReport)
            assert report_vuln.overall_risk_score == 100
            assert report_vuln.severity == "CRITICAL"
            assert len(report_vuln.findings) == 4
            assert report_vuln.cortensor_session_id == 101
            assert trace_vuln.fallback_triggered is False

            req_safe = _make_request("HardenedStakingPoolV2", server.router_url)
            report_safe, trace_safe = sentinel.audit_contract(
                req_safe, session_id="shared-audit-session"
            )
            assert report_safe.overall_risk_score == 8
            assert report_safe.severity == "LOW"
            assert len(report_safe.findings) == 0
            assert trace_safe.fallback_triggered is False

            runs = sentinel.inspect_session_runs("shared-audit-session")
            assert len(runs) == 2


def test_subagent_and_peer_handoff_delegation(tmp_path: Path) -> None:
    with running_mock_cortensor_server(fault_mode="none") as server:
        with CortensorSentinelAgent(
            tmp_path / "delegation",
            provider="cortensor",
            base_url=server.router_url,
            session_ids=[101, 102],
        ) as sentinel:
            sub_text = sentinel.run_subagent_specialist(
                SAMPLE_CONTRACTS["CrossChainVaultV1"]["address"]
            )
            assert "Cortensor Sentinel" in sub_text
            assert "101" in sub_text

            handoff_text = sentinel.run_peer_handoff(server.router_url)
            assert "Cortensor Sentinel" in handoff_text


def test_streamed_turn_execution(tmp_path: Path) -> None:
    with running_mock_cortensor_server(fault_mode="none") as server:
        with CortensorSentinelAgent(
            tmp_path / "stream",
            provider="cortensor",
            base_url=server.router_url,
        ) as sentinel:
            seen_chunks: list[str] = []
            response, kinds = sentinel.run_streamed_turn(
                "Check Cortensor router status.",
                on_chunk=lambda c: seen_chunks.append(c.kind),
            )
            assert len(kinds) > 0
            assert seen_chunks == kinds
            assert "Cortensor Sentinel" in response.final_text


def test_cortensor_session_failover_and_urn_pending_retry(tmp_path: Path) -> None:
    with running_mock_cortensor_server(fault_mode="session_101_down") as server_fo:
        with CortensorSentinelAgent(
            tmp_path / "failover",
            provider="cortensor",
            base_url=server_fo.router_url,
            session_ids=[101, 102],
        ) as sentinel:
            req = _make_request("CrossChainVaultV1", server_fo.router_url)
            report, trace = sentinel.audit_contract(req)
            assert trace.fallback_triggered is False
            assert report.cortensor_session_id == 102

    with running_mock_cortensor_server(fault_mode="urn_pending_once") as server_urn:
        with CortensorSentinelAgent(
            tmp_path / "urn_retry",
            provider="cortensor",
            base_url=server_urn.router_url,
            session_ids=[101],
        ) as sentinel:
            req = _make_request("CrossChainVaultV1", server_urn.router_url)
            report, trace = sentinel.audit_contract(req)
            assert trace.fallback_triggered is False
            assert report.overall_risk_score == 100
            assert len(server_urn.requests_log) >= 2


def test_malformed_output_retry_and_auth_error_deterministic_fallback(tmp_path: Path) -> None:
    with running_mock_cortensor_server(fault_mode="malformed_json_once") as server_bad_json:
        with CortensorSentinelAgent(
            tmp_path / "bad_json",
            provider="cortensor",
            base_url=server_bad_json.router_url,
        ) as sentinel:
            req = _make_request("CrossChainVaultV1", server_bad_json.router_url)
            report, trace = sentinel.audit_contract(req, max_retries=2)
            assert trace.fallback_triggered is False
            assert trace.retries_used == 1
            assert any("AgentOutputValidationError" in ev for ev in trace.error_events)
            assert report.overall_risk_score == 100

    with running_mock_cortensor_server(fault_mode="always_401") as server_401:
        with CortensorSentinelAgent(
            tmp_path / "auth_401",
            provider="cortensor",
            base_url=server_401.router_url,
        ) as sentinel:
            req = _make_request("CrossChainVaultV1", server_401.router_url)
            report, trace = sentinel.audit_contract(req, max_retries=1)
            assert trace.fallback_triggered is True
            assert report.rpc_router_healthy is False
            assert report.overall_risk_score == 100
            assert "[DETERMINISTIC FALLBACK]" in report.summary
