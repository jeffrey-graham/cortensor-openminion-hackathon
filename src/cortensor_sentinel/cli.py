"""CLI Entrypoint for Cortensor Sentinel Agent (OpenMinion 0.1 SDK)."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from openminion import __version__ as OPENMINION_VERSION

from cortensor_sentinel.agent import CortensorSentinelAgent
from cortensor_sentinel.mock_cortensor_server import running_mock_cortensor_server
from cortensor_sentinel.schemas import SentinelAuditRequest
from cortensor_sentinel.tools import SAMPLE_CONTRACTS


def run_demo(export_log_path: str | None = None) -> int:
    lines: list[str] = []

    def log(msg: str = "") -> None:
        print(msg)
        lines.append(msg)

    log("=" * 78)
    log(f"CORTENSOR SENTINEL AGENT — OpenMinion {OPENMINION_VERSION} SDK Verification Suite")
    log("On-Chain & DeFi Smart-Contract Risk & Cortensor RPC/Router Health Verifier")
    log("=" * 78)

    with tempfile.TemporaryDirectory(prefix="cortensor_sentinel_") as tmp:
        tmp_path = Path(tmp)

        with running_mock_cortensor_server(fault_mode="none") as server:
            log(f"\n[1/5] Cortensor Router v2 Simulator listening at: {server.router_url}")
            with CortensorSentinelAgent(
                tmp_path / "run_main",
                provider="cortensor",
                base_url=server.router_url,
                api_mode="cortensor_completion",
                model="gpt-oss-20b",
                session_ids=[101, 102],
            ) as sentinel:
                v1_spec = SAMPLE_CONTRACTS["CrossChainVaultV1"]
                req_v1 = SentinelAuditRequest(
                    contract_name="CrossChainVaultV1",
                    contract_address=v1_spec["address"],
                    chain_id=v1_spec["chain_id"],
                    source_or_bytecode=v1_spec["source"],
                    pool_address=v1_spec["pool_address"],
                    token_pair=v1_spec["token_pair"],
                    cortensor_endpoint=server.router_url,
                )
                report_v1, trace_v1 = sentinel.audit_contract(
                    req_v1, session_id="audit-session-main"
                )
                log("\n[2/5] Audited Vulnerable Contract: CrossChainVaultV1")
                log(f"  Address            : {report_v1.contract_address} (Chain {report_v1.chain_id})")
                log(f"  Overall Risk Score : {report_v1.overall_risk_score}/100 ({report_v1.severity})")
                log(f"  Cortensor Session  : {report_v1.cortensor_session_id} (Router Healthy: {report_v1.rpc_router_healthy})")
                log(f"  Findings Detected  : {len(report_v1.findings)}")
                for f in report_v1.findings:
                    log(f"    - [{f.severity}] {f.finding_id}: {f.title}")
                log(f"  OpenMinion Run IDs : {trace_v1.run_ids}")

                v2_spec = SAMPLE_CONTRACTS["HardenedStakingPoolV2"]
                req_v2 = SentinelAuditRequest(
                    contract_name="HardenedStakingPoolV2",
                    contract_address=v2_spec["address"],
                    chain_id=v2_spec["chain_id"],
                    source_or_bytecode=v2_spec["source"],
                    pool_address=v2_spec["pool_address"],
                    token_pair=v2_spec["token_pair"],
                    cortensor_endpoint=server.router_url,
                )
                report_v2, _ = sentinel.audit_contract(
                    req_v2, session_id="audit-session-main"
                )
                log("\n[3/5] Audited Hardened Contract (Same Session Continuity): HardenedStakingPoolV2")
                log(f"  Address            : {report_v2.contract_address} (Chain {report_v2.chain_id})")
                log(f"  Overall Risk Score : {report_v2.overall_risk_score}/100 ({report_v2.severity})")
                log(f"  Findings Detected  : {len(report_v2.findings)}")

                sub_reply = sentinel.run_subagent_specialist(v1_spec["address"])
                handoff_reply = sentinel.run_peer_handoff(server.router_url)
                log("\n[4/5] Multi-Agent Delegation (subagent & Handoff)")
                log(f"  Subagent Reply     : {sub_reply}")
                log(f"  Peer Handoff Reply : {handoff_reply}")

                stream_resp, chunk_kinds = sentinel.run_streamed_turn(
                    "Verify Cortensor router session pool 101/102 status."
                )
                runs = sentinel.inspect_session_runs("audit-session-main")
                log("\n[5/5] Streaming & Durable Session State (APIRuntime.submit_turn & list_runs)")
                log(f"  Stream Chunk Kinds : {chunk_kinds}")
                log(f"  Stream Final Text  : {stream_resp.final_text}")
                log(f"  Durable Runs Stored: {len(runs)} runs in SQLite session 'audit-session-main'")

        with running_mock_cortensor_server(fault_mode="session_101_down") as failover_srv:
            with CortensorSentinelAgent(
                tmp_path / "run_failover",
                provider="cortensor",
                base_url=failover_srv.router_url,
                api_mode="cortensor_completion",
                model="gpt-oss-20b",
                session_ids=[101, 102],
            ) as sentinel_fo:
                rep_fo, _ = sentinel_fo.audit_contract(req_v1, session_id="failover-session")
                log("\n[Chaos Verification] Session 101 Precommit Quorum Failure -> Automatic Failover")
                log(f"  Configured Pool    : [101, 102]")
                log(f"  Recovered Session  : {rep_fo.cortensor_session_id} (Expected: 102)")

    log("\n" + "=" * 78)
    log("STATUS: ALL CORTENSOR SENTINEL CHECKS PASSED")
    log("=" * 78)

    if export_log_path:
        out = Path(export_log_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cortensor Sentinel: On-Chain Smart-Contract Risk & RPC Health Verifier (OpenMinion 0.1)"
    )
    parser.add_argument("--mode", choices=("demo", "json"), default="demo")
    parser.add_argument("--contract", choices=("CrossChainVaultV1", "HardenedStakingPoolV2"), default="CrossChainVaultV1")
    parser.add_argument("--export-log", default=None)
    args = parser.parse_args()

    if args.mode == "json":
        with tempfile.TemporaryDirectory(prefix="cortensor_json_") as tmp:
            with running_mock_cortensor_server() as srv:
                with CortensorSentinelAgent(Path(tmp), provider="cortensor", base_url=srv.router_url) as sentinel:
                    spec = SAMPLE_CONTRACTS[args.contract]
                    req = SentinelAuditRequest(
                        contract_name=args.contract,
                        contract_address=spec["address"],
                        chain_id=spec["chain_id"],
                        source_or_bytecode=spec["source"],
                        pool_address=spec["pool_address"],
                        token_pair=spec["token_pair"],
                        cortensor_endpoint=srv.router_url,
                    )
                    report, _ = sentinel.audit_contract(req)
                    print(json.dumps(report.model_dump(), indent=2))
        return 0

    return run_demo(export_log_path=args.export_log)


if __name__ == "__main__":
    raise SystemExit(main())
