"""Deterministic Local Cortensor Router (/api/v2/completions) & Portal (/v1/chat/completions) Simulator."""

from __future__ import annotations

import json
import re
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterator

from cortensor_sentinel.tools import SAMPLE_CONTRACTS, analyze_contract_findings


class LocalCortensorMockServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, fault_mode: str = "none") -> None:
        super().__init__(("127.0.0.1", 0), _CortensorHandler)
        self.fault_mode = fault_mode
        self.requests_log: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._fault_counter = 0
        self._tool_call_rounds = 0

    @property
    def router_url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}/api/v2/completions"

    @property
    def portal_url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}/v1"

    def record_request(self, path: str, payload: dict[str, Any]) -> int:
        with self._lock:
            self.requests_log.append({"path": path, "payload": payload, "ts": time.time()})
            self._fault_counter += 1
            return self._fault_counter


def _build_assistant_reply(payload: dict[str, Any], path: str) -> dict[str, Any]:
    messages = payload.get("messages") or []
    prompt_text = str(payload.get("prompt") or "")
    session_id = int(payload.get("session_id") or 101)
    model = str(payload.get("model") or "gpt-oss-20b")

    offered_tools: list[str] = []
    for t in payload.get("tools") or []:
        if isinstance(t, dict) and t.get("type") == "function":
            fn_name = t.get("function", {}).get("name")
            if fn_name:
                offered_tools.append(str(fn_name))
    if not offered_tools and prompt_text:
        for candidate in (
            "transfer_to_rpc_diagnoser",
            "audit_smart_contract_bytecode",
            "verify_cortensor_rpc_health",
            "inspect_liquidity_and_oracle_risk",
            "generate_remediation_plan",
        ):
            if candidate in prompt_text:
                offered_tools.append(candidate)

    has_tool_result = any(m.get("role") == "tool" for m in messages if isinstance(m, dict))
    if not has_tool_result and prompt_text:
        if any(
            marker in prompt_text
            for marker in (
                "Successful tool calls already completed in this turn:",
                "finding_count",
                "Cortensor Sentinel [session=",
                '"ok": true',
                "delegated reply",
            )
        ):
            has_tool_result = True

    combined_text = prompt_text or " ".join(
        str(m.get("content") or "") for m in messages if isinstance(m, dict)
    )

    if "Classify freshness sensitivity semantically" in combined_text:
        fresh_json = json.dumps({"freshness_sensitive": False, "reason": "deterministic_static_audit"})
        return {
            "id": f"cortensor-fresh-{session_id}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": fresh_json},
                    "text": fresh_json,
                }
            ],
            "usage": {"prompt_tokens": 48, "completion_tokens": 12, "total_tokens": 60},
        }

    if offered_tools and not has_tool_result:
        chosen_tool = offered_tools[0]
        if "transfer_to_rpc_diagnoser" in offered_tools:
            chosen_tool = "transfer_to_rpc_diagnoser"
            tool_args: dict[str, Any] = {
                "message": "Verify Cortensor Router v2 session pool 101/102 and precommit headroom."
            }
        elif "audit_smart_contract_bytecode" in offered_tools:
            chosen_tool = "audit_smart_contract_bytecode"
            addr_match = re.search(r"0x[a-fA-F0-9]{40}", combined_text)
            address = addr_match.group(0) if addr_match else SAMPLE_CONTRACTS["CrossChainVaultV1"]["address"]
            is_hardened = "hardened" in combined_text.lower() or "1111111254" in address.lower()
            source = (
                SAMPLE_CONTRACTS["HardenedStakingPoolV2"]["source"]
                if is_hardened
                else SAMPLE_CONTRACTS["CrossChainVaultV1"]["source"]
            )
            tool_args = {
                "contract_address": address,
                "bytecode_or_source": source,
                "chain_id": 42161 if is_hardened else 1,
            }
        elif "verify_cortensor_rpc_health" in offered_tools:
            chosen_tool = "verify_cortensor_rpc_health"
            tool_args = {
                "endpoint_url": "http://127.0.0.1:8080/api/v2/completions",
                "check_session_pool": True,
            }
        elif "inspect_liquidity_and_oracle_risk" in offered_tools:
            chosen_tool = "inspect_liquidity_and_oracle_risk"
            tool_args = {
                "pool_address": "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640",
                "token_pair": "WETH/USDC",
            }
        else:
            tool_args = {}

        return {
            "id": f"cortensor-call-{session_id}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": f"call_{chosen_tool}_1",
                                "type": "function",
                                "function": {
                                    "name": chosen_tool,
                                    "arguments": json.dumps(tool_args),
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 142, "completion_tokens": 38, "total_tokens": 180},
        }

    wants_contract_report = (
        "overall_risk_score" in combined_text
        or "ContractRiskReport" in combined_text
        or "contract_address" in combined_text
    )

    if not wants_contract_report:
        reply_text = (
            f"Cortensor Sentinel [session={session_id}] verified endpoint health (latency=14.2ms, "
            "dedicated_sessions=[101, 102], precommit_headroom=120s OK) and completed bounded inspection."
        )
        return {
            "id": f"cortensor-cmpl-{session_id}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": reply_text},
                    "text": reply_text,
                }
            ],
            "usage": {"prompt_tokens": 96, "completion_tokens": 32, "total_tokens": 128},
        }

    addr_match = re.search(r"0x[a-fA-F0-9]{40}", combined_text)
    address = addr_match.group(0) if addr_match else SAMPLE_CONTRACTS["CrossChainVaultV1"]["address"]
    is_hardened = "hardened" in combined_text.lower() or "1111111254" in address.lower()
    contract_key = "HardenedStakingPoolV2" if is_hardened else "CrossChainVaultV1"
    analysis = analyze_contract_findings(
        contract_address=address,
        bytecode_or_source=SAMPLE_CONTRACTS[contract_key]["source"],
        chain_id=42161 if is_hardened else 1,
    )

    report_payload = {
        "contract_address": address,
        "chain_id": analysis["chain_id"],
        "overall_risk_score": analysis["risk_score"],
        "severity": analysis["overall_severity"],
        "rpc_router_healthy": True,
        "cortensor_session_id": session_id,
        "findings": analysis["findings"],
        "recommended_actions": (
            [
                "Enforce Checks-Effects-Interactions and OpenZeppelin ReentrancyGuard on withdrawAll().",
                "Restrict upgradeAndCall() with onlyOwner + 48h TimelockController and remove arbitrary delegatecall.",
                "Validate Chainlink latestRoundData() updatedAt heartbeat (<=3600s) and answer > 0.",
                "Replace unchecked low-level ERC-20 call with SafeERC20.safeTransfer().",
            ]
            if not is_hardened
            else [
                "Maintain 48h TimelockController monitoring and periodic Cortensor Sentinel RPC verification."
            ]
        ),
        "summary": (
            f"Cortensor Sentinel audited {address} (session {session_id}): "
            f"detected {analysis['finding_count']} findings with overall risk score "
            f"{analysis['risk_score']}/100 ({analysis['overall_severity']})."
        ),
    }
    json_str = json.dumps(report_payload)
    return {
        "id": f"cortensor-report-{session_id}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": json_str},
                "text": json_str,
            }
        ],
        "usage": {"prompt_tokens": 210, "completion_tokens": 165, "total_tokens": 375},
    }


class _CortensorHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: LocalCortensorMockServer

    def do_GET(self) -> None:  # noqa: N802
        if self.path.endswith("/health"):
            self._send_json(
                200,
                {
                    "ok": True,
                    "router": "cortensor-v2-simulator",
                    "active_sessions": [101, 102, 204],
                },
            )
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        content_len = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(content_len) if content_len > 0 else b"{}"
        payload = json.loads(raw_body.decode("utf-8", errors="replace") or "{}")
        call_num = self.server.record_request(self.path, payload)
        fault = self.server.fault_mode

        if fault == "always_401":
            self._send_json(401, {"error": {"code": "AUTH_ERROR", "message": "Invalid CORTENSOR_API_KEY"}})
            return
        if fault == "rate_limit_once" and call_num == 1:
            self._send_json(429, {"error": {"code": "RATE_LIMITED", "message": "Cortensor router rate limit exceeded, try again"}})
            return
        if fault == "urn_pending_once" and call_num == 1:
            self._send_json(
                200,
                {
                    "status": "pending",
                    "urn": "urn:blob:cortensor:offchainresult991",
                    "message": "off-chain result unavailable (still processing)",
                    "choices": [],
                },
            )
            return
        if fault == "session_101_down" and int(payload.get("session_id") or 0) == 101:
            self._send_json(502, {"error": {"message": "Miner session 101 precommit quorum failed"}})
            return
        if fault == "malformed_json_once":
            prompt_str = str(payload.get("prompt", ""))
            if "Available tools:\n- audit_smart_contract_bytecode" in prompt_str and "Successful tool calls already completed" not in prompt_str:
                self.server._tool_call_rounds += 1
            elif self.server._tool_call_rounds == 1 and (
                "Successful tool calls already completed" in prompt_str
                or "finding_count" in prompt_str
            ):
                self._send_json(
                    200,
                    {
                        "id": "bad-json",
                        "object": "chat.completion",
                        "model": "gpt-oss-20b",
                        "choices": [
                            {
                                "index": 0,
                                "finish_reason": "stop",
                                "message": {"role": "assistant", "content": "NOT_VALID_JSON_OUTPUT"},
                                "text": "NOT_VALID_JSON_OUTPUT",
                            }
                        ],
                    },
                )
                return

        response_payload = _build_assistant_reply(payload, self.path)
        self._send_json(200, response_payload)

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        encoded = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


@contextmanager
def running_mock_cortensor_server(
    fault_mode: str = "none",
) -> Iterator[LocalCortensorMockServer]:
    server = LocalCortensorMockServer(fault_mode=fault_mode)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)
