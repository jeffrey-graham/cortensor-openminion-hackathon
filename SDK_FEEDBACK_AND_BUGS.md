# OpenMinion 0.1.18 SDK Feedback, Building-Block Findings & Reproducible Bug Report

> **Target Event:** Cortensor Hackathon #5 (`https://dorahacks.io/hackathon/2418/detail`)  
> **Evaluated Package:** `openminion==0.1.18` (Python 3.11 / 3.12)  
> **Verification Suite:** `pytest tests/test_sdk_bugs_repro.py -v` (automated reproduction of upstream behavior + verification of runtime patches in [`src/cortensor_sentinel/cortensor_compat.py`](src/cortensor_sentinel/cortensor_compat.py))

---

## Executive Summary

While building **Cortensor Sentinel** (an On-Chain Smart-Contract Risk & Cortensor RPC/Router Health Verifier Agent), we systematically exercised OpenMinion `0.1.18`'s core building blocks:
1. **`APIRuntime` & `OpenMinionConfig`** (embedded single-process lifecycle & SQLite run persistence)
2. **Cortensor Provider Adapter (`CortensorProvider`)** (`/api/v2/completions` router mode, `/v1/chat/completions` portal mode, session pool failover, and off-chain `urn:blob` retry polling)
3. **Structured `@tool` Execution & Action Policy (`PolicyCtl`)** (`forced_tools`, `approval_callback`, and risk classification)
4. **Typed Output Validation (`output_type=ContractRiskReport`)** (`AgentOutputValidationError`, `ProviderError`, `TurnTimeoutError`)
5. **Multi-Agent Delegation (`subagent()` & `Handoff()`)** (`transfer_to_<agent>` peer delegation and isolated subagent contexts)
6. **Streamed Turn Handles (`APIRuntime.submit_turn()`)** (`RuntimeTurnHandle`, `TurnChunk`, `TurnResponse`)

Below we document **what worked well**, **8 concrete, reproducible bugs & DX rough edges** (with exact file paths and line numbers in `openminion==0.1.18`), and **drop-in patches** implemented in [`src/cortensor_sentinel/cortensor_compat.py`](src/cortensor_sentinel/cortensor_compat.py).

---

## Part 1: What Worked Well in OpenMinion 0.1.18

- **Cortensor Session Pool Failover & Off-Chain URN Polling (`adapter.py:292-418`)**: `CortensorProvider._resolve_session_candidates` and `_post_with_retries` cleanly iterate across `dedicated_session_ids` / `ephemeral_session_ids` (e.g., failing over from Miner Session `101` to Session `102` on HTTP 502) and automatically extend `max_attempts` to `_OFFCHAIN_RESULT_MIN_WAIT_ATTEMPTS = 6` when an off-chain `urn:blob` result is still pending.
- **Prose-Wrapped JSON Extraction (`agent.py:264-272`)**: `Agent._coerce_output` uses `_extract_json_object(text)` when `model_validate_json(text)` initially fails.
- **Typed Error Hierarchy (`ProviderError`, `TurnTimeoutError`, `AgentOutputValidationError`)**: Clean separation of transport/provider failures, turn deadline expiration, and schema coercion failure.
- **Temporary Tool Registration Rollback (`agent.py:216-238`)**: Reliable rollback of `@tool` and `Handoff` registrations in a `finally` block.

---

## Part 2: Reproducible Bugs Discovered in `openminion==0.1.18` (Bonus Track)

### Bug #1: `CortensorProvider._parse_response_payload` Ignores `tool_call_strategy` and Hardcodes `fallback_enabled=False`
- **Location:** `src/openminion/modules/llm/providers/cortensor/adapter.py`, lines `291`, `453`, and `470`
- **Fix Implemented (`cortensor_compat.py:51-100`):** Compute `effective_fallback = bool(request.tools and supports_fallback_tool_calling(tool_call_strategy) and has_fallback_markers)` and pass `fallback_enabled=effective_fallback`.

### Bug #2: `CortensorProvider._complete_via_openai_chat_mode` Omits `http_client_for_config(self._http_client, config)`
- **Location:** `src/openminion/modules/llm/providers/cortensor/adapter.py`, lines `261-279` vs lines `333-344`
- **Fix Implemented (`cortensor_compat.py:113-163`):** Pass `http_client=http_client_for_config(self._http_client, config)` in `_complete_via_openai_chat_mode`.

### Bug #3: `CortensorProvider._resolve_max_tokens` Enforces an Unconditional `4096` Floor Even When Caller Explicitly Requests Fewer Tokens
- **Location:** `src/openminion/modules/llm/providers/cortensor/adapter.py`, lines `645-671`
- **Fix Implemented (`cortensor_compat.py:166-179`):** Return `explicit_max_tokens` directly when `request.max_output_tokens` or `request.metadata["max_tokens"]` is explicitly set (`> 0`).

### Bug #4: `CortensorProvider._normalize_cortensor_base_url` Corrupts `/api/v1/chat/completions` Endpoints Into `/api/v2/chat/completions`
- **Location:** `src/openminion/modules/llm/providers/cortensor/adapter.py`, lines `844-867`
- **Fix Implemented (`cortensor_compat.py:182-193`):** Preserve `/api/v1` when the URL path explicitly targets `/chat/completions`.

### Bug #5: `CortensorProvider.complete` Auto-Fallback From `cortensor_completion` to `openai_chat` Records Stale `api_mode` in `normalization_meta`
- **Location:** `src/openminion/modules/llm/providers/cortensor/adapter.py`, lines `160-181` and `229`

### Bug #6: `CortensorProvider.healthcheck` Is a Hardcoded Stub (`del config; return {"ok": True}`)
- **Location:** `src/openminion/modules/llm/providers/cortensor/adapter.py`, lines `910-912`
- **Fix Implemented (`cortensor_compat.py:196-220`):** Validate `api_mode` and `_resolve_session_candidates` inside `CortensorProvider.healthcheck`.

---

## Part 3: Developer Experience (DX) & Architecture Findings

### Finding #7: Public `OpenMinionConfig` Export Cannot Configure an Agent Without Importing Private `openminion.base.config` Internals
### Finding #8: Cross-Thread Shared-Runtime `Handoff` Deadlock Guard When Target Agent Registers `@tool` Functions
