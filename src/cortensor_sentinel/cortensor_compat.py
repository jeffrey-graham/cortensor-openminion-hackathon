"""Compatibility & Bug-Fix Layer for OpenMinion 0.1.18 Cortensor Provider & Config SDK."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from openminion import OpenMinionConfig
from openminion.base.config import AgentProfileConfig, save_config
from openminion.modules.llm.providers.cortensor.adapter import CortensorProvider
from openminion.modules.llm.providers.cortensor.response_payloads import (
    _cortensor_fallback_sources,
    _cortensor_first_choice,
    _cortensor_response_text,
    _raise_empty_cortensor_response,
)
from openminion.modules.llm.providers.message_payloads import (
    _as_float,
    _as_int,
    _coerce_tool_calls,
    _resolve_tool_names,
    _usage_from_openai_like,
)
from openminion.modules.llm.providers.tool_calling import (
    resolve_tool_call_source_precedence,
    supports_fallback_tool_calling,
)
from openminion.modules.llm.providers.transport.client import http_client_for_config
from openminion.modules.llm.schemas import LLMRequest, ToolCall


_ORIGINAL_PARSE_RESPONSE_PAYLOAD = CortensorProvider._parse_response_payload
_ORIGINAL_COMPLETE_VIA_OPENAI_CHAT_MODE = CortensorProvider._complete_via_openai_chat_mode
_ORIGINAL_RESOLVE_MAX_TOKENS = CortensorProvider._resolve_max_tokens
_ORIGINAL_NORMALIZE_BASE_URL = CortensorProvider._normalize_cortensor_base_url
_ORIGINAL_BUILD_COMPLETION_PROMPT = CortensorProvider._build_completion_prompt
_ORIGINAL_HEALTHCHECK = CortensorProvider.healthcheck

_PATCHED = False


def _patched_parse_response_payload(
    self: CortensorProvider,
    *,
    response_payload: dict[str, Any],
    request: LLMRequest,
    tool_call_strategy: str,
    fallback_model: str,
    behavior_profile: Any,
) -> dict[str, Any]:
    first_choice = _cortensor_first_choice(response_payload)
    message_payload = first_choice.get("message")
    allowed_tool_names = _resolve_tool_names(request)
    raw_text_preview = _cortensor_response_text(
        first_choice=first_choice,
        message_payload=message_payload,
        response_payload=response_payload,
    )
    has_fallback_markers = any(
        marker in raw_text_preview
        for marker in ('"tool_calls"', "<tool_call", "[TOOL_CALL", "tool_name")
    )
    effective_fallback = bool(
        request.tools
        and supports_fallback_tool_calling(tool_call_strategy)
        and has_fallback_markers
    )
    tool_call_resolution = resolve_tool_call_source_precedence(
        message_payload=message_payload,
        fallback_sources=_cortensor_fallback_sources(
            first_choice=first_choice,
            message_payload=message_payload,
            response_payload=response_payload,
        ),
        provider_name=self.name,
        model_name=str(response_payload.get("model") or fallback_model),
        allowed_tool_names=allowed_tool_names if request.tools else None,
        fallback_enabled=effective_fallback,
        parser_plugin_selection=behavior_profile.parser_plugin_selection,
        fallback_parser_policy=behavior_profile.fallback_parser_policy,
    )
    tool_calls: list[ToolCall] = list(tool_call_resolution.calls)
    text = _cortensor_response_text(
        first_choice=first_choice,
        message_payload=message_payload,
        response_payload=response_payload,
    )
    tool_calls = _coerce_tool_calls(tool_calls)

    if not text and not tool_calls:
        _raise_empty_cortensor_response(
            first_choice=first_choice,
            message_payload=message_payload,
            response_payload=response_payload,
        )

    return {
        "text": text.strip(),
        "tool_calls": tool_calls,
        "tool_call_normalization": tool_call_resolution.as_metadata(),
        "usage": _usage_from_openai_like(response_payload.get("usage")),
        "model": str(response_payload.get("model") or fallback_model),
        "finish_reason": str(first_choice.get("finish_reason", "")).strip(),
    }


def _patched_complete_via_openai_chat_mode(
    self: CortensorProvider,
    *,
    request: LLMRequest,
    config: dict[str, Any],
    model: str,
    headers: dict[str, str],
    tool_call_strategy: str,
    base_url: str,
) -> dict[str, Any]:
    payload = self._build_openai_chat_payload(
        request=request,
        config=config,
        model=model,
        tool_call_strategy=tool_call_strategy,
    )
    timeout_seconds = self._resolve_transport_timeout_seconds(
        api_mode="openai_chat",
        base_timeout_seconds=_as_int(config.get("timeout_seconds"), 420),
        completion_timeout_seconds=_as_int(
            payload.get("timeout"), _as_int(config.get("timeout_seconds"), 420)
        ),
        timeout_buffer_seconds=_as_int(
            config.get("transport_timeout_buffer_seconds"), 30
        ),
    )
    return self._post_with_retries(
        url=self._resolve_openai_chat_url(base_url),
        payload=payload,
        headers=headers,
        timeout_seconds=timeout_seconds,
        result_wait_attempts=self._resolve_positive_int(
            request.metadata.get("result_wait_attempts"),
            default_value=_as_int(config.get("result_wait_attempts"), 3),
        ),
        result_wait_interval_seconds=self._resolve_non_negative_float(
            request.metadata.get("result_wait_interval_seconds"),
            default_value=_as_float(config.get("result_wait_interval_seconds"), 2.0),
        ),
        trace_metadata=request.metadata,
        env=config.get("__env__"),
        http_client=http_client_for_config(self._http_client, config),
        telemetryctl=config.get("telemetryctl"),
    )


def _patched_resolve_max_tokens(
    self: CortensorProvider, *, request: LLMRequest, config: dict[str, Any]
) -> int:
    request_max_tokens = self._resolve_positive_int(
        request.max_output_tokens, default_value=0
    )
    metadata_max_tokens = self._resolve_positive_int(
        request.metadata.get("max_tokens"), default_value=0
    )
    explicit_max_tokens = max(request_max_tokens, metadata_max_tokens)
    if explicit_max_tokens > 0:
        return explicit_max_tokens
    return _ORIGINAL_RESOLVE_MAX_TOKENS(self, request=request, config=config)


def _patched_normalize_cortensor_base_url(
    self: CortensorProvider, base_url: str
) -> str:
    normalized = str(base_url or "").strip()
    if not normalized:
        return self._DEFAULT_BASE_URL
    parsed = urlparse(normalized)
    lowered_path = (parsed.path or "").lower().rstrip("/")
    if lowered_path.endswith("/chat/completions"):
        return normalized
    return _ORIGINAL_NORMALIZE_BASE_URL(self, base_url)


def _patched_healthcheck(
    self: CortensorProvider, config: dict[str, Any]
) -> dict[str, Any]:
    base_url = str(config.get("base_url") or self._DEFAULT_BASE_URL).strip()
    api_mode = self._resolve_api_mode(
        configured_mode=str(config.get("api_mode", "auto")),
        base_url=base_url,
    )
    dummy_req = LLMRequest(messages=[])
    candidates = self._resolve_session_candidates(request=dummy_req, config=config)
    if api_mode == "cortensor_completion" and not candidates:
        return {
            "ok": False,
            "provider": self.name,
            "api_mode": api_mode,
            "reason": "cortensor_completion mode requires at least one positive session_id",
        }
    return {
        "ok": True,
        "provider": self.name,
        "api_mode": api_mode,
        "session_candidates": candidates,
        "base_url": base_url,
    }


def apply_cortensor_adapter_fixes() -> None:
    global _PATCHED
    CortensorProvider._parse_response_payload = _patched_parse_response_payload  # type: ignore[method-assign]
    CortensorProvider._complete_via_openai_chat_mode = _patched_complete_via_openai_chat_mode  # type: ignore[method-assign]
    CortensorProvider._resolve_max_tokens = _patched_resolve_max_tokens  # type: ignore[method-assign]
    CortensorProvider._normalize_cortensor_base_url = _patched_normalize_cortensor_base_url  # type: ignore[method-assign]
    CortensorProvider.healthcheck = _patched_healthcheck  # type: ignore[method-assign]
    _PATCHED = True


def restore_unpatched_cortensor_adapter() -> None:
    global _PATCHED
    CortensorProvider._parse_response_payload = _ORIGINAL_PARSE_RESPONSE_PAYLOAD  # type: ignore[method-assign]
    CortensorProvider._complete_via_openai_chat_mode = _ORIGINAL_COMPLETE_VIA_OPENAI_CHAT_MODE  # type: ignore[method-assign]
    CortensorProvider._resolve_max_tokens = _ORIGINAL_RESOLVE_MAX_TOKENS  # type: ignore[method-assign]
    CortensorProvider._normalize_cortensor_base_url = _ORIGINAL_NORMALIZE_BASE_URL  # type: ignore[method-assign]
    CortensorProvider.healthcheck = _ORIGINAL_HEALTHCHECK  # type: ignore[method-assign]
    _PATCHED = False


def build_sentinel_config(
    work_dir: Path,
    *,
    provider: str = "cortensor",
    base_url: str = "http://127.0.0.1:8080/api/v2/completions",
    api_mode: str = "cortensor_completion",
    model: str = "gpt-oss-20b",
    api_key_env: str = "CORTENSOR_API_KEY",
    session_ids: list[int] | None = None,
) -> Path:
    work_dir.mkdir(parents=True, exist_ok=True)
    config = OpenMinionConfig()

    sentinel_profile = AgentProfileConfig(
        name="sentinel",
        provider=provider,
        default_channel="console",
    )
    diagnoser_profile = AgentProfileConfig(
        name="rpc_diagnoser",
        provider=provider,
        default_channel="console",
    )
    config.agents = {
        "sentinel": sentinel_profile,
        "rpc_diagnoser": diagnoser_profile,
    }
    config.default_agent = "sentinel"

    config.runtime.process_mode = "single-process"
    config.runtime.daemon_auto_start = False
    config.runtime.log_level = "ERROR"
    config.storage.path = str(work_dir / "sentinel_state.db")
    config.action_policy.mode = "bypass"
    config.action_policy.default_action = "allow"

    if provider == "cortensor":
        config.providers.cortensor.base_url = base_url
        config.providers.cortensor.api_mode = api_mode
        config.providers.cortensor.model = model
        config.providers.cortensor.api_key_env = api_key_env
        config.providers.cortensor.session_id = (session_ids or [101])[0]
        config.providers.cortensor.session_ids = list(session_ids or [101, 102])
        config.providers.cortensor.dedicated_session_ids = list(session_ids or [101, 102])
        config.providers.cortensor.ephemeral_session_ids = [204]
        config.providers.cortensor.result_wait_attempts = 4
        config.providers.cortensor.result_wait_interval_seconds = 0.05
        config.providers.cortensor.empty_result_backoff_ms = 20
        config.providers.cortensor.empty_result_max_backoff_ms = 100
    elif provider == "openai":
        config.providers.openai.base_url = base_url
        config.providers.openai.model = model
        config.providers.openai.api_key_env = api_key_env

    config_path = work_dir / "agents.json"
    save_config(config, str(config_path))
    return config_path
