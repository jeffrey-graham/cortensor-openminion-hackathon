"""Automated reproduction tests for real OpenMinion 0.1.18 SDK bugs & verification of fixes."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from openminion import OpenMinionConfig
from openminion.modules.llm.providers.behavior import resolve_behavior_profile
from openminion.modules.llm.providers.cortensor.adapter import CortensorProvider
from openminion.modules.llm.schemas import LLMRequest, Message, ToolSpec

from cortensor_sentinel.cortensor_compat import (
    apply_cortensor_adapter_fixes,
    restore_unpatched_cortensor_adapter,
)


def test_bug1_cortensor_parse_response_payload_hardcodes_fallback_enabled_false() -> None:
    restore_unpatched_cortensor_adapter()
    provider = CortensorProvider()
    req = LLMRequest(
        messages=[Message(role="user", content="Audit 0x123")],
        tools=[
            ToolSpec(
                name="audit_smart_contract_bytecode",
                description="Audit bytecode",
                input_schema={"type": "object", "properties": {"contract_address": {"type": "string"}}},
            )
        ],
    )
    behavior = resolve_behavior_profile(
        provider="cortensor",
        model="gpt-oss-20b",
        base_url="http://127.0.0.1:8080/api/v2/completions",
        metadata={},
    )
    fallback_payload = {
        "id": "cmpl-1",
        "model": "gpt-oss-20b",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "text": '{"tool_calls": [{"name": "audit_smart_contract_bytecode", "arguments": {"contract_address": "0x123"}}]}',
            }
        ],
    }

    captured_kwargs: list[dict[str, Any]] = []
    orig_resolve = __import__(
        "openminion.modules.llm.providers.cortensor.adapter",
        fromlist=["resolve_tool_call_source_precedence"],
    ).resolve_tool_call_source_precedence

    def _spy_resolve(**kwargs: Any) -> Any:
        captured_kwargs.append(kwargs)
        return orig_resolve(**kwargs)

    with patch(
        "openminion.modules.llm.providers.cortensor.adapter.resolve_tool_call_source_precedence",
        side_effect=_spy_resolve,
    ):
        provider._parse_response_payload(
            response_payload=fallback_payload,
            request=req,
            tool_call_strategy="hybrid",
            fallback_model="gpt-oss-20b",
            behavior_profile=behavior,
        )
    assert captured_kwargs[-1]["fallback_enabled"] is False

    apply_cortensor_adapter_fixes()
    with patch(
        "cortensor_sentinel.cortensor_compat.resolve_tool_call_source_precedence",
        side_effect=_spy_resolve,
    ):
        parsed = provider._parse_response_payload(
            response_payload=fallback_payload,
            request=req,
            tool_call_strategy="hybrid",
            fallback_model="gpt-oss-20b",
            behavior_profile=behavior,
        )
    assert captured_kwargs[-1]["fallback_enabled"] is True
    assert len(parsed["tool_calls"]) == 1
    assert parsed["tool_calls"][0].name == "audit_smart_contract_bytecode"


def test_bug2_openai_chat_mode_omits_http_client_for_config() -> None:
    restore_unpatched_cortensor_adapter()
    provider = CortensorProvider()
    req = LLMRequest(messages=[Message(role="user", content="hello")])

    seen_http_clients: list[Any] = []

    def _fake_post_with_retries(self_obj: Any, **kwargs: Any) -> dict[str, Any]:
        seen_http_clients.append(kwargs.get("http_client"))
        return {"choices": [{"message": {"content": "ok"}}]}

    with patch.object(CortensorProvider, "_post_with_retries", _fake_post_with_retries):
        provider._complete_via_openai_chat_mode(
            request=req,
            config={"http_connection_reuse_enabled": True},
            model="gpt-oss-20b",
            headers={},
            tool_call_strategy="hybrid",
            base_url="https://api.cortensor.app/v1",
        )
    assert seen_http_clients[-1] is None

    apply_cortensor_adapter_fixes()
    with patch.object(CortensorProvider, "_post_with_retries", _fake_post_with_retries):
        provider._complete_via_openai_chat_mode(
            request=req,
            config={"http_connection_reuse_enabled": True},
            model="gpt-oss-20b",
            headers={},
            tool_call_strategy="hybrid",
            base_url="https://api.cortensor.app/v1",
        )
    assert seen_http_clients[-1] is provider._http_client


def test_bug3_resolve_max_tokens_enforces_4096_floor_over_explicit_request() -> None:
    restore_unpatched_cortensor_adapter()
    provider = CortensorProvider()
    req = LLMRequest(
        messages=[Message(role="user", content="short")],
        max_output_tokens=256,
    )
    assert provider._resolve_max_tokens(request=req, config={"max_tokens": 256}) == 4096

    apply_cortensor_adapter_fixes()
    assert provider._resolve_max_tokens(request=req, config={"max_tokens": 256}) == 256


def test_bug4_normalize_base_url_corrupts_v1_chat_completions_endpoint() -> None:
    restore_unpatched_cortensor_adapter()
    provider = CortensorProvider()
    v1_chat_url = "http://127.0.0.1:8080/api/v1/chat/completions"

    assert (
        provider._normalize_cortensor_base_url(v1_chat_url)
        == "http://127.0.0.1:8080/api/v2/chat/completions"
    )

    apply_cortensor_adapter_fixes()
    assert provider._normalize_cortensor_base_url(v1_chat_url) == v1_chat_url
    assert (
        provider._normalize_cortensor_base_url("http://127.0.0.1:8080/api/v1/completions")
        == "http://127.0.0.1:8080/api/v2/completions"
    )


def test_bug6_cortensor_healthcheck_ignores_missing_session_id_in_completion_mode() -> None:
    restore_unpatched_cortensor_adapter()
    provider = CortensorProvider()
    broken_cfg = {
        "base_url": "http://127.0.0.1:8080/api/v2/completions",
        "api_mode": "cortensor_completion",
        "session_id": 0,
        "session_ids": [],
    }
    assert provider.healthcheck(broken_cfg) == {"ok": True, "provider": "cortensor"}

    apply_cortensor_adapter_fixes()
    hc = provider.healthcheck(broken_cfg)
    assert hc["ok"] is False
    assert "session_id" in hc["reason"]


def test_bug7_openminion_config_default_has_empty_agents_and_daemon_auto_start() -> None:
    import openminion
    import openminion.api

    cfg = OpenMinionConfig()
    assert cfg.agents == {}
    assert cfg.runtime.daemon_auto_start is True
    assert "AgentProfileConfig" not in openminion.__all__
    assert "AgentProfileConfig" not in openminion.api.__all__
