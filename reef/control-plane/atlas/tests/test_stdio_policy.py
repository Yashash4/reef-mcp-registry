"""STDIO transport + SDK-version policy tests."""

from __future__ import annotations

import pytest

from app.models import Manifest, Tool
from app.policy import (
    enforce_capability_allowlist,
    enforce_tool_allowlist,
    is_vulnerable_sdk,
    requires_extra_scrutiny,
    stdio_pre_handshake_decision,
    vulnerable_sdk_violation,
)


@pytest.mark.parametrize(
    "sdk_version,expected",
    [
        ("@modelcontextprotocol/sdk@0.5.0", True),
        ("@modelcontextprotocol/sdk@1.9.999", True),
        ("@modelcontextprotocol/sdk@1.10.0", False),
        ("@modelcontextprotocol/sdk@1.29.0", False),
        ("mcp==0.9.0", True),
        ("mcp==1.11.0", False),
        ("modelcontextprotocol/sdk@0.1.2", True),
        ("io.modelcontextprotocol:mcp-sdk:0.7.0", True),
        ("unknown-sdk@1.0.0", False),
        ("", True),
        (None, True),
        ("garbage", True),
    ],
)
def test_is_vulnerable_sdk(sdk_version, expected):
    assert is_vulnerable_sdk(sdk_version) is expected


def test_vulnerable_sdk_violation_uses_code():
    viol = vulnerable_sdk_violation("@modelcontextprotocol/sdk@0.5.0")
    assert viol["code"] == "MCP-RCE-26.04"
    assert "OX Security disclosure April 2026" in viol["detail"]
    assert "@modelcontextprotocol/sdk@0.5.0" in viol["detail"]


def test_requires_extra_scrutiny_only_for_stdio():
    assert requires_extra_scrutiny("stdio") is True
    assert requires_extra_scrutiny("STDIO") is True
    assert requires_extra_scrutiny("http") is False
    assert requires_extra_scrutiny("") is False


def _manifest(transports=("stdio",), entrypoint_hash="sha256:" + "a" * 64) -> Manifest:
    return Manifest(
        mcpName="com.example/weather-mcp",
        version="1.0.0",
        transports=list(transports),
        tools=[Tool(name="ping")],
        capabilities=["tools"],
        sdk_version="@modelcontextprotocol/sdk@1.29.0",
        stdio_entrypoint_hash=entrypoint_hash,
    )


def test_stdio_decision_allows_when_hash_matches():
    m = _manifest()
    deny, reason = stdio_pre_handshake_decision(
        transport="stdio",
        manifest=m,
        claimed_entrypoint_hash=m.stdio_entrypoint_hash,
    )
    assert deny is False
    assert reason is None


def test_stdio_decision_denies_on_missing_hash():
    m = _manifest(entrypoint_hash=None)
    deny, reason = stdio_pre_handshake_decision(
        transport="stdio",
        manifest=m,
        claimed_entrypoint_hash=None,
    )
    assert deny is True
    assert reason is not None
    assert "STDIO transport pre-handshake denial" in reason


def test_stdio_decision_denies_on_hash_mismatch():
    m = _manifest()
    deny, reason = stdio_pre_handshake_decision(
        transport="stdio",
        manifest=m,
        claimed_entrypoint_hash="sha256:" + "f" * 64,
    )
    assert deny is True
    assert reason is not None
    assert "does not match" in reason


def test_stdio_decision_skips_for_http_transport():
    m = _manifest()
    deny, _ = stdio_pre_handshake_decision(
        transport="http",
        manifest=m,
        claimed_entrypoint_hash=None,
    )
    assert deny is False


def test_capability_allowlist_blocks_inflation():
    m = _manifest()
    extras = enforce_capability_allowlist(m, ["tools", "elicitation"])
    assert extras == ["elicitation"]


def test_capability_allowlist_empty_claim_is_ok():
    m = _manifest()
    assert enforce_capability_allowlist(m, []) == []


def test_tool_allowlist_blocks_extras():
    m = _manifest()
    m = m.model_copy(update={"tools": [Tool(name="get_weather")]})
    assert enforce_tool_allowlist(m, ["get_weather"]) == []
    assert enforce_tool_allowlist(m, ["get_weather", "send_message"]) == ["send_message"]
