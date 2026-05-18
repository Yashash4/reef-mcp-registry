"""Unit tests for the data-source helpers."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import httpx
import pytest

from app.data_sources import (
    AtlasUnreachable,
    AuditRootError,
    DastAUnreachable,
    PolicyBusUnreachable,
)
from app.data_sources.ai_bom import (
    ServiceURLs,
    assemble_ai_bom,
    query_atlas_registry,
    query_dast_a_packs,
    query_policy_bus,
    resolve_service_urls_from_env,
)
from app.data_sources.attack_telemetry import (
    TELEMETRY_BUCKETS,
    TelemetryDay,
    aggregate_heatmap,
    telemetry_to_audit_window,
)
from app.data_sources.audit_root import SignedMerkleRoot, fetch_signed_merkle_root
from app.data_sources.coverage_matrix import (
    OWASP_ASI_IDS,
    build_mitre_coverage,
    build_owasp_coverage,
    extract_policy_rule_names_from_bundles,
)


# ---------------------------------------------------------------------------
# AI-BOM helpers
# ---------------------------------------------------------------------------


def _atlas_payload() -> dict:
    return {
        "healthz": {
            "registry_entries": {"verified": 47, "quarantined": 2, "poisoned": 1},
            "total_entries": 50,
            "publishers": 4,
        },
        "entries": [
            {
                "registry_id": "reg-1",
                "manifest": {
                    "mcpName": "io.example/safe",
                    "version": "1.0.0",
                    "transports": ["stdio"],
                    "sdk_version": "@mcp/sdk@1.29.0",
                },
                "publisher_id": "pub-a",
                "status": "verified",
                "registered_at": "2026-05-01T00:00:00+00:00",
            },
            {
                "registry_id": "reg-2",
                "manifest": {
                    "mcpName": "com.attacker/evil",
                    "version": "0.5.0",
                    "transports": ["stdio"],
                    "sdk_version": "@mcp/sdk@0.5.0",
                },
                "publisher_id": "pub-unknown",
                "status": "poisoned",
                "registered_at": "2026-04-16T00:00:00+00:00",
                "poisoned_reason": "MCP-RCE-26.04 vulnerable SDK",
            },
        ],
        "publishers": [
            {
                "publisher_id": "pub-a",
                "fingerprint": "fp-a",
                "scopes": ["io.example.*"],
            }
        ],
    }


def _policy_bus_payload() -> dict:
    return {
        "healthz": {"status": "ok", "active_subscribers": 3, "active_bundles": 1, "fleet_node_count": 49},
        "fleet": {
            "fleet_id": "prod-fleet",
            "nodes": [
                {"identity": {"fleet_id": "prod-fleet", "node_id": "n1"}, "online": True, "last_ack_status": "applied"},
                {"identity": {"fleet_id": "prod-fleet", "node_id": "n2"}, "online": False, "last_ack_status": "unknown"},
            ],
        },
        "bundles": [
            {
                "bundle_id": "b1",
                "version": "v1",
                "signer_key_id": "pub-prod",
                "published_at_unix": 1_715_731_200,
                "scope": {"fleet_id": "prod-fleet"},
                "bundle_yaml": (
                    "ingress_rules:\n"
                    "- name: block_prompt_injection\n"
                    "- name: review_high_asi_ewma\n"
                    "- name: mcp_bind_denied_by_registry\n"
                    "- name: markdown_exfil_modify\n"
                ),
            }
        ],
    }


def _dast_a_payload() -> dict:
    return {
        "total": 2,
        "page": 1,
        "page_size": 100,
        "packs": [
            {
                "pack_id": "MCP-RCE-26.04",
                "name": "MCP STDIO Command Execution",
                "discovered_by": "DAST-A | OX Security (April 2026 disclosure)",
                "owasp_asi": ["ASI09", "ASI10"],
                "mitre_atlas": ["AML.T0010", "AML.T0050"],
                "blocked_by_reef": True,
                "ox_security_citation": "OX Security disclosed April 16 2026.",
            },
            {
                "pack_id": "EchoLeak-26.05",
                "name": "EchoLeak",
                "discovered_by": "DAST-A | Aim Labs",
                "owasp_asi": ["ASI09"],
                "mitre_atlas": ["AML.T0051"],
                "blocked_by_reef": True,
            },
        ],
    }


def test_assemble_ai_bom_normalises_payloads() -> None:
    out = assemble_ai_bom(
        fleet_id="prod-fleet",
        atlas_payload=_atlas_payload(),
        policy_bus_payload=_policy_bus_payload(),
        dast_a_payload=_dast_a_payload(),
    )
    assert out["fleet_id"] == "prod-fleet"
    assert out["registry_entry_counts"]["verified"] == 47
    assert out["registry_entry_counts"]["quarantined"] == 2
    assert out["registry_entry_counts"]["poisoned"] == 1
    assert len(out["mcp_servers"]) == 2
    safe = out["mcp_servers"][0]
    assert safe["mcp_name"] == "io.example/safe"
    assert safe["status"] == "verified"
    assert safe["signature_status"] == "verified"
    poisoned = out["mcp_servers"][1]
    assert poisoned["status"] == "poisoned"
    assert poisoned["poisoned_reason"] == "MCP-RCE-26.04 vulnerable SDK"
    assert out["active_bundle"]["bundle_id"] == "b1"
    assert out["fleet_node_count"] == 2
    assert out["fleet_node_summary"]["online"] == 1
    assert out["fleet_node_summary"]["offline"] == 1
    assert out["dast_a_pack_total"] == 2


def test_resolve_service_urls_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REEF_ATLAS_URL", "http://atlas:8080")
    monkeypatch.setenv("REEF_POLICY_BUS_ADMIN_URL", "http://bus:50052")
    monkeypatch.setenv("REEF_DAST_A_URL", "http://dast:8088")
    urls = resolve_service_urls_from_env()
    assert urls.atlas_url == "http://atlas:8080"
    assert urls.policy_bus_url == "http://bus:50052"
    assert urls.dast_a_url == "http://dast:8088"


def _stub_http_response(json_payload: dict, *, status_code: int = 200) -> httpx.Response:
    request = httpx.Request("GET", "http://stub.example/path")
    return httpx.Response(status_code, json=json_payload, request=request)


def test_query_atlas_registry_aggregates_two_endpoints() -> None:
    urls = ServiceURLs(atlas_url="http://atlas:8080")
    payloads = {
        "/healthz": {"registry_entries": {"verified": 1}, "total_entries": 1, "publishers": 1},
        "/registry/entries": {"entries": [], "publishers": []},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return _stub_http_response(payloads[request.url.path])

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, timeout=1.0) as c:
        out = query_atlas_registry(urls, client=c)
    assert out["healthz"]["registry_entries"] == {"verified": 1}
    assert out["entries"] == []
    assert out["publishers"] == []


def test_query_atlas_registry_raises_on_transport_error() -> None:
    urls = ServiceURLs(atlas_url="http://atlas:8080", timeout_s=0.1)

    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, timeout=0.1) as c:
        with pytest.raises(AtlasUnreachable):
            query_atlas_registry(urls, client=c)


def test_query_policy_bus_three_endpoints_then_raises() -> None:
    urls = ServiceURLs(policy_bus_url="http://bus:50052")

    def handler(request: httpx.Request) -> httpx.Response:
        # Healthz works, fleet 500s
        if request.url.path == "/healthz":
            return _stub_http_response({"status": "ok"})
        if request.url.path == "/fleet":
            return _stub_http_response({}, status_code=500)
        return _stub_http_response({})

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, timeout=1.0) as c:
        with pytest.raises(PolicyBusUnreachable):
            query_policy_bus(urls, client=c)


def test_query_dast_a_packs_returns_payload() -> None:
    urls = ServiceURLs(dast_a_url="http://dast:8088")

    def handler(_request: httpx.Request) -> httpx.Response:
        return _stub_http_response({"total": 0, "page": 1, "page_size": 100, "packs": []})

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, timeout=1.0) as c:
        out = query_dast_a_packs(urls, client=c)
    assert out["total"] == 0
    assert out["packs"] == []


def test_query_dast_a_packs_raises_on_500() -> None:
    urls = ServiceURLs(dast_a_url="http://dast:8088")
    transport = httpx.MockTransport(lambda _r: _stub_http_response({}, status_code=503))
    with httpx.Client(transport=transport, timeout=1.0) as c:
        with pytest.raises(DastAUnreachable):
            query_dast_a_packs(urls, client=c)


# ---------------------------------------------------------------------------
# Coverage matrix
# ---------------------------------------------------------------------------


def test_owasp_coverage_full_when_pack_blocked_and_rule_present() -> None:
    packs = _dast_a_payload()["packs"]
    # ASI09 = covered by EchoLeak pack (blocked_by_reef=True). Rule
    # markdown_exfil_modify is in the bundle.
    rules = ["markdown_exfil_modify"]
    out = build_owasp_coverage(packs=packs, rule_names=rules)
    assert out["ASI09"]["state"] == "full"


def test_owasp_coverage_partial_when_only_one_signal() -> None:
    # ASI10 has a pack but no rule — partial.
    packs = _dast_a_payload()["packs"]
    out = build_owasp_coverage(packs=packs, rule_names=[])
    assert out["ASI09"]["state"] == "partial"
    assert out["ASI10"]["state"] == "partial"


def test_owasp_coverage_none_when_no_signal() -> None:
    out = build_owasp_coverage(packs=[], rule_names=[])
    for asi_id in OWASP_ASI_IDS:
        assert out[asi_id]["state"] == "none"


def test_mitre_coverage_full_when_blocked_pack_and_rule() -> None:
    packs = _dast_a_payload()["packs"]
    # AML.T0050 is tagged by MCP-RCE-26.04 (blocked). Rule "command_injection" maps.
    rules = ["command_injection_block"]
    out = build_mitre_coverage(packs=packs, rule_names=rules)
    assert out["AML.T0050"]["state"] == "full"


def test_extract_policy_rule_names_from_bundles_parses_yaml_lines() -> None:
    rules = extract_policy_rule_names_from_bundles(_policy_bus_payload()["bundles"])
    assert "block_prompt_injection" in rules
    assert "markdown_exfil_modify" in rules
    assert "mcp_bind_denied_by_registry" in rules


# ---------------------------------------------------------------------------
# Attack telemetry / heatmap
# ---------------------------------------------------------------------------


def test_aggregate_heatmap_returns_30_days_with_demo_seed_when_logs_empty(tmp_path: Path) -> None:
    empty = tmp_path / "audit.jsonl"
    empty.touch()
    days = aggregate_heatmap(
        policy_bus_audit=empty,
        dast_a_audit=empty,
        window_days=30,
        include_demo_seed=True,
    )
    assert len(days) == 30
    # All days are flagged demo seed when there's no real data.
    assert all(d.is_demo_seed for d in days)
    # At least one bucket per day has a count thanks to the synthetic data.
    assert any(sum(d.by_bucket.values()) > 0 for d in days)


def test_aggregate_heatmap_marks_real_days_when_log_has_events(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    today = dt.datetime.now(tz=dt.timezone.utc).date()
    rows = [
        {"ts": dt.datetime.combine(today, dt.time(12, 0), tzinfo=dt.timezone.utc).isoformat(),
         "rule_id": "block_prompt_injection", "decision": "deny", "kind": "ingress"},
        {"ts": dt.datetime.combine(today, dt.time(13, 0), tzinfo=dt.timezone.utc).isoformat(),
         "rule_id": "markdown_exfil_modify", "decision": "modify", "kind": "egress"},
    ]
    audit.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    days = aggregate_heatmap(
        policy_bus_audit=audit,
        dast_a_audit=tmp_path / "missing.jsonl",  # missing file
        window_days=7,
        include_demo_seed=True,
        end_date=today,
    )
    today_entry = next(d for d in days if d.date_iso == today.isoformat())
    assert not today_entry.is_demo_seed
    assert today_entry.by_bucket["Prompt injection"] >= 1
    assert today_entry.by_bucket["Markdown exfil"] >= 1


def test_telemetry_to_audit_window_packs_totals() -> None:
    days = [
        TelemetryDay(date_iso="2026-05-01", by_bucket={b: 1 for b in TELEMETRY_BUCKETS}, is_demo_seed=False),
        TelemetryDay(date_iso="2026-05-02", by_bucket={b: 2 for b in TELEMETRY_BUCKETS}, is_demo_seed=True),
    ]
    out = telemetry_to_audit_window(
        days,
        merkle_root_hex="abcd" * 16,
        merkle_count=10,
        fleet_id="prod-fleet",
    )
    assert out["days"] == 2
    assert out["fleet_id"] == "prod-fleet"
    assert out["merkle_root_sha256"] == "abcd" * 16
    assert out["merkle_event_count"] == 10
    assert out["total_events"] == sum(out["totals_by_bucket"].values())
    assert out["demo_seed_day_count"] == 1
    assert out["has_real_data"] is True


# ---------------------------------------------------------------------------
# Audit-root subprocess
# ---------------------------------------------------------------------------


def test_audit_root_error_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the lobstertrap binary cannot be found, surface :class:`AuditRootError`."""
    monkeypatch.setenv("REEF_LOBSTERTRAP_BIN", "/definitely/not/a/real/binary")
    with pytest.raises(AuditRootError):
        fetch_signed_merkle_root()


def test_audit_root_parses_subprocess_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """When a fake binary emits valid JSON, the parser returns the dataclass."""
    import subprocess
    import sys

    monkeypatch.setenv("REEF_AUDIT_DIR", "/tmp/audit-stub")

    class _StubResult:
        returncode = 0
        stdout = json.dumps(
            {
                "root": "ab" * 32,
                "signature": "c2lnLWI2NA==",
                "count": 7,
                "timestamp": "2026-05-18T01:23:45Z",
                "dir": "/tmp/audit-stub",
                "signed": True,
                "hash_algo": "sha256",
                "signature_algo": "ed25519-over-raw-root-bytes",
            }
        )
        stderr = ""

    def fake_run(*args, **kwargs):
        return _StubResult()

    # Pretend the binary exists.
    monkeypatch.setenv("REEF_LOBSTERTRAP_BIN", sys.executable)
    monkeypatch.setattr(subprocess, "run", fake_run)

    root = fetch_signed_merkle_root()
    assert isinstance(root, SignedMerkleRoot)
    assert root.root_hex == "ab" * 32
    assert root.count == 7
    assert root.signed is True
    assert root.short_root().endswith("…")
