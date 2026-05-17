"""Tests for POST /verify."""

from __future__ import annotations


def test_verify_unknown_mcpname_denies(api_client):
    resp = api_client.post(
        "/verify",
        json={
            "mcpName": "victim-mcp-server",
            "version": "1.0.4",
            "transport": "http",
            "request_id": "req-test-1",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert any(v["code"] == "BIND_DENIED" for v in body["violations"])
    assert body["registry_id"] is None
    assert "D-020" in body["reason"]


def test_verify_verified_entry_allows(api_client):
    # Verified seed entry — io.github.modelcontextprotocol/server-filesystem @ 0.6.3
    resp = api_client.post(
        "/verify",
        json={
            "mcpName": "io.github.modelcontextprotocol/server-filesystem",
            "version": "0.6.3",
            "transport": "http",
            "request_id": "req-allow-1",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["decision"] == "allow", body
    assert body["registry_id"].startswith("reg-")
    assert "manifest_pinning" in body["matched_capabilities"]


def test_verify_poisoned_entry_denies_with_mcp_rce_code(api_client):
    resp = api_client.post(
        "/verify",
        json={
            "mcpName": "com.attacker-example/evil-server",
            "version": "0.5.0",
            "transport": "stdio",
            "request_id": "req-poison-1",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    codes = [v["code"] for v in body["violations"]]
    assert "MCP-RCE-26.04" in codes
    assert "OX Security disclosure April 2026" in "".join(
        v["detail"] for v in body["violations"]
    )


def test_verify_quarantined_returns_review(api_client):
    resp = api_client.post(
        "/verify",
        json={
            "mcpName": "com.example/keyrotation-mcp",
            "version": "0.4.1",
            "transport": "http",
            "request_id": "req-quar-1",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "review"
    assert "Publisher key rotated" in body["reason"]


def test_verify_stdio_with_mismatched_hash_denies(api_client):
    resp = api_client.post(
        "/verify",
        json={
            "mcpName": "io.github.modelcontextprotocol/server-filesystem",
            "version": "0.6.3",
            "transport": "stdio",
            "claimed_entrypoint_hash": "sha256:" + "f" * 64,
            "request_id": "req-hashbad-1",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert any(v["code"] == "MCP-RCE-26.04" for v in body["violations"])


def test_verify_tool_drift_denies(api_client):
    resp = api_client.post(
        "/verify",
        json={
            "mcpName": "io.github.modelcontextprotocol/server-filesystem",
            "version": "0.6.3",
            "transport": "http",
            "claimed_tools": ["read_file", "write_file", "exec_shell"],
            "request_id": "req-drift-1",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert any(v["code"] == "MANIFEST_PIN_VIOLATION" for v in body["violations"])


def test_verify_records_audit_id_each_call(api_client):
    body1 = api_client.post(
        "/verify",
        json={"mcpName": "victim-mcp-server", "version": "1.0.4", "transport": "http"},
    ).json()
    body2 = api_client.post(
        "/verify",
        json={"mcpName": "victim-mcp-server", "version": "1.0.4", "transport": "http"},
    ).json()
    assert body1["audit_id"] != body2["audit_id"]
    assert body1["audit_id"].startswith("audit-")


def test_healthz_reports_seed_counts(api_client):
    resp = api_client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["registry_entries"]["verified"] == 47
    assert body["registry_entries"]["quarantined"] == 2
    assert body["registry_entries"]["poisoned"] == 1
    assert body["total_entries"] == 50
