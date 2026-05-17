"""Integration test against the victim app's MCP endpoint contract.

The real victim app at `victim/app/api/mcp/route.ts` returns `signed: false`
+ `warning: "intentionally unsigned"` per D-020. Spinning up the Next.js dev
server inside a pytest run is brittle (and Atlas is the gating contract, not
the victim), so we ship a small in-process stub that returns the exact same
JSON shape. The test then drives Atlas's /verify with the same wire payload
the Lobster Trap sidecar would emit when an agent fleet tries to bind to
``victim-mcp-server@1.0.4``.

Why this is honest: D-020 declares "the registry treats `signed: false` (or
absent signature) as immediate BIND_DENIED." Atlas's verify path has no
notion of the victim's HTTP body — it only knows whether a mcpName+version
appears in the signed registry. The victim is registered nowhere, therefore
the deny is structural; the stub exists only to prove the wire-shape
contract.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest


VICTIM_PAYLOAD = {
    "name": "victim-mcp-server",
    "version": "1.0.4",
    "signed": False,
    "protocol": "mcp/1.0",
    "publisher": None,
    "tools": [
        {
            "name": "read_company_doc",
            "description": "Read an internal company document by name.",
        },
        {
            "name": "send_message",
            "description": "Send an outbound message on behalf of the agent.",
        },
    ],
    "warning": (
        "This server is unsigned. Reef MCP registry will refuse handshakes "
        "until a trusted signature is attached."
    ),
}


class _VictimStubHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        import json

        body = json.dumps(VICTIM_PAYLOAD).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args, **_kwargs):  # silence stdout
        pass


@pytest.fixture()
def victim_stub() -> str:
    """Start an in-process HTTP server that mimics victim/app/api/mcp."""
    server = HTTPServer(("127.0.0.1", 0), _VictimStubHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_victim_stub_advertises_signed_false(victim_stub):
    r = httpx.get(victim_stub + "/")
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "victim-mcp-server"
    assert body["signed"] is False
    assert "unsigned" in body["warning"]


def test_atlas_denies_victim_bind_attempt(api_client, victim_stub):
    """The canonical D-020 sad path: victim attempts bind → Atlas denies."""
    # Real fleet would discover the victim's MCP root, then ask Atlas to verify
    # the {mcpName, version, transport} triple.
    metadata = httpx.get(victim_stub + "/").json()
    resp = api_client.post(
        "/verify",
        json={
            "mcpName": metadata["name"],
            "version": metadata["version"],
            "transport": "http",
            "agent_id": "spiffe://reef.local/integration-test-agent",
            "request_id": "req-integ-victim",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["decision"] == "deny"
    assert any(v["code"] == "BIND_DENIED" for v in body["violations"])


def test_atlas_allows_verified_seed_entry(api_client):
    resp = api_client.post(
        "/verify",
        json={
            "mcpName": "io.github.modelcontextprotocol/server-filesystem",
            "version": "0.6.3",
            "transport": "http",
            "agent_id": "spiffe://reef.local/integration-test-agent",
            "request_id": "req-integ-verified",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"


def test_atlas_denies_poisoned_entry_with_mcp_rce_code(api_client):
    resp = api_client.post(
        "/verify",
        json={
            "mcpName": "com.attacker-example/evil-server",
            "version": "0.5.0",
            "transport": "stdio",
            "agent_id": "spiffe://reef.local/integration-test-agent",
            "request_id": "req-integ-poisoned",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    codes = [v["code"] for v in body["violations"]]
    assert "MCP-RCE-26.04" in codes
    assert "OX Security disclosure April 2026" in " ".join(
        v["detail"] for v in body["violations"]
    )
