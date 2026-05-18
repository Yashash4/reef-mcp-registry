"""AI-BOM assembly from upstream Reef services.

Queries (in order, fail-closed on any of them):

1. Atlas registry — ``GET {ATLAS_URL}/registry/entries`` for the MCP
   server inventory and publisher allowlist; ``GET {ATLAS_URL}/healthz``
   for the verified/quarantined/poisoned counts.
2. Policy bus — ``GET {BUS_URL}/fleet`` for the 49-node fleet snapshot;
   ``GET {BUS_URL}/bundles`` for the current bundle version + hash.
3. DAST-A — ``GET {DAST_A_URL}/dast-a/packs`` for the attack-pack catalog.

The output dict is consumed by:

* :class:`UnderwriterAgent` — the JSON snapshot that Gemini Pro scores.
* :mod:`app.pdf.sections` — the AI-BOM page (page 2) and attack-pack
  catalog page (page 5).
"""
from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from app.data_sources import AtlasUnreachable, DastAUnreachable, PolicyBusUnreachable

logger = logging.getLogger("quote.data_sources.ai_bom")

DEFAULT_ATLAS_URL = "http://localhost:8080"
DEFAULT_POLICY_BUS_URL = "http://localhost:50052"
DEFAULT_DAST_A_URL = "http://localhost:8088"
DEFAULT_TIMEOUT_S = 3.0


@dataclass
class ServiceURLs:
    """Resolved upstream service URLs.

    Tests pass explicit URLs into the assembler; production reads from
    env vars (``REEF_ATLAS_URL`` / ``REEF_POLICY_BUS_ADMIN_URL`` /
    ``REEF_DAST_A_URL``) so docker-compose service names work cleanly.
    """

    atlas_url: str = DEFAULT_ATLAS_URL
    policy_bus_url: str = DEFAULT_POLICY_BUS_URL
    dast_a_url: str = DEFAULT_DAST_A_URL
    timeout_s: float = DEFAULT_TIMEOUT_S
    # The policy bus admin token is required only for /audit/tail; the
    # /fleet + /bundles + /healthz endpoints are anonymous (per A-7).
    policy_bus_admin_token: Optional[str] = None


def resolve_service_urls_from_env() -> ServiceURLs:
    """Construct :class:`ServiceURLs` from environment variables."""
    return ServiceURLs(
        atlas_url=os.environ.get("REEF_ATLAS_URL")
        or os.environ.get("REEF_MCP_REGISTRY_URL")
        or DEFAULT_ATLAS_URL,
        policy_bus_url=os.environ.get("REEF_POLICY_BUS_ADMIN_URL", DEFAULT_POLICY_BUS_URL),
        dast_a_url=os.environ.get("REEF_DAST_A_URL", DEFAULT_DAST_A_URL),
        timeout_s=float(os.environ.get("REEF_RIA_HTTP_TIMEOUT_S", DEFAULT_TIMEOUT_S)),
        policy_bus_admin_token=os.environ.get("REEF_POLICY_BUS_ADMIN_TOKEN") or None,
    )


# ---------------------------------------------------------------------------
# Per-service queries
# ---------------------------------------------------------------------------


def query_atlas_registry(urls: ServiceURLs, *, client: Optional[httpx.Client] = None) -> dict[str, Any]:
    """Return ``{healthz, entries, publishers}`` from Atlas.

    Calls Atlas's ``/healthz`` for the seed-count summary
    (``verified/quarantined/poisoned``) and ``/registry/entries`` for the
    full inventory. Both endpoints are anonymous and idempotent.
    """
    own_client = client is None
    c = client or httpx.Client(timeout=urls.timeout_s)
    try:
        try:
            health = c.get(f"{urls.atlas_url}/healthz").raise_for_status().json()
        except httpx.HTTPError as exc:
            raise AtlasUnreachable(
                f"GET {urls.atlas_url}/healthz failed: {exc!r}"
            ) from exc
        try:
            entries = c.get(f"{urls.atlas_url}/registry/entries").raise_for_status().json()
        except httpx.HTTPError as exc:
            raise AtlasUnreachable(
                f"GET {urls.atlas_url}/registry/entries failed: {exc!r}"
            ) from exc
        return {
            "healthz": health,
            "entries": entries.get("entries", []),
            "publishers": entries.get("publishers", []),
        }
    finally:
        if own_client:
            c.close()


def query_policy_bus(urls: ServiceURLs, *, client: Optional[httpx.Client] = None) -> dict[str, Any]:
    """Return ``{fleet, bundles, healthz}`` from the policy bus admin REST."""
    own_client = client is None
    c = client or httpx.Client(timeout=urls.timeout_s)
    try:
        try:
            health = c.get(f"{urls.policy_bus_url}/healthz").raise_for_status().json()
        except httpx.HTTPError as exc:
            raise PolicyBusUnreachable(
                f"GET {urls.policy_bus_url}/healthz failed: {exc!r}"
            ) from exc
        try:
            fleet = c.get(f"{urls.policy_bus_url}/fleet").raise_for_status().json()
        except httpx.HTTPError as exc:
            raise PolicyBusUnreachable(
                f"GET {urls.policy_bus_url}/fleet failed: {exc!r}"
            ) from exc
        try:
            bundles = c.get(f"{urls.policy_bus_url}/bundles").raise_for_status().json()
        except httpx.HTTPError as exc:
            raise PolicyBusUnreachable(
                f"GET {urls.policy_bus_url}/bundles failed: {exc!r}"
            ) from exc
        return {
            "healthz": health,
            "fleet": fleet,
            "bundles": bundles,
        }
    finally:
        if own_client:
            c.close()


def query_dast_a_packs(urls: ServiceURLs, *, client: Optional[httpx.Client] = None) -> dict[str, Any]:
    """Return ``{packs, total, page, page_size}`` from DAST-A."""
    own_client = client is None
    c = client or httpx.Client(timeout=urls.timeout_s)
    try:
        try:
            packs = c.get(f"{urls.dast_a_url}/dast-a/packs").raise_for_status().json()
        except httpx.HTTPError as exc:
            raise DastAUnreachable(
                f"GET {urls.dast_a_url}/dast-a/packs failed: {exc!r}"
            ) from exc
        return packs
    finally:
        if own_client:
            c.close()


# ---------------------------------------------------------------------------
# AI-BOM assembly
# ---------------------------------------------------------------------------


def assemble_ai_bom(
    *,
    fleet_id: str,
    atlas_payload: dict[str, Any],
    policy_bus_payload: dict[str, Any],
    dast_a_payload: dict[str, Any],
    agents: Optional[list[dict[str, Any]]] = None,
    models: Optional[list[dict[str, Any]]] = None,
    tools: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Fold the three payloads into the AI-BOM dict.

    The shape mirrors the PDF's page-2 table layout. Caller passes optional
    agent + model + tool lists for the rows the upstream services don't
    expose — A-10 has no live agent registry yet (Phase 2 brings SPIRE).
    """
    registry_entries = atlas_payload.get("entries", [])
    atlas_health = atlas_payload.get("healthz", {})
    publishers = atlas_payload.get("publishers", [])

    mcp_servers: list[dict[str, Any]] = []
    for raw in registry_entries:
        manifest = raw.get("manifest", {})
        publisher_id = raw.get("publisher_id", "")
        publisher_match = next(
            (p for p in publishers if p.get("publisher_id") == publisher_id),
            None,
        )
        mcp_servers.append(
            {
                "mcp_name": manifest.get("mcpName", "<unknown>"),
                "version": manifest.get("version", ""),
                "transports": list(manifest.get("transports", [])),
                "sdk_version": manifest.get("sdk_version", ""),
                "status": raw.get("status", "unknown"),
                "signature_status": (
                    "verified"
                    if raw.get("status") == "verified"
                    else raw.get("status", "unknown")
                ),
                "publisher_id": publisher_id,
                "publisher_fingerprint": (
                    publisher_match.get("fingerprint", "") if publisher_match else ""
                ),
                "registered_at": raw.get("registered_at", ""),
                "poisoned_reason": raw.get("poisoned_reason"),
                "quarantined_reason": raw.get("quarantined_reason"),
            }
        )

    fleet = policy_bus_payload.get("fleet", {})
    fleet_nodes = fleet.get("nodes", [])
    bundles = policy_bus_payload.get("bundles", [])
    # Choose the most recently published bundle for the headline.
    sorted_bundles = sorted(
        bundles,
        key=lambda b: int(b.get("published_at_unix", 0)),
        reverse=True,
    )
    active_bundle = sorted_bundles[0] if sorted_bundles else None

    return {
        "fleet_id": fleet_id,
        "registry_entry_counts": atlas_health.get("registry_entries", {}),
        "registry_total": atlas_health.get("total_entries", len(registry_entries)),
        "publishers_total": atlas_health.get("publishers", len(publishers)),
        "mcp_servers": mcp_servers,
        "agents": agents or [],
        "models": models or [],
        "tools": tools or [],
        "policy_versions": [
            {
                "bundle_id": b.get("bundle_id", ""),
                "version": b.get("version", ""),
                "signer_key_id": b.get("signer_key_id", ""),
                "published_at_unix": b.get("published_at_unix", 0),
                "scope": b.get("scope", {}),
                "bundle_hash_sha256": _bundle_hash_or_empty(b),
            }
            for b in bundles
        ],
        "active_bundle": (
            {
                "bundle_id": active_bundle.get("bundle_id", ""),
                "version": active_bundle.get("version", ""),
                "published_at_unix": active_bundle.get("published_at_unix", 0),
                "signer_key_id": active_bundle.get("signer_key_id", ""),
            }
            if active_bundle
            else None
        ),
        "fleet_node_count": len(fleet_nodes),
        "fleet_node_summary": _summarise_fleet(fleet_nodes),
        "dast_a_pack_total": dast_a_payload.get("total", 0),
    }


def _summarise_fleet(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    """Count nodes by online state + last_ack_status."""
    summary = {"online": 0, "offline": 0, "applied": 0, "verify_failed": 0, "unknown": 0}
    for n in nodes:
        if n.get("online"):
            summary["online"] += 1
        else:
            summary["offline"] += 1
        st = (n.get("last_ack_status") or "unknown").lower()
        if st in summary:
            summary[st] += 1
    return summary


def _bundle_hash_or_empty(b: dict[str, Any]) -> str:
    """Recover the bundle SHA-256 from the wire representation when possible.

    The policy bus's ``/bundles`` view scrubs ``bundle_yaml_b64`` from the
    list response to keep it small — so we can't always recompute the hash
    on the client. Surface an empty string honestly when that's the case;
    A-10's PDF says "(hash withheld by bus admin endpoint)" in that path.
    """
    if "bundle_hash_sha256" in b:
        return str(b["bundle_hash_sha256"])
    yaml_b64 = b.get("bundle_yaml_b64")
    if not yaml_b64:
        return ""
    try:
        import base64

        return hashlib.sha256(base64.b64decode(yaml_b64)).hexdigest()
    except (TypeError, ValueError, hashlib.UnsupportedHashError):  # type: ignore[attr-defined]
        return ""


__all__ = [
    "DEFAULT_ATLAS_URL",
    "DEFAULT_POLICY_BUS_URL",
    "DEFAULT_DAST_A_URL",
    "ServiceURLs",
    "resolve_service_urls_from_env",
    "query_atlas_registry",
    "query_policy_bus",
    "query_dast_a_packs",
    "assemble_ai_bom",
]
