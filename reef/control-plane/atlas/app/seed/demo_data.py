"""Demo seed data — 47 verified + 2 quarantined + 1 poisoned MCP entries.

Why these numbers?
  - The Stage UI's FleetGrid is 7x7 (49) — but Reef's fleet visualisation is
    47 active nodes + 2 yellow (quarantine) + 1 red (poisoned). The
    registry's contents are what the FleetGrid is reflecting.
  - The poisoned entry MUST be `com.attacker-example.evil-server@0.5.0` so the
    integration test + recorded demo target the same artifact.
  - Each manifest is realistic-shaped (reverse-DNS mcpName, real-looking sdk
    version, a tools list) so judges scrubbing the JSON see a plausible
    registry, not lorem ipsum.

The seed is idempotent: re-running won't duplicate entries (keyed on
``(mcpName, version)`` upserts).
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.crypto import canonical_json, fingerprint, generate_keypair, sign_manifest
from app.models import (
    Manifest,
    Publisher,
    RegistryEntry,
    Tool,
)
from app.store import FileStore


# ----------------------------------------------------------------------
# Publisher catalogue — the demo-time set of trusted key holders.
# ----------------------------------------------------------------------

_PUBLISHER_DEFS: list[dict[str, Any]] = [
    {
        "publisher_id": "pub-mcp-foundation",
        "display_name": "Model Context Protocol Foundation (demo)",
        "scopes": ["com.modelcontextprotocol.*", "io.github.modelcontextprotocol.*"],
    },
    {
        "publisher_id": "pub-anthropic-demo",
        "display_name": "Anthropic Reference (demo)",
        "scopes": ["com.anthropic.*"],
    },
    {
        "publisher_id": "pub-langchain-demo",
        "display_name": "LangChain MCP (demo)",
        "scopes": ["org.langchain.mcp.*"],
    },
    {
        "publisher_id": "pub-example",
        "display_name": "Example Vendor (demo)",
        "scopes": ["com.example.*", "org.demo.*"],
    },
    {
        "publisher_id": "pub-attacker-example",
        "display_name": "Attacker Example (demo poisoned publisher)",
        # Scoped narrowly so it can sign the poisoned entry but nothing else.
        "scopes": ["com.attacker-example.*"],
    },
]


# ----------------------------------------------------------------------
# Manifest definitions — 47 verified + 2 quarantined + 1 poisoned.
# ----------------------------------------------------------------------


def _safe_sdk(name: str = "@modelcontextprotocol/sdk", version: str = "1.29.0") -> str:
    """Return an SDK string that is *not* on the April 2026 vulnerable list."""
    return f"{name}@{version}"


def _deterministic_hash(seed: str) -> str:
    """Produce a stable sha256 hex for a given seed string.

    The seed binds the hash to the mcpName+version so re-seeding produces
    identical entries. The hash plays the role of the executable hash that
    capability #1 (STDIO entrypoint integrity) pins.
    """
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return "sha256:" + digest


def _verified_manifest_defs() -> list[dict[str, Any]]:
    """Return 47 verified manifest definitions.

    Names cover three publisher namespaces (modelcontextprotocol, example,
    langchain) so the seed exercises every scope rule. Versions are
    semantically realistic and the SDK string sits *above* the April 2026
    vulnerable window so they all pass SDK-version policy.
    """

    defs: list[dict[str, Any]] = []

    # --- modelcontextprotocol reference servers (12) ---
    mcp_ref = [
        ("server-filesystem", "0.6.3", ["read_file", "write_file", "list_dir"]),
        ("server-github", "0.5.1", ["list_repos", "open_issue", "comment_pr"]),
        ("server-postgres", "0.4.0", ["query", "describe_schema"]),
        ("server-slack", "0.3.2", ["post_message", "list_channels"]),
        ("server-google-drive", "0.2.4", ["list_files", "get_file"]),
        ("server-fetch", "0.7.0", ["fetch"]),
        ("server-sqlite", "0.4.1", ["query"]),
        ("server-puppeteer", "0.3.0", ["screenshot", "click"]),
        ("server-time", "0.1.6", ["now", "convert_tz"]),
        ("server-memory", "0.2.0", ["recall", "store"]),
        ("server-everart", "0.1.2", ["generate_image"]),
        ("server-sentry", "0.1.5", ["list_issues", "get_issue"]),
    ]
    for short, version, tools in mcp_ref:
        defs.append(
            {
                "publisher_id": "pub-mcp-foundation",
                "mcpName": f"io.github.modelcontextprotocol/{short}",
                "version": version,
                "transports": ["stdio", "http"] if "filesystem" in short else ["stdio"],
                "tools": tools,
                "sdk_version": _safe_sdk(),
                "capabilities": ["tools", "resources"],
            }
        )

    # --- Anthropic-namespaced demo servers (5) ---
    anth_defs = [
        ("server-jira", "1.4.0", ["create_issue", "search_issues"]),
        ("server-confluence", "1.2.0", ["search_pages", "create_page"]),
        ("server-zendesk", "0.9.1", ["list_tickets"]),
        ("server-pagerduty", "0.5.2", ["trigger_incident", "ack_incident"]),
        ("server-snowflake", "0.7.3", ["query", "list_schemas"]),
    ]
    for short, version, tools in anth_defs:
        defs.append(
            {
                "publisher_id": "pub-anthropic-demo",
                "mcpName": f"com.anthropic/{short}",
                "version": version,
                "transports": ["http"],
                "tools": tools,
                "sdk_version": _safe_sdk("@modelcontextprotocol/sdk", "1.29.0"),
                "capabilities": ["tools"],
            }
        )

    # --- LangChain MCP-shaped servers (5) ---
    lc_defs = [
        ("weather", "2.0.1", ["get_weather", "get_forecast"]),
        ("calendar", "1.1.4", ["list_events", "create_event"]),
        ("notion", "1.3.0", ["search_pages", "append_block"]),
        ("airtable", "1.0.5", ["list_records", "create_record"]),
        ("hubspot", "0.4.7", ["list_contacts", "create_deal"]),
    ]
    for short, version, tools in lc_defs:
        defs.append(
            {
                "publisher_id": "pub-langchain-demo",
                "mcpName": f"org.langchain.mcp.{short}",
                "version": version,
                "transports": ["stdio", "http"],
                "tools": tools,
                "sdk_version": _safe_sdk(),
                "capabilities": ["tools", "resources", "prompts"],
            }
        )

    # --- com.example.* and org.demo.* demo servers (25) ---
    ex_defs = [
        ("com.example", "weather-mcp", "1.2.3", ["get_weather", "get_forecast"]),
        ("com.example", "billing-mcp", "0.9.1", ["create_invoice", "void_invoice"]),
        ("com.example", "search-mcp", "1.0.0", ["web_search"]),
        ("com.example", "translate-mcp", "0.5.2", ["translate"]),
        ("com.example", "support-mcp", "1.4.1", ["create_ticket", "close_ticket"]),
        ("com.example", "crm-mcp", "0.8.0", ["upsert_contact"]),
        ("com.example", "linter-mcp", "1.0.5", ["lint_file"]),
        ("com.example", "stripe-bridge", "1.6.0", ["create_charge"]),
        ("com.example", "github-mirror", "0.3.0", ["open_pr"]),
        ("com.example", "k8s-tools", "0.7.1", ["list_pods", "describe_node"]),
        ("com.example", "vault-bridge", "0.2.4", ["read_secret"]),
        ("com.example", "terraform-tools", "0.6.0", ["plan", "apply"]),
        ("com.example", "splunk-bridge", "0.5.5", ["search"]),
        ("com.example", "datadog-bridge", "1.0.2", ["list_monitors"]),
        ("org.demo", "media-mcp", "1.0.0", ["transcode"]),
        ("org.demo", "audit-mcp", "0.4.3", ["export_log"]),
        ("org.demo", "scim-mcp", "0.9.0", ["create_user"]),
        ("org.demo", "ldap-mcp", "0.3.1", ["search_users"]),
        ("org.demo", "okta-mcp", "1.1.0", ["assign_app"]),
        ("org.demo", "jenkins-mcp", "0.7.0", ["trigger_build"]),
        ("org.demo", "argo-mcp", "0.8.2", ["promote"]),
        ("org.demo", "grafana-mcp", "0.6.5", ["render_dashboard"]),
        ("org.demo", "prometheus-mcp", "0.5.4", ["query"]),
        ("org.demo", "sonarqube-mcp", "0.4.0", ["scan"]),
        ("org.demo", "rollout-mcp", "0.3.0", ["start_rollout"]),
    ]
    for ns, short, version, tools in ex_defs:
        defs.append(
            {
                "publisher_id": "pub-example",
                "mcpName": f"{ns}/{short}",
                "version": version,
                "transports": ["stdio", "http"]
                if "github" in short or "bridge" in short
                else ["http"],
                "tools": tools,
                "sdk_version": _safe_sdk(),
                "capabilities": ["tools"],
            }
        )

    assert len(defs) == 47, f"expected 47 verified defs, got {len(defs)}"
    return defs


def _quarantined_manifest_defs() -> list[dict[str, Any]]:
    """Two manifests known to be quarantined.

    Each has a distinct reason — a key rotation mid-flight and a signature
    replay caught by the verifier. Calls to /verify return ``decision: review``
    for these.
    """
    return [
        {
            "publisher_id": "pub-example",
            "mcpName": "com.example/keyrotation-mcp",
            "version": "0.4.1",
            "transports": ["http"],
            "tools": ["list_keys"],
            "sdk_version": _safe_sdk(),
            "capabilities": ["tools"],
            "quarantined_reason": (
                "Publisher key rotated mid-flight — pending re-issue and "
                "publisher attestation. Held under HUMAN_REVIEW per Reef "
                "policy."
            ),
        },
        {
            "publisher_id": "pub-langchain-demo",
            "mcpName": "org.langchain.mcp.replay",
            "version": "1.0.0",
            "transports": ["stdio", "http"],
            "tools": ["echo"],
            "sdk_version": _safe_sdk(),
            "capabilities": ["tools"],
            "quarantined_reason": (
                "Manifest signature replay detected — same registry_id signed "
                "twice with conflicting tool surfaces within 30s. Atlas "
                "quarantines pending audit."
            ),
        },
    ]


def _poisoned_manifest_def() -> dict[str, Any]:
    """The single poisoned manifest — the centerpiece block.

    ``@modelcontextprotocol/sdk@0.5.0`` lives squarely in the April 2026
    vulnerable window. The entrypoint hash deliberately doesn't match the
    sha256 of any production binary — STDIO policy denies it on both grounds.
    """
    return {
        "publisher_id": "pub-attacker-example",
        "mcpName": "com.attacker-example/evil-server",
        "version": "0.5.0",
        "transports": ["stdio"],
        "tools": ["read_company_doc", "send_message", "exec"],
        "sdk_version": "@modelcontextprotocol/sdk@0.5.0",
        "capabilities": ["tools", "resources", "elicitation"],
        "poisoned_reason": (
            "Pinned SDK version @modelcontextprotocol/sdk@0.5.0 is on the OX "
            "Security April 2026 vulnerable list (STDIO command-execution RCE "
            "class). stdio_entrypoint_hash does not match any known-good "
            "binary. Refusing any handshake under MCP-RCE-26.04."
        ),
    }


# ----------------------------------------------------------------------
# Seed orchestration
# ----------------------------------------------------------------------


def _build_manifest(definition: dict[str, Any]) -> Manifest:
    """Convert a flat definition dict to a Manifest model.

    The ``stdio_entrypoint_hash`` is derived deterministically from
    ``mcpName@version`` so seeded entries are reproducible between runs.
    """
    seed = f"{definition['mcpName']}@{definition['version']}"
    return Manifest(
        mcpName=definition["mcpName"],
        version=definition["version"],
        protocolVersion="2025-06-18",
        transports=definition["transports"],
        tools=[Tool(name=t) for t in definition["tools"]],
        capabilities=definition.get("capabilities", []),
        stdio_entrypoint_hash=_deterministic_hash(seed)
        if "stdio" in definition["transports"]
        else None,
        sdk_version=definition["sdk_version"],
    )


def _ensure_publisher_keys(keys_dir: Path) -> dict[str, dict[str, str]]:
    """Generate or load per-publisher ed25519 keys.

    Each publisher gets a 64-char-hex (32-byte) private key file under
    ``keys_dir``. Files are created with 0o600 permissions on POSIX
    (no-op on Windows). The function returns a dict mapping publisher_id to
    ``{"private_hex", "public_hex"}``.
    """
    keys_dir.mkdir(parents=True, exist_ok=True)
    materials: dict[str, dict[str, str]] = {}
    for pdef in _PUBLISHER_DEFS:
        pid = pdef["publisher_id"]
        sk_path = keys_dir / f"{pid}.sk"
        pk_path = keys_dir / f"{pid}.pk"
        if sk_path.exists() and pk_path.exists():
            sk_hex = sk_path.read_text(encoding="utf-8").strip()
            pk_hex = pk_path.read_text(encoding="utf-8").strip()
        else:
            sk_hex, pk_hex = generate_keypair()
            sk_path.write_text(sk_hex, encoding="utf-8")
            pk_path.write_text(pk_hex, encoding="utf-8")
            try:
                os.chmod(sk_path, 0o600)
            except (OSError, NotImplementedError):
                # Windows / non-POSIX — best-effort.
                pass
        materials[pid] = {"private_hex": sk_hex, "public_hex": pk_hex}
    return materials


def seed_demo(
    store: FileStore,
    keys_dir: str | os.PathLike[str],
    *,
    logger=None,
) -> dict[str, int]:
    """Populate the file store with the demo set.

    Idempotent — re-running on an already-seeded store yields the same set
    (upserts keyed on (mcpName, version)). Returns counts so the API health
    endpoint can echo them.
    """
    keys_path = Path(keys_dir)
    materials = _ensure_publisher_keys(keys_path)

    now_iso = datetime.now(tz=timezone.utc).isoformat()

    # --- Persist publishers
    publishers: list[Publisher] = []
    for pdef in _PUBLISHER_DEFS:
        pid = pdef["publisher_id"]
        pub = Publisher(
            publisher_id=pid,
            display_name=pdef["display_name"],
            public_key_hex=materials[pid]["public_hex"],
            scopes=pdef["scopes"],
            created_at=now_iso,
            revoked=False,
            fingerprint=fingerprint(materials[pid]["public_hex"]),
        )
        store.upsert_publisher(pub)
        publishers.append(pub)

    # --- Build + sign verified entries
    verified_entries: list[RegistryEntry] = []
    for idx, defn in enumerate(_verified_manifest_defs()):
        manifest = _build_manifest(defn)
        sig = sign_manifest(
            manifest.model_dump(mode="json"),
            materials[defn["publisher_id"]]["private_hex"],
        )
        entry = RegistryEntry(
            registry_id=f"reg-{idx:04d}-{manifest.mcpName.replace('/', '-')}",
            manifest=manifest,
            publisher_id=defn["publisher_id"],
            signature_hex=sig,
            status="verified",
            registered_at=now_iso,
            checks_passed=[
                "publisher_provenance",
                "manifest_schema",
                "sdk_version_policy",
                "stdio_policy",
            ],
            checks_failed=[],
        )
        verified_entries.append(entry)

    # --- Quarantined entries
    quarantined_entries: list[RegistryEntry] = []
    for idx, defn in enumerate(_quarantined_manifest_defs(), start=len(verified_entries)):
        manifest = _build_manifest(defn)
        sig = sign_manifest(
            manifest.model_dump(mode="json"),
            materials[defn["publisher_id"]]["private_hex"],
        )
        entry = RegistryEntry(
            registry_id=f"reg-{idx:04d}-{manifest.mcpName.replace('/', '-')}",
            manifest=manifest,
            publisher_id=defn["publisher_id"],
            signature_hex=sig,
            status="quarantined",
            registered_at=now_iso,
            quarantined_reason=defn["quarantined_reason"],
            checks_passed=["publisher_provenance", "manifest_schema"],
            checks_failed=["operator_review"],
        )
        quarantined_entries.append(entry)

    # --- Poisoned entry (the centerpiece sad path)
    poisoned_defn = _poisoned_manifest_def()
    poisoned_manifest = _build_manifest(poisoned_defn)
    # Deliberately overwrite with a mismatch hash so the STDIO entrypoint
    # check fails. We sign the manifest as written so the verifier still finds
    # a syntactically valid signed entry — the entry just denies on policy
    # rather than on signature.
    poisoned_manifest = poisoned_manifest.model_copy(
        update={"stdio_entrypoint_hash": "sha256:" + "0" * 64}
    )
    poisoned_sig = sign_manifest(
        poisoned_manifest.model_dump(mode="json"),
        materials[poisoned_defn["publisher_id"]]["private_hex"],
    )
    poisoned_entry = RegistryEntry(
        registry_id="reg-poisoned-attacker-example-evil-server",
        manifest=poisoned_manifest,
        publisher_id=poisoned_defn["publisher_id"],
        signature_hex=poisoned_sig,
        status="poisoned",
        registered_at=now_iso,
        poisoned_reason=poisoned_defn["poisoned_reason"],
        checks_passed=["manifest_schema"],
        checks_failed=["sdk_version_policy", "stdio_entrypoint_hash", "publisher_scope"],
    )

    all_entries: list[RegistryEntry] = []
    all_entries.extend(verified_entries)
    all_entries.extend(quarantined_entries)
    all_entries.append(poisoned_entry)

    store.bulk_upsert_entries(all_entries)

    counts = {
        "verified": len(verified_entries),
        "quarantined": len(quarantined_entries),
        "poisoned": 1,
        "publishers": len(publishers),
    }

    if logger is not None:
        # Cross-publisher fingerprint summary keeps the line readable.
        primary = next(p for p in publishers if p.publisher_id == "pub-example")
        logger.info(
            "[atlas] seeded %d verified + %d quarantined + %d poisoned MCP server entries (key fingerprint %s)",
            counts["verified"],
            counts["quarantined"],
            counts["poisoned"],
            primary.fingerprint,
        )
    return counts


def write_canonical_snapshot(store: FileStore, target: Path) -> None:
    """Dump a canonical-JSON snapshot of the registry to disk.

    Useful for hand-verification during the recorded demo: ``cat
    data/snapshot.json`` shows the signed entries grouped by status.
    """
    entries = store.list_entries()
    snap = {
        "verified": [e.model_dump(mode="json") for e in entries if e.status == "verified"],
        "quarantined": [e.model_dump(mode="json") for e in entries if e.status == "quarantined"],
        "poisoned": [e.model_dump(mode="json") for e in entries if e.status == "poisoned"],
    }
    target.write_bytes(canonical_json(snap))
