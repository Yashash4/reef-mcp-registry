"""POST /register — accept a publisher-signed manifest into the registry."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from app.crypto import verify_manifest_signature
from app.models import RegisterRequest, RegisterResponse, RegistryEntry
from app.policy import (
    is_vulnerable_sdk,
    vulnerable_sdk_violation,
)

router = APIRouter()


def _scope_match(scopes: list[str], mcp_name: str) -> bool:
    """Return True when at least one scope pattern covers the mcpName.

    Scope grammar:
      - exact: ``com.example/weather-mcp``
      - prefix wildcard: ``com.example.*`` (matches anything under com.example)
      - prefix wildcard with slash: ``com.example.*/something`` is not
        supported in v1 — keep scopes coarse-grained at the namespace level.
    A publisher with no declared scopes is rejected (we never silently allow).
    """
    if not scopes:
        return False
    name = mcp_name.lower()
    for s in scopes:
        s_lc = s.lower().strip()
        if s_lc == name:
            return True
        if s_lc.endswith(".*"):
            prefix = s_lc[:-2]
            if name == prefix or name.startswith(prefix + ".") or name.startswith(prefix + "/"):
                return True
        elif s_lc.endswith("*"):
            prefix = s_lc[:-1]
            if name.startswith(prefix):
                return True
    return False


@router.post("/register", status_code=201, response_model=RegisterResponse)
def register(req: RegisterRequest, request: Request) -> RegisterResponse:
    """Accept a signed manifest into the registry.

    Validation order (every step explicit; nothing silently allowed):
      1. Publisher must exist + be unrevoked.
      2. Signature must verify against the publisher's public key.
      3. Publisher scope must cover the manifest's mcpName.
      4. SDK-version policy (vulnerable SDK → quarantine + poisoned tag).
      5. STDIO transport requires stdio_entrypoint_hash to be set.
    """
    store = request.app.state.store
    auditor = request.app.state.auditor

    checks_passed: list[str] = []
    checks_failed: list[str] = []
    status: str = "verified"
    poisoned_reason: str | None = None
    quarantined_reason: str | None = None

    publisher = store.get_publisher(req.publisher_id)
    if publisher is None:
        # Surface this as a 400 rather than silently quarantining — the caller
        # should know the publisher_id is unknown.
        auditor.log(
            {
                "kind": "register",
                "decision": "error",
                "error": "unknown_publisher",
                "publisher_id": req.publisher_id,
                "mcpName": req.manifest.mcpName,
                "version": req.manifest.version,
            }
        )
        raise HTTPException(
            status_code=400,
            detail=f"unknown publisher_id {req.publisher_id!r}",
        )
    if publisher.revoked:
        auditor.log(
            {
                "kind": "register",
                "decision": "error",
                "error": "revoked_publisher",
                "publisher_id": req.publisher_id,
                "mcpName": req.manifest.mcpName,
                "version": req.manifest.version,
            }
        )
        raise HTTPException(
            status_code=403,
            detail=f"publisher {publisher.publisher_id} has been revoked",
        )

    manifest_dict = req.manifest.model_dump(mode="json")

    if verify_manifest_signature(manifest_dict, req.signature, publisher.public_key_hex):
        checks_passed.append("publisher_provenance")
    else:
        checks_failed.append("publisher_provenance")
        auditor.log(
            {
                "kind": "register",
                "decision": "error",
                "error": "bad_signature",
                "publisher_id": publisher.publisher_id,
                "mcpName": req.manifest.mcpName,
                "version": req.manifest.version,
            }
        )
        raise HTTPException(
            status_code=400,
            detail="manifest signature did not verify against publisher's public key",
        )

    if _scope_match(publisher.scopes, req.manifest.mcpName):
        checks_passed.append("publisher_scope")
    else:
        checks_failed.append("publisher_scope")
        poisoned_reason = (
            f"publisher {publisher.publisher_id} scopes {publisher.scopes!r} do not "
            f"cover mcpName {req.manifest.mcpName!r}; treating as poisoned"
        )
        status = "poisoned"

    # Manifest schema is implicitly checked by pydantic at decode time.
    checks_passed.append("manifest_schema")

    if is_vulnerable_sdk(req.manifest.sdk_version):
        checks_failed.append("sdk_version_policy")
        viol = vulnerable_sdk_violation(req.manifest.sdk_version)
        poisoned_reason = poisoned_reason or viol["detail"]
        status = "poisoned"
    else:
        checks_passed.append("sdk_version_policy")

    if req.manifest.has_stdio() and not req.manifest.stdio_entrypoint_hash:
        checks_failed.append("stdio_policy")
        if status == "verified":
            status = "quarantined"
            quarantined_reason = (
                "STDIO transport declared without stdio_entrypoint_hash — "
                "capability #1 (STDIO entrypoint integrity) cannot be "
                "enforced. Held for operator review."
            )
    else:
        checks_passed.append("stdio_policy")

    registry_id = "reg-" + secrets.token_hex(8) + "-" + req.manifest.mcpName.replace("/", "-")
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    entry = RegistryEntry(
        registry_id=registry_id,
        manifest=req.manifest,
        publisher_id=publisher.publisher_id,
        signature_hex=req.signature,
        status=status,
        registered_at=now_iso,
        poisoned_reason=poisoned_reason,
        quarantined_reason=quarantined_reason,
        checks_passed=checks_passed,
        checks_failed=checks_failed,
    )
    store.upsert_entry(entry)

    audit_id = auditor.log(
        {
            "kind": "register",
            "decision": status,
            "registry_id": registry_id,
            "publisher_id": publisher.publisher_id,
            "publisher_fingerprint": publisher.fingerprint,
            "mcpName": req.manifest.mcpName,
            "version": req.manifest.version,
            "transports": list(req.manifest.transports),
            "sdk_version": req.manifest.sdk_version,
            "checks_passed": checks_passed,
            "checks_failed": checks_failed,
            "poisoned_reason": poisoned_reason,
            "quarantined_reason": quarantined_reason,
        }
    )

    return RegisterResponse(
        registry_id=registry_id,
        registered_at=now_iso,
        status=status,
        checks_passed=checks_passed,
        checks_failed=checks_failed,
        audit_id=audit_id,
    )
