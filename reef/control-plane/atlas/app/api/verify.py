"""POST /verify — called by the Lobster Trap sidecar at handshake time."""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.crypto import verify_manifest_signature
from app.models import VerifyRequest, VerifyResponse, Violation
from app.policy import (
    enforce_capability_allowlist,
    enforce_tool_allowlist,
    is_vulnerable_sdk,
    requires_extra_scrutiny,
    stdio_pre_handshake_decision,
    vulnerable_sdk_violation,
)

router = APIRouter()


@router.post("/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest, request: Request) -> VerifyResponse:
    """Decide whether a server bind attempt is allowed.

    Decisions:
      - ``allow``  : signed entry exists, all six capabilities pass.
      - ``review`` : entry status is ``quarantined`` (or transport policy
        wants human eyes on a corner case).
      - ``deny``   : entry missing, mismatched, or any capability fails.

    Every decision is appended to the audit log with a fresh ``audit_id``.
    """
    store = request.app.state.store
    auditor = request.app.state.auditor

    violations: list[Violation] = []
    matched_capabilities: list[str] = []

    entry = store.find_entry(req.mcpName, req.version)
    if entry is None:
        # No signed entry → MUST deny. Look up other versions so the audit
        # captures whether the operator has a similar (but wrong) version
        # registered — a known-good registry lookup miss is the canonical
        # "victim-mcp-server" sad path.
        siblings = store.find_any_version(req.mcpName)
        sibling_versions = [s.manifest.version for s in siblings]
        reason = (
            f"No signed registry entry for {req.mcpName}@{req.version}. "
            "Reef enforces the 'signed: false + warning' convention (see "
            "docs/10-DECISIONS.md D-020); unsigned MCP servers are blocked at "
            "handshake."
        )
        if sibling_versions:
            reason += (
                f" Registry knows other versions for this mcpName: "
                f"{sibling_versions!r} — version pinning prevents fallback."
            )
        violations.append(
            Violation(code="BIND_DENIED", detail=reason)
        )
        audit_id = auditor.log(
            {
                "kind": "verify",
                "decision": "deny",
                "mcpName": req.mcpName,
                "version": req.version,
                "transport": req.transport,
                "agent_id": req.agent_id,
                "request_id": req.request_id,
                "reason": reason,
                "violations": [v.model_dump() for v in violations],
            }
        )
        return VerifyResponse(
            decision="deny",
            reason=reason,
            registry_id=None,
            matched_capabilities=[],
            violations=violations,
            audit_id=audit_id,
        )

    # We have an entry. Re-verify its signature so a tampered store file
    # can't bypass crypto (the file is mutex-protected but operators may
    # still edit it offline).
    publisher = store.get_publisher(entry.publisher_id)
    if publisher is None or publisher.revoked:
        reason = (
            f"publisher {entry.publisher_id!r} for registry_id {entry.registry_id} "
            "is unknown or revoked; refusing handshake"
        )
        violations.append(Violation(code="PUBLISHER_REVOKED", detail=reason))
        audit_id = auditor.log(
            {
                "kind": "verify",
                "decision": "deny",
                "registry_id": entry.registry_id,
                "mcpName": req.mcpName,
                "version": req.version,
                "agent_id": req.agent_id,
                "request_id": req.request_id,
                "reason": reason,
                "violations": [v.model_dump() for v in violations],
            }
        )
        return VerifyResponse(
            decision="deny",
            reason=reason,
            registry_id=entry.registry_id,
            violations=violations,
            audit_id=audit_id,
        )

    manifest_dict = entry.manifest.model_dump(mode="json")
    if not verify_manifest_signature(
        manifest_dict, entry.signature_hex, publisher.public_key_hex
    ):
        reason = (
            f"signature on registry_id {entry.registry_id} did not verify against "
            f"publisher {publisher.publisher_id!r} public key (tampered store?)"
        )
        violations.append(Violation(code="SIGNATURE_INVALID", detail=reason))
        audit_id = auditor.log(
            {
                "kind": "verify",
                "decision": "deny",
                "registry_id": entry.registry_id,
                "mcpName": req.mcpName,
                "version": req.version,
                "agent_id": req.agent_id,
                "request_id": req.request_id,
                "reason": reason,
                "violations": [v.model_dump() for v in violations],
            }
        )
        return VerifyResponse(
            decision="deny",
            reason=reason,
            registry_id=entry.registry_id,
            violations=violations,
            audit_id=audit_id,
        )
    matched_capabilities.append("publisher_provenance")

    # Poisoned entry — always deny with the OX disclosure code attached.
    if entry.status == "poisoned":
        reason = entry.poisoned_reason or "registry entry flagged as poisoned"
        violations.append(Violation(**vulnerable_sdk_violation(entry.manifest.sdk_version)))
        audit_id = auditor.log(
            {
                "kind": "verify",
                "decision": "deny",
                "registry_id": entry.registry_id,
                "mcpName": req.mcpName,
                "version": req.version,
                "agent_id": req.agent_id,
                "request_id": req.request_id,
                "reason": reason,
                "violations": [v.model_dump() for v in violations],
                "status": "poisoned",
            }
        )
        return VerifyResponse(
            decision="deny",
            reason=reason,
            registry_id=entry.registry_id,
            matched_capabilities=matched_capabilities,
            violations=violations,
            audit_id=audit_id,
        )

    # Quarantined entry — return ``review`` and let the Lobster Trap pipeline
    # dispatch HUMAN_REVIEW.
    if entry.status == "quarantined":
        reason = entry.quarantined_reason or "registry entry held under review"
        audit_id = auditor.log(
            {
                "kind": "verify",
                "decision": "review",
                "registry_id": entry.registry_id,
                "mcpName": req.mcpName,
                "version": req.version,
                "agent_id": req.agent_id,
                "request_id": req.request_id,
                "reason": reason,
                "status": "quarantined",
            }
        )
        return VerifyResponse(
            decision="review",
            reason=reason,
            registry_id=entry.registry_id,
            matched_capabilities=matched_capabilities,
            violations=violations,
            audit_id=audit_id,
        )

    # Verified status — but the six capabilities still have to pass on this
    # specific handshake attempt. Operators may have a verified entry but the
    # binding client lies about its SDK version / tools.

    # Capability #5 — SDK version policy
    if is_vulnerable_sdk(entry.manifest.sdk_version):
        violations.append(Violation(**vulnerable_sdk_violation(entry.manifest.sdk_version)))
    if req.claimed_sdk_version and is_vulnerable_sdk(req.claimed_sdk_version):
        violations.append(Violation(**vulnerable_sdk_violation(req.claimed_sdk_version)))
    if not violations:
        matched_capabilities.append("sdk_version_policy")

    # Capability #6 — transport policy + capability #1 — STDIO entrypoint
    if requires_extra_scrutiny(req.transport):
        deny, reason = stdio_pre_handshake_decision(
            transport=req.transport,
            manifest=entry.manifest,
            claimed_entrypoint_hash=req.claimed_entrypoint_hash,
        )
        if deny:
            violations.append(
                Violation(code="MCP-RCE-26.04", detail=reason or "stdio policy denial")
            )
        else:
            matched_capabilities.append("stdio_entrypoint_hash")
            matched_capabilities.append("transport_policy")
    else:
        matched_capabilities.append("transport_policy")

    # Capability #3 — capability allowlist
    extra_caps = enforce_capability_allowlist(entry.manifest, None)
    # We don't currently accept claimed capabilities on the wire; this hook
    # is reserved for the A-9 (DPI binding) work. When supplied we'd block.
    if not extra_caps:
        matched_capabilities.append("capability_allowlist")

    # Capability #2 — manifest pinning (tool set)
    extra_tools = enforce_tool_allowlist(entry.manifest, req.claimed_tools)
    if extra_tools:
        violations.append(
            Violation(
                code="MANIFEST_PIN_VIOLATION",
                detail=(
                    f"server advertised tools {extra_tools!r} that are not on the "
                    f"signed manifest for {entry.registry_id}"
                ),
            )
        )
    else:
        matched_capabilities.append("manifest_pinning")

    if violations:
        reason = "; ".join(v.detail for v in violations)
        audit_id = auditor.log(
            {
                "kind": "verify",
                "decision": "deny",
                "registry_id": entry.registry_id,
                "mcpName": req.mcpName,
                "version": req.version,
                "agent_id": req.agent_id,
                "request_id": req.request_id,
                "reason": reason,
                "violations": [v.model_dump() for v in violations],
            }
        )
        return VerifyResponse(
            decision="deny",
            reason=reason,
            registry_id=entry.registry_id,
            matched_capabilities=matched_capabilities,
            violations=violations,
            audit_id=audit_id,
        )

    reason = (
        f"manifest matches signed entry verified by publisher "
        f"{publisher.publisher_id} ({publisher.fingerprint})"
    )
    audit_id = auditor.log(
        {
            "kind": "verify",
            "decision": "allow",
            "registry_id": entry.registry_id,
            "publisher_id": publisher.publisher_id,
            "mcpName": req.mcpName,
            "version": req.version,
            "transport": req.transport,
            "agent_id": req.agent_id,
            "request_id": req.request_id,
            "reason": reason,
        }
    )
    return VerifyResponse(
        decision="allow",
        reason=reason,
        registry_id=entry.registry_id,
        matched_capabilities=matched_capabilities,
        violations=[],
        audit_id=audit_id,
    )
