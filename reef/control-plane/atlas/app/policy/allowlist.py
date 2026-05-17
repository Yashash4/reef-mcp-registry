"""Capability + tool allowlist enforcement.

The signed registry entry declares which capabilities + tools the server is
permitted to surface. At verify time, the runtime claim (the tools the server
actually advertised over the wire) must be a **subset** of the signed
declaration. Capability inflation (e.g., a weather server adding
``elicitation``) => deny. Tool inflation (e.g., adding ``read_company_doc``)
=> deny.

This is capability #2 (manifest pinning) and capability #3 (capability
allowlist) from docs/24-GROUNDING.md Part 3.
"""

from __future__ import annotations

from app.models import Manifest


def enforce_capability_allowlist(
    manifest: Manifest, claimed_capabilities: list[str] | None
) -> list[str]:
    """Return capabilities the runtime advertised that aren't on the manifest.

    If the runtime declared a capability not in the signed manifest, the caller
    MUST deny — capability inflation is the OX Security attack-family #2
    (hardening bypass) pattern.
    """
    if not claimed_capabilities:
        return []
    declared = {c.lower() for c in manifest.capabilities}
    extras = [c for c in claimed_capabilities if c.lower() not in declared]
    return extras


def enforce_tool_allowlist(
    manifest: Manifest, claimed_tools: list[str] | None
) -> list[str]:
    """Return tool names the runtime advertised that aren't on the manifest.

    Mismatch => deny (tool-set drift = OX attack family #2/#4).
    """
    if not claimed_tools:
        return []
    declared = {t.name.lower() for t in manifest.tools}
    extras = [t for t in claimed_tools if t.lower() not in declared]
    return extras
