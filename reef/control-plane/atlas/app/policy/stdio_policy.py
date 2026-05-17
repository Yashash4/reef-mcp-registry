"""STDIO transport policy.

The April 2026 OX disclosure traced the RCE class to the STDIO transport:

  > "MCP uses STDIO (standard input/output) as a local transport mechanism for
  > an AI application to spawn an MCP server as a subprocess. But in practice
  > it actually lets anyone run any arbitrary OS command." — OX Security

  > "Pass in a malicious command, receive an error – and the command still
  > runs. No sanitization warnings." — OX Security

Atlas's transport policy:

  1. STDIO transport requires a populated ``stdio_entrypoint_hash`` on the
     signed registry entry. Missing hash => quarantine at register; deny at
     verify. This is capability #1 of the six listed in 24-GROUNDING.md Part 3.
  2. STDIO verifies with **extra scrutiny**: the registry rejects mismatched
     entrypoint hashes (capability #1) before evaluating tools/capabilities.
  3. HTTP transport gets baseline scrutiny — still requires a verified
     publisher signature + manifest pin, but no entrypoint-hash requirement.
"""

from __future__ import annotations

from app.models import Manifest

STDIO_DENIAL_REASON = (
    "STDIO transport pre-handshake denial — the April 2026 execution model is "
    "treated as untrusted by default in this fleet. The OX Security "
    "disclosure of 2026-04-16 (https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/) "
    "described the STDIO transport as providing \"a direct "
    "configuration-to-command execution via their STDIO interface on all of "
    "their implementations, regardless of programming language\". Atlas "
    "requires an unrevoked publisher signature + matching entrypoint hash "
    "+ post-disclosure SDK before allowing a STDIO bind."
)


def requires_extra_scrutiny(transport: str) -> bool:
    """True when transport carries the April 2026 RCE class risk."""
    return transport.lower() == "stdio"


def stdio_pre_handshake_decision(
    *,
    transport: str,
    manifest: Manifest,
    claimed_entrypoint_hash: str | None,
) -> tuple[bool, str | None]:
    """Apply STDIO transport policy to a verify request.

    Returns ``(deny, reason)``. When ``deny`` is True, the caller MUST emit a
    deny outcome with code MCP-RCE-26.04 — no exceptions, no warnings, no
    silent fallthrough.
    """
    if transport.lower() != "stdio":
        return False, None
    # STDIO requires the registry entry to have a pinned entrypoint hash.
    if not manifest.stdio_entrypoint_hash:
        return True, (
            STDIO_DENIAL_REASON
            + " Registry entry is missing stdio_entrypoint_hash; refusing handshake."
        )
    # If the verifier provided a claimed hash, it MUST match the signed entry.
    if claimed_entrypoint_hash and claimed_entrypoint_hash != manifest.stdio_entrypoint_hash:
        return True, (
            STDIO_DENIAL_REASON
            + f" Claimed entrypoint hash {claimed_entrypoint_hash!r} does not match "
            f"signed entry hash {manifest.stdio_entrypoint_hash!r}."
        )
    return False, None
