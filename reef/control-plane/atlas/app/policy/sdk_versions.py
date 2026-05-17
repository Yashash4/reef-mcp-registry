"""SDK-version policy — the centerpiece block for the April 2026 RCE class.

Sources (verbatim from docs/24-GROUNDING.md Part 3):

  > "This flaw enables Arbitrary Command Execution (RCE) on any system running
  > a vulnerable MCP implementation, granting attackers direct access to
  > sensitive user data, internal databases, API keys, and chat histories."
  > — OX Security researchers, April 2026

  > "Anthropic's Model Context Protocol gives a direct configuration-to-command
  > execution via their STDIO interface on all of their implementations,
  > regardless of programming language." — OX Security researchers

Atlas's SDK-version policy blocks any manifest declaring an MCP SDK whose
version lies in the OX-Security-disclosed vulnerable range. Code `MCP-RCE-26.04`
is surfaced verbatim in every deny path so operators can grep audit logs
against the disclosure ID. The "safe" pivot version `1.10.0` is the published
post-disclosure threshold — see https://github.com/modelcontextprotocol/sdk and
the April 2026 OX advisory.
"""

from __future__ import annotations

import re

VIOLATION_CODE = "MCP-RCE-26.04"

# The verbatim citation we surface in every audit + deny path.
OX_PRIMARY_QUOTE = (
    "OX Security disclosure April 2026: "
    "\"This flaw enables Arbitrary Command Execution (RCE) on any system "
    "running a vulnerable MCP implementation, granting attackers direct "
    "access to sensitive user data, internal databases, API keys, and chat "
    "histories.\" — OX Security primary disclosure, "
    "https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/"
)

MCP_RCE_26_04_DETAIL = (
    "MCP-RCE-26.04 — OX Security disclosure April 2026. SDK version {sdk} is "
    "on the OX Security April 2026 vulnerable list (STDIO command-execution "
    "RCE class). The protocol gives a direct configuration-to-command "
    "execution via the STDIO interface on every official MCP SDK regardless "
    "of programming language. Upgrade to a post-disclosure SDK version "
    "(>=1.10.0 for @modelcontextprotocol/sdk) before re-registering."
)

# Vulnerable ranges per SDK package, distilled from the OX advisory cluster.
# Format: dict[sdk_name_lower, tuple[(min_inclusive_str, max_inclusive_str), ...]]
# Names normalised to the lowercase package id without version (so we accept
# both @modelcontextprotocol/sdk and the python `mcp` import name).
_VULN_RANGES: dict[str, tuple[tuple[str, str], ...]] = {
    # JavaScript / TypeScript reference SDK. <1.10.0 is the vulnerable window.
    "@modelcontextprotocol/sdk": (("0.0.0", "1.9.999"),),
    "modelcontextprotocol/sdk": (("0.0.0", "1.9.999"),),
    "mcp-sdk": (("0.0.0", "1.9.999"),),
    # Python SDK (`mcp` on PyPI). Same window logically.
    "mcp": (("0.0.0", "1.9.999"),),
    # Java SDK family.
    "io.modelcontextprotocol:mcp-sdk": (("0.0.0", "1.9.999"),),
    # Rust SDK family.
    "modelcontextprotocol-rs": (("0.0.0", "1.9.999"),),
}

# Match `name@version` (npm style), `name==version` (pip), or `name:version`
# (maven coords). We extract the package id and the version separately.
_SDK_VERSION_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_./:@\-]+?)\s*(?:[@=]+|:)\s*v?(?P<version>[0-9][A-Za-z0-9.\-+]*)\s*$"
)


def _parse_sdk(sdk_version: str) -> tuple[str, str] | None:
    """Split a `name@version` string into ``(name_lower, version)``.

    Returns None when the input doesn't look like a parseable SDK reference.
    """
    match = _SDK_VERSION_RE.match(sdk_version.strip())
    if not match:
        return None
    name = match.group("name").lower().strip()
    version = match.group("version").strip()
    return name, version


def _parse_version_tuple(v: str) -> tuple[int, ...]:
    """Return a comparable integer tuple for a dotted semver-ish string.

    Pre-release suffixes are stripped (so ``1.0.0-rc1`` => (1, 0, 0)). This
    is intentionally lenient because the OX disclosure tracked vulnerable
    ranges by the major+minor pivot, not by pre-release labels.
    """
    base = re.split(r"[-+]", v, maxsplit=1)[0]
    parts = base.split(".")
    out: list[int] = []
    for p in parts:
        if not p:
            continue
        m = re.match(r"^(\d+)", p)
        if not m:
            break
        out.append(int(m.group(1)))
    while out and out[-1] == 0:
        # Don't strip trailing zeros — we want strict numeric comparison.
        break
    return tuple(out)


def _version_in_range(version: str, lo: str, hi: str) -> bool:
    v = _parse_version_tuple(version)
    return _parse_version_tuple(lo) <= v <= _parse_version_tuple(hi)


def is_vulnerable_sdk(sdk_version: str | None) -> bool:
    """Return True when the SDK declaration matches the April 2026 vuln list.

    Unparseable inputs are treated as **vulnerable** (fail-closed). The
    SDK-version field is required at register time, so an empty/unparseable
    string at verify time means the registry entry is missing data the
    operator declared the manifest had — that's a denial in itself.
    """
    if not sdk_version:
        return True
    parsed = _parse_sdk(sdk_version)
    if parsed is None:
        # Treat ambiguous "@modelcontextprotocol/sdk@latest" or plain "1.2.3"
        # without a name as vulnerable — operators must be explicit.
        return True
    name, version = parsed
    ranges = _VULN_RANGES.get(name)
    if ranges is None:
        # Unknown SDK family is not on the vulnerable list. Atlas will still
        # flag transport policy + entrypoint hash separately.
        return False
    return any(_version_in_range(version, lo, hi) for lo, hi in ranges)


def vulnerable_sdk_violation(sdk_version: str | None) -> dict[str, str]:
    """Return the structured violation envelope used in the API response."""
    return {
        "code": VIOLATION_CODE,
        "detail": MCP_RCE_26_04_DETAIL.format(sdk=sdk_version or "<unspecified>"),
    }
