"""Policy modules backing the six grounded capabilities Atlas enforces.

See docs/24-GROUNDING.md Part 3.
"""

from app.policy.allowlist import (
    enforce_capability_allowlist,
    enforce_tool_allowlist,
)
from app.policy.sdk_versions import (
    MCP_RCE_26_04_DETAIL,
    OX_PRIMARY_QUOTE,
    is_vulnerable_sdk,
    vulnerable_sdk_violation,
)
from app.policy.stdio_policy import (
    STDIO_DENIAL_REASON,
    requires_extra_scrutiny,
    stdio_pre_handshake_decision,
)

__all__ = [
    "enforce_capability_allowlist",
    "enforce_tool_allowlist",
    "MCP_RCE_26_04_DETAIL",
    "OX_PRIMARY_QUOTE",
    "is_vulnerable_sdk",
    "vulnerable_sdk_violation",
    "STDIO_DENIAL_REASON",
    "requires_extra_scrutiny",
    "stdio_pre_handshake_decision",
]
