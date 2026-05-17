"""Pydantic models for the MCP signature registry wire protocol.

The shapes here are anchored to `docs/24-GROUNDING.md` Part 2 (Anthropic MCP
spec verified live 2026-05-18). The `protocolVersion` default `"2025-06-18"`
mirrors the verified MCP spec wire format; `transports` reflects the two
transport mechanisms the spec describes (`stdio`, `http`).
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Transport = Literal["stdio", "http"]
Decision = Literal["allow", "deny", "review"]

# MCP servers are identified by reverse-DNS `mcpName` (see Part 2, package.json
# example: `io.github.modelcontextprotocol/server-filesystem`). We validate
# loosely — the registry primary-keys on this field so it must be non-empty,
# lowercase, and look like reverse-DNS, but we don't pin a strict regex
# because real registries see edge cases (uppercase package names,
# org-prefixed subdomains).
MCP_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]*(\.[a-z0-9][a-z0-9._\-]*)+(/[A-Za-z0-9._\-]+)?$")

# `stdio_entrypoint_hash` is a `sha256:<64-hex>` string. Anything else is
# rejected at register time — the centerpiece capability depends on this.
STDIO_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class Tool(BaseModel):
    """One tool a server advertises in its `tools/list` response."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=2048)


class Manifest(BaseModel):
    """An MCP server manifest. This is what publishers sign.

    All fields here become part of the canonical-JSON over which the publisher
    ed25519 signature is computed. Changing any field invalidates the
    signature.
    """

    model_config = ConfigDict(extra="forbid")

    mcpName: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=64)
    protocolVersion: str = Field(default="2025-06-18", min_length=1, max_length=32)
    transports: list[Transport] = Field(min_length=1, max_length=2)
    tools: list[Tool] = Field(default_factory=list, max_length=64)
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    stdio_entrypoint_hash: str | None = None
    sdk_version: str = Field(min_length=1, max_length=128)

    @field_validator("mcpName")
    @classmethod
    def _validate_mcp_name(cls, v: str) -> str:
        normalized = v.strip().lower()
        if not MCP_NAME_RE.match(normalized):
            raise ValueError(
                f"mcpName must be reverse-DNS (e.g. 'io.github.modelcontextprotocol/server-filesystem'); got {v!r}"
            )
        return normalized

    @field_validator("stdio_entrypoint_hash")
    @classmethod
    def _validate_entrypoint_hash(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not STDIO_HASH_RE.match(v):
            raise ValueError(
                "stdio_entrypoint_hash must be 'sha256:<64-hex>'; got " + repr(v)
            )
        return v

    @field_validator("transports")
    @classmethod
    def _dedup_transports(cls, v: list[str]) -> list[str]:
        # preserve order, but eliminate duplicates
        seen: set[str] = set()
        out: list[str] = []
        for t in v:
            if t in seen:
                continue
            seen.add(t)
            out.append(t)
        return out

    def has_stdio(self) -> bool:
        return "stdio" in self.transports


class RegisterRequest(BaseModel):
    """POST /register body."""

    model_config = ConfigDict(extra="forbid")

    manifest: Manifest
    publisher_id: str = Field(min_length=1, max_length=128)
    signature: str = Field(
        min_length=2,
        max_length=256,
        description="hex-encoded ed25519 signature over canonical-JSON(manifest)",
    )


class RegisterResponse(BaseModel):
    """POST /register response body."""

    model_config = ConfigDict(extra="forbid")

    registry_id: str
    registered_at: str  # ISO-8601 UTC
    status: str  # "verified" | "quarantined" | "poisoned"
    checks_passed: list[str]
    checks_failed: list[str]
    audit_id: str


class VerifyRequest(BaseModel):
    """POST /verify body (called by the Go sidecar at handshake time)."""

    model_config = ConfigDict(extra="forbid")

    mcpName: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=64)
    transport: Transport
    claimed_signature: str | None = Field(default=None, max_length=256)
    agent_id: str | None = Field(default=None, max_length=256)
    request_id: str | None = Field(default=None, max_length=128)
    claimed_entrypoint_hash: str | None = None
    claimed_sdk_version: str | None = None
    claimed_tools: list[str] | None = None

    @field_validator("mcpName")
    @classmethod
    def _normalize_name(cls, v: str) -> str:
        return v.strip().lower()


class Violation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    detail: str


class VerifyResponse(BaseModel):
    """POST /verify response body."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision
    reason: str
    registry_id: str | None = None
    matched_capabilities: list[str] = Field(default_factory=list)
    violations: list[Violation] = Field(default_factory=list)
    audit_id: str
