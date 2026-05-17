"""Publisher (signing-key) records."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Publisher(BaseModel):
    """A trusted publisher of MCP manifests.

    `public_key_hex` is the ed25519 raw public key (32 bytes, hex-encoded).
    `scopes` constrains which `mcpName` prefixes this publisher may sign —
    e.g., a `com.example.*` publisher may not sign for `org.attacker.*`.
    """

    model_config = ConfigDict(extra="forbid")

    publisher_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=256)
    public_key_hex: str = Field(min_length=64, max_length=64)  # 32 bytes hex
    scopes: list[str] = Field(default_factory=list, max_length=32)
    created_at: str
    revoked: bool = False
    fingerprint: str  # short hex digest for log lines


class PublisherRegisterRequest(BaseModel):
    """POST /publishers body (admin-only in production; demo seeds at boot)."""

    model_config = ConfigDict(extra="forbid")

    publisher_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=256)
    public_key_hex: str = Field(min_length=64, max_length=64)
    scopes: list[str] = Field(default_factory=list, max_length=32)
