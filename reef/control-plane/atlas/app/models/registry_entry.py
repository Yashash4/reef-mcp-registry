"""A single signed registry entry, as persisted by the file store."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.manifest import Manifest

RegistryStatus = Literal["verified", "quarantined", "poisoned"]


class RegistryEntry(BaseModel):
    """A persisted registry entry.

    `signature_hex` is the ed25519 signature over canonical-JSON(manifest),
    using the publisher's private key. The verifier re-derives canonical-JSON
    at verify time and checks the signature against the publisher's public
    key; mismatch => `decision: deny`.
    """

    model_config = ConfigDict(extra="forbid")

    registry_id: str = Field(min_length=1, max_length=128)
    manifest: Manifest
    publisher_id: str
    signature_hex: str = Field(min_length=2, max_length=256)
    status: RegistryStatus
    registered_at: str
    quarantined_reason: str | None = None
    poisoned_reason: str | None = None
    checks_passed: list[str] = Field(default_factory=list)
    checks_failed: list[str] = Field(default_factory=list)
