"""Bundle record models — pydantic shape for storage + admin REST.

A BundleRecord is the persistent shape of a SignedBundle. We deliberately
store both the raw `bundle_yaml` bytes and the `signature` bytes so the bus
can re-broadcast on Subscribe reconnect without needing the signer present.
"""

from __future__ import annotations

import base64
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


BundleStatus = Literal["active", "expired", "superseded", "rejected"]


class BundleScope(BaseModel):
    """TerraFabric scope filter. Empty fields are wildcards."""

    model_config = ConfigDict(extra="forbid")

    fleet_id: str = ""
    region_id: str = ""
    site_id: str = ""
    node_id: str = ""

    def matches(self, identity: "NodeIdentityShape") -> bool:
        """Return True if `identity` falls under this scope.

        Empty scope fields wildcard at their hierarchy level. A non-empty
        scope field must equal the identity's value exactly (case sensitive
        on purpose; fleet/region/site/node ids are operator-controlled
        opaque strings).
        """
        if self.fleet_id and self.fleet_id != identity.fleet_id:
            return False
        if self.region_id and self.region_id != identity.region_id:
            return False
        if self.site_id and self.site_id != identity.site_id:
            return False
        if self.node_id and self.node_id != identity.node_id:
            return False
        return True


# Forward declaration shim so BundleScope.matches can annotate against
# NodeIdentity without importing fleet.py (which would create a cycle).
class NodeIdentityShape(BaseModel):
    fleet_id: str
    region_id: str
    site_id: str
    node_id: str
    svid_subject: str = ""


class BundleRecord(BaseModel):
    """Persistent representation of a signed policy bundle."""

    model_config = ConfigDict(extra="forbid")

    bundle_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    scope: BundleScope = Field(default_factory=BundleScope)

    # bundle_yaml + signature stored as base64 for JSON-friendly persistence.
    # The gRPC layer converts back to bytes via the b64 helpers below.
    bundle_yaml_b64: str
    signature_b64: str
    signer_key_id: str = Field(min_length=1, max_length=128)

    published_at_unix: int
    expires_at_unix: int = 0  # 0 = never expires
    status: BundleStatus = "active"

    # Tracking metadata.
    recipients_targeted: int = 0
    recipients_applied: int = 0
    recipients_failed: int = 0

    @field_validator("bundle_yaml_b64", "signature_b64")
    @classmethod
    def _validate_b64(cls, v: str) -> str:
        if not v:
            raise ValueError("base64 field cannot be empty")
        # Round-trip to catch malformed payloads at construct time.
        try:
            base64.b64decode(v, validate=True)
        except (ValueError, base64.binascii.Error) as e:  # type: ignore[attr-defined]
            raise ValueError(f"invalid base64 payload: {e}") from e
        return v

    @property
    def bundle_yaml(self) -> bytes:
        return base64.b64decode(self.bundle_yaml_b64)

    @property
    def signature(self) -> bytes:
        return base64.b64decode(self.signature_b64)

    @classmethod
    def from_raw(
        cls,
        *,
        bundle_id: str,
        version: str,
        scope: BundleScope,
        bundle_yaml: bytes,
        signature: bytes,
        signer_key_id: str,
        published_at_unix: int | None = None,
        expires_at_unix: int = 0,
    ) -> "BundleRecord":
        return cls(
            bundle_id=bundle_id,
            version=version,
            scope=scope,
            bundle_yaml_b64=base64.b64encode(bundle_yaml).decode("ascii"),
            signature_b64=base64.b64encode(signature).decode("ascii"),
            signer_key_id=signer_key_id,
            published_at_unix=published_at_unix or int(time.time()),
            expires_at_unix=expires_at_unix,
        )

    def is_expired(self, now_unix: int | None = None) -> bool:
        if self.expires_at_unix == 0:
            return False
        now = now_unix or int(time.time())
        return now >= self.expires_at_unix


class PublishOutcome(BaseModel):
    """Result of a Publish operation, surfaced via gRPC + REST."""

    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    audit_id: str
    fleet_recipient_count: int
    accepted: bool
    reason: str = ""
