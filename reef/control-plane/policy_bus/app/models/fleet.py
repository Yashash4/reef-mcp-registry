"""Fleet hierarchy models — fleet → region → site → node.

The fleet store seeds **49 nodes** (7 sites × 7 nodes per site, distributed
across 3 regions, all in `prod-fleet`) so the Stage UI can render its 7×7
stadium-wave demo grid without needing real-hardware nodes.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


# Ack status taxonomy. "kept_old_active" is the fail-safe path the Go client
# uses when a tampered bundle arrives — it kept the previous policy and
# notified the bus so the dashboard can highlight the rejection.
AckStatus = Literal[
    "applied",
    "verify_failed",
    "policy_parse_failed",
    "kept_old_active",
    "scope_mismatch",
    "unknown",
]


class NodeIdentity(BaseModel):
    """Address a single Lobster Trap node in the TerraFabric hierarchy."""

    model_config = ConfigDict(extra="forbid")

    fleet_id: str = Field(min_length=1, max_length=64)
    region_id: str = Field(min_length=1, max_length=64)
    site_id: str = Field(min_length=1, max_length=64)
    node_id: str = Field(min_length=1, max_length=64)
    svid_subject: str = ""

    def key(self) -> str:
        """Stable hash key for the in-memory fleet map."""
        return f"{self.fleet_id}/{self.region_id}/{self.site_id}/{self.node_id}"


class NodeRecord(BaseModel):
    """Persistent fleet-store entry for one node + its last-ack metadata."""

    model_config = ConfigDict(extra="forbid")

    identity: NodeIdentity
    # The version the node most recently acked as "applied" — the dashboard
    # paints the 7×7 grid based on whether this matches the latest broadcast.
    last_applied_version: str = ""
    last_applied_bundle_id: str = ""
    last_ack_status: AckStatus = "unknown"
    last_ack_detail: str = ""
    last_ack_unix: int = 0
    # last_subscribe_unix is the most recent Subscribe stream open (renewed
    # heartbeats refresh this — the dashboard uses it for "node is alive").
    last_subscribe_unix: int = 0
    # online tracks whether a Subscribe stream is currently live for this
    # node. Updated by the gRPC service on stream open + close.
    online: bool = False


class FleetSnapshot(BaseModel):
    """Snapshot of the fleet for the Stage UI dashboard."""

    model_config = ConfigDict(extra="forbid")

    fleet_id: str
    region_count: int
    site_count: int
    node_count: int
    nodes: list[NodeRecord]
