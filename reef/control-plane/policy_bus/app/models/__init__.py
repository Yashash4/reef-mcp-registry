"""Pydantic models for the Reef Policy Bus.

The gRPC wire types live in `app.gen.policy_bus_pb2`. These pydantic models
are the **internal** representations the bus uses for storage + REST admin
endpoints. They convert to/from the protobuf shapes via the helpers in
`app.models.bundle` and `app.models.fleet`.
"""

from app.models.bundle import (
    BundleRecord,
    BundleScope,
    BundleStatus,
    PublishOutcome,
)
from app.models.fleet import (
    NodeRecord,
    NodeIdentity,
    AckStatus,
    FleetSnapshot,
)

__all__ = [
    "BundleRecord",
    "BundleScope",
    "BundleStatus",
    "PublishOutcome",
    "NodeRecord",
    "NodeIdentity",
    "AckStatus",
    "FleetSnapshot",
]
