"""gRPC PolicyBus service implementation.

Implements four RPCs:

  - Subscribe — server-streaming. Long-lived: pushes any matching bundle
    plus heartbeats. Closes cleanly on context cancel.
  - Ack       — unary. Records node's apply outcome.
  - Publish   — unary. Admin pushes a new signed bundle.
  - Healthz   — unary. Lightweight liveness probe.

The implementation is asyncio-native (grpc.aio).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import AsyncIterator

import grpc

from app.audit import AuditLogger
from app.crypto import (
    BundleVerifier,
    BundleVerifyError,
    SignatureMismatch,
    UnknownPublisher,
)
from app.gen import policy_bus_pb2, policy_bus_pb2_grpc
from app.models.bundle import BundleRecord, BundleScope
from app.models.fleet import NodeIdentity
from app.store import BundleStore, FleetStore


logger = logging.getLogger("policy_bus.service")


# Heartbeat cadence on the Subscribe stream. Short enough that the Go client
# can detect a dead stream within ~30s; long enough that the bus doesn't
# generate gratuitous traffic.
HEARTBEAT_INTERVAL_SECONDS = 15.0


@dataclass
class ServiceState:
    """All the shared dependencies the bus service hangs onto."""

    bundle_store: BundleStore
    fleet_store: FleetStore
    verifier: BundleVerifier
    audit: AuditLogger
    admin_token: str
    # active_subscribers tracks how many Subscribe streams are currently
    # open. The Healthz RPC reads this.
    active_subscribers: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


def _identity_from_pb(pb: policy_bus_pb2.NodeIdentity) -> NodeIdentity:
    return NodeIdentity(
        fleet_id=pb.fleet_id,
        region_id=pb.region_id,
        site_id=pb.site_id,
        node_id=pb.node_id,
        svid_subject=pb.svid_subject,
    )


def _bundle_to_pb(rec: BundleRecord, is_heartbeat: bool = False) -> policy_bus_pb2.SignedBundle:
    return policy_bus_pb2.SignedBundle(
        bundle_id=rec.bundle_id,
        version=rec.version,
        scope_fleet_id=rec.scope.fleet_id,
        scope_region_id=rec.scope.region_id,
        scope_site_id=rec.scope.site_id,
        scope_node_id=rec.scope.node_id,
        bundle_yaml=rec.bundle_yaml,
        signature=rec.signature,
        signer_key_id=rec.signer_key_id,
        published_at_unix=rec.published_at_unix,
        expires_at_unix=rec.expires_at_unix,
        is_heartbeat=is_heartbeat,
    )


class PolicyBusService(policy_bus_pb2_grpc.PolicyBusServicer):
    """gRPC PolicyBus servicer.

    Pure-asyncio. All long-lived state lives in `ServiceState`.
    """

    def __init__(self, state: ServiceState) -> None:
        self._state = state

    @property
    def state(self) -> ServiceState:
        return self._state

    # ------------------------------------------------------------------
    # Subscribe — server-streaming
    # ------------------------------------------------------------------

    async def Subscribe(
        self,
        request: policy_bus_pb2.SubscribeRequest,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[policy_bus_pb2.SignedBundle]:
        # Validate identity at the protobuf layer first — empty fields are
        # rejected with INVALID_ARGUMENT before we try to materialise the
        # pydantic model (which would otherwise raise ValidationError and
        # bubble out as StatusCode.UNKNOWN).
        node_pb = request.node
        missing = [
            name
            for name, val in (
                ("fleet_id", node_pb.fleet_id),
                ("region_id", node_pb.region_id),
                ("site_id", node_pb.site_id),
                ("node_id", node_pb.node_id),
            )
            if not val
        ]
        if missing:
            msg = f"NodeIdentity missing fields: {', '.join(missing)}"
            audit_id = self._state.audit.log(
                {
                    "kind": "subscribe",
                    "event": "rejected",
                    "reason": msg,
                    "node_pb": {
                        "fleet_id": node_pb.fleet_id,
                        "region_id": node_pb.region_id,
                        "site_id": node_pb.site_id,
                        "node_id": node_pb.node_id,
                        "svid_subject": node_pb.svid_subject,
                    },
                }
            )
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"{msg} (audit={audit_id})",
            )
            return
        identity = _identity_from_pb(node_pb)

        # Register the node in the fleet store + bump subscriber counter.
        await self._state.fleet_store.mark_subscribed(identity)
        async with self._state.lock:
            self._state.active_subscribers += 1
        audit_id = self._state.audit.log(
            {
                "kind": "subscribe",
                "event": "opened",
                "node": identity.model_dump(),
                "current_version": request.current_policy_version,
            }
        )
        logger.info(
            "subscribe opened: %s (current_version=%r, audit=%s)",
            identity.key(),
            request.current_policy_version,
            audit_id,
        )

        try:
            # 1) Initial backfill — push every currently-applicable bundle
            #    so a freshly-booted node converges to the latest state.
            current_version = request.current_policy_version
            for rec in self._state.bundle_store.applicable_for(identity, current_version):
                yield _bundle_to_pb(rec)
                self._state.bundle_store.increment_recipient_targeted(rec.bundle_id)
                current_version = rec.version

            # 2) Steady-state — wait for new bundles or heartbeat tick.
            last_heartbeat = time.monotonic()
            while True:
                if context.cancelled():
                    break
                event = self._state.bundle_store.wait_event()
                # asyncio.wait_for raises TimeoutError when the heartbeat
                # cadence elapses with no new bundle.
                try:
                    await asyncio.wait_for(
                        event.wait(),
                        timeout=HEARTBEAT_INTERVAL_SECONDS,
                    )
                except asyncio.TimeoutError:
                    # Heartbeat frame keeps the connection alive.
                    yield policy_bus_pb2.SignedBundle(
                        bundle_id="heartbeat",
                        version="",
                        is_heartbeat=True,
                        published_at_unix=int(time.time()),
                    )
                    last_heartbeat = time.monotonic()
                    continue

                # New bundle arrived — push any applicable to this node.
                for rec in self._state.bundle_store.applicable_for(identity, current_version):
                    if context.cancelled():
                        return
                    yield _bundle_to_pb(rec)
                    self._state.bundle_store.increment_recipient_targeted(rec.bundle_id)
                    current_version = rec.version

                # Heartbeat insurance: if it's been > HEARTBEAT_INTERVAL
                # since the last frame, send one even after a bundle.
                if time.monotonic() - last_heartbeat > HEARTBEAT_INTERVAL_SECONDS:
                    last_heartbeat = time.monotonic()
        finally:
            await self._state.fleet_store.mark_disconnected(identity)
            async with self._state.lock:
                self._state.active_subscribers = max(0, self._state.active_subscribers - 1)
            self._state.audit.log(
                {
                    "kind": "subscribe",
                    "event": "closed",
                    "node": identity.model_dump(),
                }
            )

    # ------------------------------------------------------------------
    # Ack — unary
    # ------------------------------------------------------------------

    async def Ack(
        self,
        request: policy_bus_pb2.AckRequest,
        context: grpc.aio.ServicerContext,
    ) -> policy_bus_pb2.AckResponse:
        identity = _identity_from_pb(request.node)
        status = request.ack_status or "unknown"
        # Pydantic literal validation will catch unknown statuses; map to
        # the wider sentinel rather than rejecting outright (we want acks
        # to land even if the wire enum drifts).
        from typing import get_args
        from app.models.fleet import AckStatus as AckLit

        allowed = set(get_args(AckLit))
        normalized: str = status if status in allowed else "unknown"
        await self._state.fleet_store.record_ack(
            identity,
            bundle_id=request.bundle_id,
            applied_version=request.applied_version,
            status=normalized,  # type: ignore[arg-type]
            detail=request.detail,
        )
        if normalized == "applied":
            self._state.bundle_store.increment_recipient_applied(request.bundle_id)
        elif normalized in ("verify_failed", "policy_parse_failed", "kept_old_active"):
            self._state.bundle_store.increment_recipient_failed(request.bundle_id)
        audit_id = self._state.audit.log(
            {
                "kind": "ack",
                "node": identity.model_dump(),
                "bundle_id": request.bundle_id,
                "applied_version": request.applied_version,
                "ack_status": normalized,
                "detail": request.detail,
            }
        )
        return policy_bus_pb2.AckResponse(audit_id=audit_id)

    # ------------------------------------------------------------------
    # Publish — unary
    # ------------------------------------------------------------------

    async def Publish(
        self,
        request: policy_bus_pb2.PublishRequest,
        context: grpc.aio.ServicerContext,
    ) -> policy_bus_pb2.PublishResponse:
        # 1) Admin auth.
        if not request.admin_token or not secrets.compare_digest(
            request.admin_token, self._state.admin_token
        ):
            audit_id = self._state.audit.log(
                {
                    "kind": "publish",
                    "event": "rejected",
                    "reason": "admin_token mismatch",
                }
            )
            await context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                f"admin_token mismatch (audit={audit_id})",
            )
            return policy_bus_pb2.PublishResponse(audit_id=audit_id)

        b = request.bundle
        if not b.bundle_id or not b.version:
            audit_id = self._state.audit.log(
                {
                    "kind": "publish",
                    "event": "rejected",
                    "reason": "bundle_id/version required",
                }
            )
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"bundle_id and version are required (audit={audit_id})",
            )
            return policy_bus_pb2.PublishResponse(audit_id=audit_id)

        # 2) Signature verify against publisher allowlist.
        try:
            publisher = self._state.verifier.verify(
                signer_key_id=b.signer_key_id,
                bundle_yaml=bytes(b.bundle_yaml),
                signature=bytes(b.signature),
            )
        except UnknownPublisher as e:
            audit_id = self._state.audit.log(
                {
                    "kind": "publish",
                    "event": "rejected",
                    "reason": f"unknown publisher: {e}",
                    "bundle_id": b.bundle_id,
                    "signer_key_id": b.signer_key_id,
                }
            )
            await context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                f"unknown publisher: {e} (audit={audit_id})",
            )
            return policy_bus_pb2.PublishResponse(audit_id=audit_id)
        except SignatureMismatch as e:
            audit_id = self._state.audit.log(
                {
                    "kind": "publish",
                    "event": "rejected",
                    "reason": f"signature mismatch: {e}",
                    "bundle_id": b.bundle_id,
                    "signer_key_id": b.signer_key_id,
                }
            )
            await context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                f"signature mismatch: {e} (audit={audit_id})",
            )
            return policy_bus_pb2.PublishResponse(audit_id=audit_id)
        except BundleVerifyError as e:
            audit_id = self._state.audit.log(
                {
                    "kind": "publish",
                    "event": "rejected",
                    "reason": f"verify error: {e}",
                    "bundle_id": b.bundle_id,
                }
            )
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"verify error: {e} (audit={audit_id})",
            )
            return policy_bus_pb2.PublishResponse(audit_id=audit_id)

        # 3) Persist + fan out.
        rec = BundleRecord.from_raw(
            bundle_id=b.bundle_id,
            version=b.version,
            scope=BundleScope(
                fleet_id=b.scope_fleet_id,
                region_id=b.scope_region_id,
                site_id=b.scope_site_id,
                node_id=b.scope_node_id,
            ),
            bundle_yaml=bytes(b.bundle_yaml),
            signature=bytes(b.signature),
            signer_key_id=b.signer_key_id,
            published_at_unix=b.published_at_unix or int(time.time()),
            expires_at_unix=b.expires_at_unix,
        )
        await self._state.bundle_store.add(rec)

        # 4) Count current subscribers whose scope matches this bundle so
        #    the admin sees the expected propagation fan-out.
        recipient_count = 0
        for node in self._state.fleet_store.all():
            if not node.online:
                continue
            if rec.scope.matches(node.identity):
                recipient_count += 1

        audit_id = self._state.audit.log(
            {
                "kind": "publish",
                "event": "accepted",
                "bundle_id": rec.bundle_id,
                "version": rec.version,
                "signer_key_id": publisher.key_id,
                "signer_fingerprint": publisher.fingerprint,
                "scope": rec.scope.model_dump(),
                "fleet_recipient_count": recipient_count,
            }
        )
        logger.info(
            "publish accepted: %s v=%s scope=%s recipients=%d (audit=%s)",
            rec.bundle_id,
            rec.version,
            rec.scope.model_dump(),
            recipient_count,
            audit_id,
        )
        return policy_bus_pb2.PublishResponse(
            bundle_id=rec.bundle_id,
            fleet_recipient_count=recipient_count,
            audit_id=audit_id,
        )

    # ------------------------------------------------------------------
    # Healthz — unary
    # ------------------------------------------------------------------

    async def Healthz(
        self,
        request: policy_bus_pb2.HealthzRequest,
        context: grpc.aio.ServicerContext,
    ) -> policy_bus_pb2.HealthzResponse:
        return policy_bus_pb2.HealthzResponse(
            status="ok",
            active_subscribers=self._state.active_subscribers,
            active_bundles=self._state.bundle_store.count(),
        )
