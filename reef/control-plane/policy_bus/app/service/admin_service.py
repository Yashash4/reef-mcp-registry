"""FastAPI admin surface wrapping the gRPC PolicyBus service.

Why both REST and gRPC?
  - The Go Lobster Trap nodes speak gRPC (long-lived streams).
  - The Stage UI dashboard + curl-style operator workflows speak HTTP/JSON.

The REST handlers are thin wrappers that call back into the same
ServiceState. They share the publisher allowlist + admin token with the
gRPC layer.
"""

from __future__ import annotations

import base64
import logging
import time
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from app.audit import AuditLogger
from app.crypto import (
    BundleVerifier,
    BundleVerifyError,
    SignatureMismatch,
    UnknownPublisher,
)
from app.models.bundle import BundleRecord, BundleScope, PublishOutcome
from app.models.fleet import FleetSnapshot
from app.service.bus_service import ServiceState


logger = logging.getLogger("policy_bus.admin")


class PublishBody(BaseModel):
    """REST shape for the Publish endpoint.

    `bundle_yaml` + `signature` MUST be base64. JSON cannot carry raw bytes;
    the gRPC layer handles bytes natively but the REST layer normalises.
    """

    model_config = ConfigDict(extra="forbid")

    bundle_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    scope_fleet_id: str = ""
    scope_region_id: str = ""
    scope_site_id: str = ""
    scope_node_id: str = ""
    bundle_yaml_b64: str
    signature_b64: str
    signer_key_id: str
    expires_at_unix: int = 0


class PublishersAddBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(min_length=1, max_length=128)
    public_key_b64: str


class HealthzResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    active_subscribers: int
    active_bundles: int
    fleet_node_count: int


def _check_admin(
    state: ServiceState,
    token_header: str | None,
) -> None:
    import secrets

    if not token_header or not secrets.compare_digest(token_header, state.admin_token):
        raise HTTPException(status_code=401, detail="admin_token mismatch")


def build_admin_app(state: ServiceState) -> FastAPI:
    """Build the FastAPI app for the admin REST surface."""

    app = FastAPI(
        title="Reef Policy Bus — admin",
        version="0.1.0",
        description=(
            "Admin REST surface. Authenticates via the X-Admin-Token header "
            "against REEF_POLICY_BUS_ADMIN_TOKEN. The gRPC service is the "
            "primary contract; this REST layer exists for curl-style demos "
            "and the Stage UI's fleet snapshot fetch."
        ),
    )

    # Stash the state on app.state for inspection / tests.
    app.state.bus_state = state

    def get_state() -> ServiceState:
        return state

    @app.get("/healthz", response_model=HealthzResponse)
    async def healthz(s: ServiceState = Depends(get_state)) -> HealthzResponse:
        return HealthzResponse(
            status="ok",
            active_subscribers=s.active_subscribers,
            active_bundles=s.bundle_store.count(),
            fleet_node_count=s.fleet_store.count(),
        )

    @app.get("/fleet", response_model=FleetSnapshot)
    async def fleet(
        fleet_id: str | None = None,
        s: ServiceState = Depends(get_state),
    ) -> FleetSnapshot:
        return s.fleet_store.snapshot(fleet_id)

    @app.get("/bundles")
    async def list_bundles(s: ServiceState = Depends(get_state)) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for rec in s.bundle_store.all():
            d = rec.model_dump(mode="json")
            # Hide the raw bundle bytes from the list response — they're
            # large + irrelevant for the dashboard.
            d.pop("bundle_yaml_b64", None)
            d.pop("signature_b64", None)
            out.append(d)
        return out

    @app.get("/publishers")
    async def list_publishers(s: ServiceState = Depends(get_state)) -> list[dict[str, str]]:
        return [
            {
                "key_id": kid,
                "fingerprint": s.verifier.allowlist.get(kid).fingerprint,  # type: ignore[union-attr]
                "source_path": s.verifier.allowlist.get(kid).source_path,  # type: ignore[union-attr]
            }
            for kid in s.verifier.allowlist.list_key_ids()
        ]

    @app.post("/publishers", status_code=201)
    async def add_publisher(
        body: PublishersAddBody,
        x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
        s: ServiceState = Depends(get_state),
    ) -> dict[str, str]:
        _check_admin(s, x_admin_token)
        try:
            pub = s.verifier.allowlist.add(body.key_id, body.public_key_b64)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        audit_id = s.audit.log(
            {
                "kind": "publisher",
                "event": "added",
                "key_id": pub.key_id,
                "fingerprint": pub.fingerprint,
            }
        )
        return {
            "key_id": pub.key_id,
            "fingerprint": pub.fingerprint,
            "audit_id": audit_id,
        }

    @app.post("/publish", response_model=PublishOutcome)
    async def publish(
        body: PublishBody,
        x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
        s: ServiceState = Depends(get_state),
    ) -> PublishOutcome:
        _check_admin(s, x_admin_token)
        try:
            bundle_yaml = base64.b64decode(body.bundle_yaml_b64, validate=True)
            signature = base64.b64decode(body.signature_b64, validate=True)
        except (ValueError, base64.binascii.Error) as e:  # type: ignore[attr-defined]
            raise HTTPException(
                status_code=400, detail=f"base64 decode failed: {e}"
            ) from e

        # Verify against allowlist.
        try:
            publisher = s.verifier.verify(
                signer_key_id=body.signer_key_id,
                bundle_yaml=bundle_yaml,
                signature=signature,
            )
        except UnknownPublisher as e:
            audit_id = s.audit.log(
                {
                    "kind": "publish",
                    "event": "rejected",
                    "reason": f"unknown publisher: {e}",
                    "bundle_id": body.bundle_id,
                    "signer_key_id": body.signer_key_id,
                }
            )
            return PublishOutcome(
                bundle_id=body.bundle_id,
                audit_id=audit_id,
                fleet_recipient_count=0,
                accepted=False,
                reason=f"unknown publisher: {e}",
            )
        except SignatureMismatch as e:
            audit_id = s.audit.log(
                {
                    "kind": "publish",
                    "event": "rejected",
                    "reason": f"signature mismatch: {e}",
                    "bundle_id": body.bundle_id,
                    "signer_key_id": body.signer_key_id,
                }
            )
            return PublishOutcome(
                bundle_id=body.bundle_id,
                audit_id=audit_id,
                fleet_recipient_count=0,
                accepted=False,
                reason=f"signature mismatch: {e}",
            )
        except BundleVerifyError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

        rec = BundleRecord.from_raw(
            bundle_id=body.bundle_id,
            version=body.version,
            scope=BundleScope(
                fleet_id=body.scope_fleet_id,
                region_id=body.scope_region_id,
                site_id=body.scope_site_id,
                node_id=body.scope_node_id,
            ),
            bundle_yaml=bundle_yaml,
            signature=signature,
            signer_key_id=body.signer_key_id,
            published_at_unix=int(time.time()),
            expires_at_unix=body.expires_at_unix,
        )
        await s.bundle_store.add(rec)

        recipient_count = 0
        for node in s.fleet_store.all():
            if not node.online:
                continue
            if rec.scope.matches(node.identity):
                recipient_count += 1

        audit_id = s.audit.log(
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
        return PublishOutcome(
            bundle_id=rec.bundle_id,
            audit_id=audit_id,
            fleet_recipient_count=recipient_count,
            accepted=True,
            reason="",
        )

    @app.get("/audit/tail")
    async def audit_tail(
        n: int = 50,
        x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
        s: ServiceState = Depends(get_state),
    ) -> list[dict[str, Any]]:
        _check_admin(s, x_admin_token)
        return s.audit.tail(n)

    return app
