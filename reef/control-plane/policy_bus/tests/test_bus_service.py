"""Tests for the gRPC PolicyBus service via grpc.aio in-process server.

We bind to 127.0.0.1:0 and let the OS pick a free port. The async client +
server share the same event loop.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from pathlib import Path
from typing import AsyncIterator

import grpc
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.gen import policy_bus_pb2, policy_bus_pb2_grpc
from app.service.bus_service import PolicyBusService, ServiceState


def _sign(priv: Ed25519PrivateKey, payload: bytes) -> bytes:
    digest = hashlib.sha256(payload).digest()
    return priv.sign(digest)


async def _serve(state: ServiceState) -> tuple[grpc.aio.Server, str]:
    server = grpc.aio.server()
    policy_bus_pb2_grpc.add_PolicyBusServicer_to_server(PolicyBusService(state), server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    return server, f"127.0.0.1:{port}"


def _make_identity(node_idx: int = 1) -> policy_bus_pb2.NodeIdentity:
    return policy_bus_pb2.NodeIdentity(
        fleet_id="prod-fleet",
        region_id="us-east",
        site_id="site-01",
        node_id=f"node-01-{node_idx:02d}",
        svid_subject=f"spiffe://reef/prod-fleet/us-east/site-01/node-01-{node_idx:02d}",
    )


@pytest.mark.asyncio
async def test_healthz(service_state: ServiceState) -> None:
    server, addr = await _serve(service_state)
    try:
        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)
            resp = await stub.Healthz(policy_bus_pb2.HealthzRequest())
            assert resp.status == "ok"
            assert resp.active_subscribers == 0
            assert resp.active_bundles == 0
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_publish_rejects_bad_admin_token(service_state: ServiceState) -> None:
    server, addr = await _serve(service_state)
    try:
        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)
            req = policy_bus_pb2.PublishRequest(
                bundle=policy_bus_pb2.SignedBundle(
                    bundle_id="b1", version="v1", bundle_yaml=b"y", signature=b"s",
                ),
                admin_token="WRONG",
            )
            with pytest.raises(grpc.aio.AioRpcError) as ei:
                await stub.Publish(req)
            assert ei.value.code() == grpc.StatusCode.UNAUTHENTICATED
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_publish_rejects_unknown_publisher(
    service_state: ServiceState,
    attacker_keypair: Ed25519PrivateKey,
) -> None:
    server, addr = await _serve(service_state)
    try:
        yaml = b"version: '1.0'\n"
        sig = _sign(attacker_keypair, yaml)
        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)
            req = policy_bus_pb2.PublishRequest(
                bundle=policy_bus_pb2.SignedBundle(
                    bundle_id="b1",
                    version="v1",
                    bundle_yaml=yaml,
                    signature=sig,
                    signer_key_id="unknown-publisher",
                    published_at_unix=int(time.time()),
                ),
                admin_token=service_state.admin_token,
            )
            with pytest.raises(grpc.aio.AioRpcError) as ei:
                await stub.Publish(req)
            assert ei.value.code() == grpc.StatusCode.PERMISSION_DENIED
            assert "unknown publisher" in ei.value.details()
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_publish_rejects_tampered_bundle(
    service_state: ServiceState,
    signer_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    """A bundle signed over one body but submitted with a different body
    must be rejected as PERMISSION_DENIED with 'signature mismatch'."""
    priv, key_id = signer_keypair
    server, addr = await _serve(service_state)
    try:
        original_yaml = b"original yaml"
        sig = _sign(priv, original_yaml)
        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)
            req = policy_bus_pb2.PublishRequest(
                bundle=policy_bus_pb2.SignedBundle(
                    bundle_id="b1",
                    version="v1",
                    bundle_yaml=b"TAMPERED yaml",  # not what was signed
                    signature=sig,
                    signer_key_id=key_id,
                    published_at_unix=int(time.time()),
                ),
                admin_token=service_state.admin_token,
            )
            with pytest.raises(grpc.aio.AioRpcError) as ei:
                await stub.Publish(req)
            assert ei.value.code() == grpc.StatusCode.PERMISSION_DENIED
            assert "signature mismatch" in ei.value.details()
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_publish_accepts_signed_bundle(
    service_state: ServiceState,
    signer_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    priv, key_id = signer_keypair
    server, addr = await _serve(service_state)
    try:
        yaml = b"version: '1.0'\npolicy_name: 'demo'\n"
        sig = _sign(priv, yaml)
        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)
            req = policy_bus_pb2.PublishRequest(
                bundle=policy_bus_pb2.SignedBundle(
                    bundle_id="b1",
                    version="v1",
                    scope_fleet_id="prod-fleet",
                    bundle_yaml=yaml,
                    signature=sig,
                    signer_key_id=key_id,
                    published_at_unix=int(time.time()),
                ),
                admin_token=service_state.admin_token,
            )
            resp = await stub.Publish(req)
            assert resp.bundle_id == "b1"
            assert resp.audit_id.startswith("audit-")
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_subscribe_requires_full_identity(
    service_state: ServiceState,
) -> None:
    server, addr = await _serve(service_state)
    try:
        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)
            req = policy_bus_pb2.SubscribeRequest(
                node=policy_bus_pb2.NodeIdentity(fleet_id="prod-fleet"),
                current_policy_version="",
            )
            with pytest.raises(grpc.aio.AioRpcError) as ei:
                async for _msg in stub.Subscribe(req):
                    pass
            assert ei.value.code() == grpc.StatusCode.INVALID_ARGUMENT
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_subscribe_delivers_existing_bundle(
    service_state: ServiceState,
    signer_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    """A node subscribing AFTER a publish should immediately receive the
    bundle as part of the initial backfill."""
    priv, key_id = signer_keypair
    server, addr = await _serve(service_state)
    try:
        yaml = b"existing-bundle-yaml"
        sig = _sign(priv, yaml)
        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)

            # Publish first.
            pub_resp = await stub.Publish(
                policy_bus_pb2.PublishRequest(
                    bundle=policy_bus_pb2.SignedBundle(
                        bundle_id="b1",
                        version="v1",
                        scope_fleet_id="prod-fleet",
                        bundle_yaml=yaml,
                        signature=sig,
                        signer_key_id=key_id,
                        published_at_unix=int(time.time()),
                    ),
                    admin_token=service_state.admin_token,
                )
            )
            assert pub_resp.bundle_id == "b1"

            # Subscribe — expect the bundle to come through.
            sub_req = policy_bus_pb2.SubscribeRequest(
                node=_make_identity(1),
                current_policy_version="",
            )
            received: list[policy_bus_pb2.SignedBundle] = []
            call = stub.Subscribe(sub_req)
            try:
                async with asyncio.timeout(3.0):
                    async for msg in call:
                        if msg.is_heartbeat:
                            continue
                        received.append(msg)
                        if len(received) >= 1:
                            break
            finally:
                call.cancel()

            assert len(received) == 1
            assert received[0].bundle_id == "b1"
            assert received[0].version == "v1"
            assert bytes(received[0].bundle_yaml) == yaml
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_subscribe_delivers_post_publish_bundle(
    service_state: ServiceState,
    signer_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    """A node already subscribed should receive a bundle published AFTER
    subscription (the streaming-fan-out path)."""
    priv, key_id = signer_keypair
    server, addr = await _serve(service_state)
    try:
        yaml = b"post-publish-yaml"
        sig = _sign(priv, yaml)
        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)
            sub_req = policy_bus_pb2.SubscribeRequest(
                node=_make_identity(1),
                current_policy_version="",
            )
            call = stub.Subscribe(sub_req)

            async def _read_one():
                async for msg in call:
                    if msg.is_heartbeat:
                        continue
                    return msg
                return None

            reader = asyncio.create_task(_read_one())
            # Let the subscribe stream open.
            await asyncio.sleep(0.2)

            # Publish.
            await stub.Publish(
                policy_bus_pb2.PublishRequest(
                    bundle=policy_bus_pb2.SignedBundle(
                        bundle_id="b1",
                        version="v1",
                        scope_fleet_id="prod-fleet",
                        bundle_yaml=yaml,
                        signature=sig,
                        signer_key_id=key_id,
                        published_at_unix=int(time.time()),
                    ),
                    admin_token=service_state.admin_token,
                )
            )

            received = await asyncio.wait_for(reader, timeout=3.0)
            assert received is not None
            assert received.bundle_id == "b1"
            call.cancel()
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_subscribe_scope_mismatch_filters_out(
    service_state: ServiceState,
    signer_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    """A bundle scoped to us-east is NOT delivered to a us-west node."""
    priv, key_id = signer_keypair
    server, addr = await _serve(service_state)
    try:
        yaml = b"east-only"
        sig = _sign(priv, yaml)
        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)

            await stub.Publish(
                policy_bus_pb2.PublishRequest(
                    bundle=policy_bus_pb2.SignedBundle(
                        bundle_id="east-bundle",
                        version="v1",
                        scope_fleet_id="prod-fleet",
                        scope_region_id="us-east",
                        bundle_yaml=yaml,
                        signature=sig,
                        signer_key_id=key_id,
                        published_at_unix=int(time.time()),
                    ),
                    admin_token=service_state.admin_token,
                )
            )

            west_node = policy_bus_pb2.NodeIdentity(
                fleet_id="prod-fleet",
                region_id="us-west",
                site_id="site-04",
                node_id="node-04-01",
            )
            call = stub.Subscribe(
                policy_bus_pb2.SubscribeRequest(node=west_node)
            )
            bundles: list[policy_bus_pb2.SignedBundle] = []
            try:
                async with asyncio.timeout(1.0):
                    async for msg in call:
                        if msg.is_heartbeat:
                            continue
                        bundles.append(msg)
            except asyncio.TimeoutError:
                pass
            call.cancel()
            assert bundles == []
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_ack_records_into_fleet_store(
    service_state: ServiceState,
) -> None:
    server, addr = await _serve(service_state)
    try:
        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)
            ack = await stub.Ack(
                policy_bus_pb2.AckRequest(
                    node=_make_identity(2),
                    bundle_id="b1",
                    applied_version="v1",
                    ack_status="applied",
                    detail="OK",
                )
            )
            assert ack.audit_id.startswith("audit-")
        # Inspect the fleet store directly.
        from app.models.fleet import NodeIdentity

        rec = service_state.fleet_store.get(
            NodeIdentity(
                fleet_id="prod-fleet",
                region_id="us-east",
                site_id="site-01",
                node_id="node-01-02",
            )
        )
        assert rec is not None
        assert rec.last_applied_version == "v1"
        assert rec.last_ack_status == "applied"
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_ack_verify_failed_keeps_old_active(
    service_state: ServiceState,
) -> None:
    """The 3-node fail-safe: verify_failed must NOT update last_applied_*."""
    server, addr = await _serve(service_state)
    try:
        from app.models.fleet import NodeIdentity

        ident_pb = _make_identity(3)
        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)
            await stub.Ack(
                policy_bus_pb2.AckRequest(
                    node=ident_pb, bundle_id="b1",
                    applied_version="v1", ack_status="applied", detail="",
                )
            )
            await stub.Ack(
                policy_bus_pb2.AckRequest(
                    node=ident_pb, bundle_id="b2",
                    applied_version="v2", ack_status="verify_failed",
                    detail="sig mismatch",
                )
            )
        ident = NodeIdentity(
            fleet_id="prod-fleet",
            region_id="us-east",
            site_id="site-01",
            node_id="node-01-03",
        )
        rec = service_state.fleet_store.get(ident)
        assert rec is not None
        assert rec.last_applied_version == "v1"  # unchanged
        assert rec.last_ack_status == "verify_failed"
    finally:
        await server.stop(grace=None)
