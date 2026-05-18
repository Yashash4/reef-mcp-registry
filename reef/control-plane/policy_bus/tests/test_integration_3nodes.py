"""3-node fleet propagation integration test — the demo's headline proof.

This is the literal "stadium wave" demonstration: publish a signed bundle,
watch it propagate to 3 nodes, watch all 3 apply it, send a tampered
bundle, watch all 3 reject it and keep the previous policy active.

The test boots a real Python gRPC PolicyBus server on a random local port.
Three "nodes" each open a Subscribe stream + run the same verify/apply/ack
loop the Go gRPC client implements in `pkg/policysync/grpc_client.go`.

Why a Python harness for a Go client contract? Two reasons:
  1) The Go side is independently covered by `grpc_client_test.go` under
     bufconn. We are NOT re-testing the Go client here.
  2) This test verifies the END-TO-END BUS BEHAVIOUR — that a real gRPC
     server fans out a real signed bundle to multiple concurrent
     subscribers, records their acks correctly, and rejects a tampered
     bundle at publish-time. That contract is what the demo hinges on.

The seven steps from the task spec are exercised in `test_3node_propagation`.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import socket
import time
from pathlib import Path
from typing import Any

import grpc
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.audit import AuditLogger
from app.crypto import BundleVerifier, PublisherAllowlist
from app.gen import policy_bus_pb2, policy_bus_pb2_grpc
from app.models.fleet import NodeIdentity
from app.service.bus_service import PolicyBusService, ServiceState
from app.store import BundleStore, FleetStore, default_seed_nodes


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _sign(priv: Ed25519PrivateKey, payload: bytes) -> bytes:
    digest = hashlib.sha256(payload).digest()
    return priv.sign(digest)


class SimulatedNode:
    """A Python simulation of a Lobster Trap node's gRPC client behaviour.

    Mirrors the Go `pkg/policysync/grpc_client.go` contract:

      - Opens Subscribe stream against the bus.
      - For each bundle received: verify signature against the trusted
        public key; on verify ok, "apply" by appending to applied_bundles
        and acking "applied"; on verify fail, ack "verify_failed" and
        keep the previous policy active.

    This is the same fail-closed semantics A-6's cosign.go implements
    on the Go side.
    """

    def __init__(
        self,
        *,
        identity: NodeIdentity,
        endpoint: str,
        trusted_pub_raw: bytes,
    ) -> None:
        self.identity = identity
        self.endpoint = endpoint
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        self._trusted_pub = Ed25519PublicKey.from_public_bytes(trusted_pub_raw)
        self.applied_bundles: list[dict[str, Any]] = []
        self.rejected_bundles: list[dict[str, Any]] = []
        self.current_version: str = ""
        self._stop = asyncio.Event()
        self._channel: grpc.aio.Channel | None = None
        self._task: asyncio.Task | None = None
        self._ack_events: list[asyncio.Event] = []
        self._lock = asyncio.Lock()

    # ---- Lifecycle -------------------------------------------------------

    async def start(self) -> None:
        self._channel = grpc.aio.insecure_channel(self.endpoint)
        self._task = asyncio.create_task(
            self._run(), name=f"sim-node-{self.identity.node_id}"
        )

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, grpc.aio.AioRpcError):
                pass
        if self._channel is not None:
            await self._channel.close()

    # ---- Coordination helpers -------------------------------------------

    async def wait_for_apply_count(self, n: int, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self.applied_bundles) >= n:
                return
            await asyncio.sleep(0.02)
        raise AssertionError(
            f"node {self.identity.node_id}: only {len(self.applied_bundles)} "
            f"applies after {timeout}s (wanted {n})"
        )

    async def wait_for_reject_count(self, n: int, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self.rejected_bundles) >= n:
                return
            await asyncio.sleep(0.02)
        raise AssertionError(
            f"node {self.identity.node_id}: only {len(self.rejected_bundles)} "
            f"rejects after {timeout}s (wanted {n})"
        )

    # ---- Internal --------------------------------------------------------

    async def _run(self) -> None:
        assert self._channel is not None
        stub = policy_bus_pb2_grpc.PolicyBusStub(self._channel)
        sub_req = policy_bus_pb2.SubscribeRequest(
            node=policy_bus_pb2.NodeIdentity(
                fleet_id=self.identity.fleet_id,
                region_id=self.identity.region_id,
                site_id=self.identity.site_id,
                node_id=self.identity.node_id,
                svid_subject=self.identity.svid_subject,
            ),
            current_policy_version=self.current_version,
        )
        call = stub.Subscribe(sub_req)
        try:
            async for msg in call:
                if msg.is_heartbeat:
                    continue
                await self._handle_bundle(stub, msg)
        except grpc.aio.AioRpcError:
            # Stream closed — simulation done.
            pass
        except asyncio.CancelledError:
            raise
        finally:
            call.cancel()

    async def _handle_bundle(
        self,
        stub: policy_bus_pb2_grpc.PolicyBusStub,
        msg: policy_bus_pb2.SignedBundle,
    ) -> None:
        from cryptography.exceptions import InvalidSignature

        bundle_yaml = bytes(msg.bundle_yaml)
        signature = bytes(msg.signature)
        digest = hashlib.sha256(bundle_yaml).digest()
        ack_status = "applied"
        ack_detail = ""
        try:
            self._trusted_pub.verify(signature, digest)
        except InvalidSignature as e:
            ack_status = "verify_failed"
            ack_detail = f"signature mismatch: {e}"

        if ack_status == "applied":
            # "Apply" the policy — for the demo this is the magic-word
            # block. We record the YAML so the test can assert on what
            # the node would have hot-loaded.
            self.applied_bundles.append(
                {
                    "bundle_id": msg.bundle_id,
                    "version": msg.version,
                    "yaml": bundle_yaml.decode("utf-8", errors="replace"),
                }
            )
            self.current_version = msg.version
        else:
            self.rejected_bundles.append(
                {
                    "bundle_id": msg.bundle_id,
                    "version": msg.version,
                    "detail": ack_detail,
                }
            )

        # Ack back to the bus.
        try:
            await stub.Ack(
                policy_bus_pb2.AckRequest(
                    node=policy_bus_pb2.NodeIdentity(
                        fleet_id=self.identity.fleet_id,
                        region_id=self.identity.region_id,
                        site_id=self.identity.site_id,
                        node_id=self.identity.node_id,
                        svid_subject=self.identity.svid_subject,
                    ),
                    bundle_id=msg.bundle_id,
                    applied_version=msg.version,
                    ack_status=ack_status,
                    detail=ack_detail,
                )
            )
        except grpc.aio.AioRpcError:
            pass

    def has_applied(self, bundle_id: str) -> bool:
        return any(b["bundle_id"] == bundle_id for b in self.applied_bundles)

    def rule_active(self, rule_substring: str) -> bool:
        """Was a bundle ever applied whose YAML mentions `rule_substring`?

        Used in step 5: "send magic_word_xyz through each node — assert
        all 3 deny it". The simulation maps this to "is there an applied
        policy containing the magic-word block rule".
        """
        for b in self.applied_bundles:
            if rule_substring in b["yaml"]:
                return True
        return False


@pytest.mark.asyncio
async def test_3node_propagation_full_arc(
    tmp_path: Path,
    tmp_keys_dir: Path,
    signer_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    """The 7-step demo proof.

      1. Boot 3 in-process Lobster Trap simulated nodes.
      2. Boot 1 policy bus.
      3. Publish a signed bundle that blocks magic_word_xyz.
      4. All 3 nodes receive, verify, apply, ack within 4 seconds.
      5. Magic-word policy is active on all 3 nodes.
      6. Publish a tampered bundle → all 3 ack verify_failed.
      7. Magic-word policy remains active on all 3 (old policy still wins).
    """
    priv, key_id = signer_keypair
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Step 2: boot the policy bus.
    bundle_store = BundleStore(tmp_path / "bundles.jsonl")
    fleet_store = FleetStore(tmp_path / "fleet.json")
    await fleet_store.seed_if_empty(default_seed_nodes())
    state = ServiceState(
        bundle_store=bundle_store,
        fleet_store=fleet_store,
        verifier=BundleVerifier(PublisherAllowlist(tmp_keys_dir)),
        audit=AuditLogger(tmp_path / "audit.jsonl"),
        admin_token="test-token-3node",
    )
    server = grpc.aio.server()
    policy_bus_pb2_grpc.add_PolicyBusServicer_to_server(
        PolicyBusService(state), server
    )
    port = _free_port()
    addr = f"127.0.0.1:{port}"
    server.add_insecure_port(addr)
    await server.start()

    try:
        # Step 1: boot 3 simulated nodes (different node IDs, same
        # fleet/region/site so the same scope-fleet bundle reaches all).
        nodes = [
            SimulatedNode(
                identity=NodeIdentity(
                    fleet_id="prod-fleet",
                    region_id="us-east",
                    site_id="site-01",
                    node_id=f"node-01-{i:02d}",
                    svid_subject=f"spiffe://reef/prod-fleet/us-east/site-01/node-01-{i:02d}",
                ),
                endpoint=addr,
                trusted_pub_raw=pub_raw,
            )
            for i in range(1, 4)
        ]
        for n in nodes:
            await n.start()

        # Wait for all 3 to register as online.
        async def _wait_online() -> None:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                online_count = sum(
                    1
                    for n in nodes
                    if (rec := fleet_store.get(n.identity)) and rec.online
                )
                if online_count == 3:
                    return
                await asyncio.sleep(0.02)
            assert False, "not all 3 simulated nodes came online"

        await _wait_online()

        # Step 3: publish a signed bundle blocking the magic word.
        yaml_v1 = (
            b"version: '1.0'\n"
            b"policy_name: 'demo-magic-word-v1'\n"
            b"default_action: ALLOW\n"
            b"ingress_rules:\n"
            b"  - name: block_magic_word_xyz\n"
            b"    description: 'block magic_word_xyz'\n"
            b"    priority: 999\n"
            b"    action: DENY\n"
            b"    deny_message: '[REEF] magic_word_xyz blocked by bus-delivered policy'\n"
            b"    conditions:\n"
            b"      - field: intent_category\n"
            b"        match_type: contains\n"
            b"        value: 'magic_word_xyz'\n"
        )
        sig_v1 = _sign(priv, yaml_v1)

        async with grpc.aio.insecure_channel(addr) as channel:
            stub = policy_bus_pb2_grpc.PolicyBusStub(channel)
            resp = await stub.Publish(
                policy_bus_pb2.PublishRequest(
                    bundle=policy_bus_pb2.SignedBundle(
                        bundle_id="bundle-magic-word",
                        version="v1",
                        scope_fleet_id="prod-fleet",
                        bundle_yaml=yaml_v1,
                        signature=sig_v1,
                        signer_key_id=key_id,
                        published_at_unix=int(time.time()),
                    ),
                    admin_token=state.admin_token,
                )
            )
            assert resp.bundle_id == "bundle-magic-word"
            assert resp.fleet_recipient_count == 3

            # Step 4: all 3 nodes receive, verify, apply, ack within 4 seconds.
            t_start = time.monotonic()
            await asyncio.gather(*(n.wait_for_apply_count(1, timeout=4.0) for n in nodes))
            elapsed = time.monotonic() - t_start
            assert elapsed < 4.0, f"propagation took {elapsed:.2f}s (wanted < 4s)"

            for n in nodes:
                assert n.has_applied("bundle-magic-word")
                assert n.current_version == "v1"

            # The fleet store should now reflect "v1 applied" for all 3.
            for n in nodes:
                rec = fleet_store.get(n.identity)
                assert rec is not None
                assert rec.last_applied_version == "v1"
                assert rec.last_ack_status == "applied"

            # Step 5: magic-word policy active on all 3.
            for n in nodes:
                assert n.rule_active("magic_word_xyz"), (
                    f"node {n.identity.node_id}: magic-word rule not active"
                )

            # Step 6: publish a TAMPERED bundle. We sign over yaml_v2 then
            # send a different payload (a backdoor "allow magic_word_xyz").
            yaml_v2_intended = (
                b"version: '1.0'\n"
                b"policy_name: 'attacker-removal-v2'\n"
                b"default_action: ALLOW\n"
                b"ingress_rules: []\n"
            )
            sig_v2 = _sign(priv, yaml_v2_intended)
            yaml_v2_tampered = (
                b"version: '1.0'\n"
                b"policy_name: 'attacker-removal-v2'\n"
                b"# attacker tries to slip in a backdoor that DROPS the magic-word rule.\n"
                b"default_action: ALLOW\n"
                b"ingress_rules: []\n"
            )

            # The bus's verify step catches this BEFORE broadcast — that's
            # part of the contract. Publish should be rejected with
            # PERMISSION_DENIED + the audit log records the rejection.
            with pytest.raises(grpc.aio.AioRpcError) as ei:
                await stub.Publish(
                    policy_bus_pb2.PublishRequest(
                        bundle=policy_bus_pb2.SignedBundle(
                            bundle_id="bundle-attacker-v2",
                            version="v2",
                            scope_fleet_id="prod-fleet",
                            bundle_yaml=yaml_v2_tampered,
                            signature=sig_v2,
                            signer_key_id=key_id,
                            published_at_unix=int(time.time()),
                        ),
                        admin_token=state.admin_token,
                    )
                )
            assert ei.value.code() == grpc.StatusCode.PERMISSION_DENIED
            assert "signature mismatch" in ei.value.details()

            # Defense-in-depth: even if a malicious bus tried to push a
            # tampered bundle to subscribers (bypassing its own verify
            # step), the node-side verifier MUST reject it. We assert this
            # by inserting the tampered record DIRECTLY into the bundle
            # store (bypassing the gRPC Publish path) and watching the
            # nodes reject it on their next ack.
            from app.models.bundle import BundleRecord, BundleScope

            tampered_record = BundleRecord.from_raw(
                bundle_id="bundle-attacker-tampered",
                version="v2",
                scope=BundleScope(fleet_id="prod-fleet"),
                bundle_yaml=yaml_v2_tampered,
                signature=sig_v2,
                signer_key_id=key_id,
                published_at_unix=int(time.time()),
            )
            await state.bundle_store.add(tampered_record)

            # Each of the 3 nodes verifies locally and rejects.
            await asyncio.gather(
                *(n.wait_for_reject_count(1, timeout=4.0) for n in nodes)
            )
            for n in nodes:
                assert any(
                    b["bundle_id"] == "bundle-attacker-tampered"
                    for b in n.rejected_bundles
                ), f"node {n.identity.node_id} did not reject the tampered bundle"
                # Step 7: magic-word policy still active.
                assert n.rule_active(
                    "magic_word_xyz"
                ), f"node {n.identity.node_id}: magic-word rule was lost"
                assert n.current_version == "v1", (
                    f"node {n.identity.node_id}: version regressed to {n.current_version!r}"
                )

            # Bus-side fleet store also reflects the rejection on all 3.
            for n in nodes:
                rec = fleet_store.get(n.identity)
                assert rec is not None
                assert rec.last_ack_status == "verify_failed"
                # last_applied_version unchanged from v1.
                assert rec.last_applied_version == "v1"

        # Tear down nodes.
        for n in nodes:
            await n.stop()
    finally:
        await server.stop(grace=0.5)


@pytest.mark.asyncio
async def test_3node_scope_filter_does_not_overdeliver(
    tmp_path: Path,
    tmp_keys_dir: Path,
    signer_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    """A bundle scoped to us-east must NOT reach a node in us-west."""
    priv, key_id = signer_keypair
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    bundle_store = BundleStore(tmp_path / "bundles.jsonl")
    fleet_store = FleetStore(tmp_path / "fleet.json")
    await fleet_store.seed_if_empty(default_seed_nodes())
    state = ServiceState(
        bundle_store=bundle_store,
        fleet_store=fleet_store,
        verifier=BundleVerifier(PublisherAllowlist(tmp_keys_dir)),
        audit=AuditLogger(tmp_path / "audit.jsonl"),
        admin_token="test-token-scope",
    )
    server = grpc.aio.server()
    policy_bus_pb2_grpc.add_PolicyBusServicer_to_server(
        PolicyBusService(state), server
    )
    port = _free_port()
    addr = f"127.0.0.1:{port}"
    server.add_insecure_port(addr)
    await server.start()

    try:
        east_node = SimulatedNode(
            identity=NodeIdentity(
                fleet_id="prod-fleet",
                region_id="us-east",
                site_id="site-01",
                node_id="node-01-01",
            ),
            endpoint=addr,
            trusted_pub_raw=pub_raw,
        )
        west_node = SimulatedNode(
            identity=NodeIdentity(
                fleet_id="prod-fleet",
                region_id="us-west",
                site_id="site-04",
                node_id="node-04-01",
            ),
            endpoint=addr,
            trusted_pub_raw=pub_raw,
        )
        await east_node.start()
        await west_node.start()

        yaml = b"version: '1.0'\npolicy_name: 'east-only'\n"
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
                    admin_token=state.admin_token,
                )
            )

        await east_node.wait_for_apply_count(1, timeout=3.0)
        # Give the west node ample time to NOT receive.
        await asyncio.sleep(0.5)
        assert east_node.has_applied("east-bundle")
        assert not west_node.has_applied("east-bundle")

        await east_node.stop()
        await west_node.stop()
    finally:
        await server.stop(grace=0.5)
