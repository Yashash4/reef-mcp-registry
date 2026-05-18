"""Reef Policy Bus — asyncio gRPC server + FastAPI admin entrypoint.

Boots two listeners:

  - gRPC PolicyBus on REEF_POLICY_BUS_GRPC_PORT (default 50051)
  - FastAPI admin on REEF_POLICY_BUS_ADMIN_PORT (default 50052)

Seeds the fleet store with 49 nodes (7 sites × 7 nodes × 3 regions × 1
prod-fleet) on first boot. Replays the bundle store from disk.

If REEF_POLICY_BUS_ADMIN_TOKEN is unset, a random 32-byte hex is generated
and persisted to `<data_dir>/admin_token.txt` so subsequent restarts pick
up the same token. The token's presence is logged at INFO; the value is
NOT logged (we log only the fingerprint).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import signal
import sys
from pathlib import Path
from typing import Optional

import grpc
import uvicorn

from app.audit import AuditLogger
from app.crypto import BundleVerifier, PublisherAllowlist
from app.gen import policy_bus_pb2_grpc
from app.service import PolicyBusService, ServiceState, build_admin_app
from app.store import BundleStore, FleetStore, default_seed_nodes


logger = logging.getLogger("policy_bus")


def _resolve_paths() -> tuple[Path, Path, Path, Path, Path]:
    data_dir = Path(os.environ.get("REEF_POLICY_BUS_DATA_DIR", "./data")).resolve()
    keys_dir = Path(
        os.environ.get("REEF_POLICY_BUS_PUBLISHER_KEYS_DIR", "./keys/publishers")
    ).resolve()
    audit_file = Path(
        os.environ.get(
            "REEF_POLICY_BUS_AUDIT_FILE",
            str(data_dir / "audit.jsonl"),
        )
    ).resolve()
    bundles_file = data_dir / "bundles.jsonl"
    fleet_file = data_dir / "fleet.json"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir, keys_dir, audit_file, bundles_file, fleet_file


def _resolve_admin_token(data_dir: Path) -> str:
    token = os.environ.get("REEF_POLICY_BUS_ADMIN_TOKEN", "").strip()
    if token:
        return token
    token_path = data_dir / "admin_token.txt"
    if token_path.exists():
        return token_path.read_text(encoding="utf-8").strip()
    new_token = secrets.token_hex(32)
    token_path.write_text(new_token, encoding="utf-8")
    return new_token


async def _build_state() -> ServiceState:
    data_dir, keys_dir, audit_file, bundles_file, fleet_file = _resolve_paths()

    allowlist = PublisherAllowlist(keys_dir)
    verifier = BundleVerifier(allowlist)
    audit = AuditLogger(audit_file)
    bundle_store = BundleStore(bundles_file)
    fleet_store = FleetStore(fleet_file)

    # Seed fleet on first boot.
    seeded = await fleet_store.seed_if_empty(default_seed_nodes())
    if seeded:
        logger.info(
            "fleet seeded: %d nodes (prod-fleet, 7 sites × 7 nodes × 3 regions)",
            seeded,
        )

    admin_token = _resolve_admin_token(data_dir)
    token_fp = hashlib.sha256(admin_token.encode("utf-8")).hexdigest()[:16]
    logger.info("admin token fingerprint: %s", token_fp)
    logger.info(
        "publisher allowlist: %d keys loaded from %s",
        len(allowlist),
        keys_dir,
    )

    return ServiceState(
        bundle_store=bundle_store,
        fleet_store=fleet_store,
        verifier=verifier,
        audit=audit,
        admin_token=admin_token,
    )


async def _serve_grpc(state: ServiceState, port: int) -> grpc.aio.Server:
    server = grpc.aio.server()
    service = PolicyBusService(state)
    policy_bus_pb2_grpc.add_PolicyBusServicer_to_server(service, server)
    listen_addr = f"0.0.0.0:{port}"
    server.add_insecure_port(listen_addr)
    await server.start()
    logger.info("gRPC PolicyBus listening on %s", listen_addr)
    return server


async def _serve_admin(state: ServiceState, port: int) -> uvicorn.Server:
    admin_app = build_admin_app(state)
    config = uvicorn.Config(
        admin_app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config)
    # Run in background so we can also serve gRPC.
    asyncio.create_task(server.serve(), name="policy-bus-admin")
    logger.info("FastAPI admin listening on 0.0.0.0:%d", port)
    return server


async def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s %(message)s",
    )
    state = await _build_state()
    grpc_port = int(os.environ.get("REEF_POLICY_BUS_GRPC_PORT", "50051"))
    admin_port = int(os.environ.get("REEF_POLICY_BUS_ADMIN_PORT", "50052"))

    grpc_server = await _serve_grpc(state, grpc_port)
    admin_server = await _serve_admin(state, admin_port)

    stop_event = asyncio.Event()

    def _shutdown(*_args) -> None:
        logger.info("shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _shutdown)

    try:
        await stop_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("draining gRPC connections (grace=2s)")
        await grpc_server.stop(grace=2.0)
        admin_server.should_exit = True
        await asyncio.sleep(0.1)


def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
