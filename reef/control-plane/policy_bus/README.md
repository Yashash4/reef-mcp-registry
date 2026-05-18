# Reef Policy Bus

TerraFabric-shaped gRPC bus for distributing **signed** Lobster Trap policy
bundles to fleet nodes. The "literal missing wire" between Veea's TerraFabric
control plane and Lobster Trap edge nodes — implemented in v1 against the
contract Reef's `pkg/policysync/cosign.go` (A-6) already verifies against.

## Run

```bash
pip install -e ".[dev]"
python -m app.main
```

Listens on `:50051` for gRPC; `:50052` for the FastAPI admin surface.

## Hierarchy

`fleet → region → site → node`. A bundle's `scope_*` fields narrow delivery;
empty fields are wildcards. The bundled seed creates **49 nodes** (7 sites ×
7 nodes per site, distributed across 3 regions, all in `prod-fleet`) — the
demo's "stadium-wave" fleet visual.

## Endpoints

- gRPC `PolicyBus/Subscribe` — long-lived server-streaming subscription.
- gRPC `PolicyBus/Ack` — node acks after applying a bundle.
- gRPC `PolicyBus/Publish` — admin pushes a new signed bundle (`admin_token`
  pre-shared secret).
- gRPC `PolicyBus/Healthz` — liveness probe (subscribers + bundles counts).
- REST `POST /publish` — JSON wrapper around gRPC Publish for curl-style ops.
- REST `GET /fleet` — fleet snapshot (49 nodes + last-ack metadata) for the
  Stage UI's 7×7 grid.
- REST `GET /healthz` — same liveness, REST shape.

## Environment

- `REEF_POLICY_BUS_GRPC_PORT` (default 50051)
- `REEF_POLICY_BUS_ADMIN_PORT` (default 50052)
- `REEF_POLICY_BUS_ADMIN_TOKEN` (default: random 32-byte hex on first boot,
  written to `data/admin_token.txt`)
- `REEF_POLICY_BUS_PUBLISHER_KEYS_DIR` (default `./keys/publishers`)
- `REEF_POLICY_BUS_DATA_DIR` (default `./data`)
- `REEF_POLICY_BUS_AUDIT_FILE` (default `./data/audit.jsonl`)

## Fail-closed contract

A bundle whose signature does not verify against the publisher allowlist is
**rejected at publish time** and never broadcast. Nodes additionally verify
the detached signature locally — on tamper they Ack `verify_failed` and keep
the previous policy active.

## Regenerate stubs

```bash
python scripts/gen_protos.py
```

Both Python (`app/gen/`) and Go (`../../lobstertrap-reef/pkg/policysync/proto/`)
stubs are committed so consumers don't need `protoc` installed.
