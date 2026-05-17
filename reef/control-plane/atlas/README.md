# Reef Atlas — MCP Signature Registry

Atlas is the **centerpiece of Reef's Layer 1**: a Sigstore-style signed registry of trusted MCP servers plus a runtime verifier the Lobster Trap sidecar calls on every bind attempt.

It is grounded in the April 2026 OX Security disclosure ("The Mother of All AI Supply Chains") and the canonical Anthropic MCP specification (`modelcontextprotocol.io`). When a poisoned server tries to bind, Atlas returns `decision: deny` with code `MCP-RCE-26.04` and a verbatim citation of the OX Security finding.

## Run it

```bash
cd reef/control-plane/atlas
python -m pip install -e ".[dev]"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080
```

The first boot seeds the registry with **47 verified + 2 quarantined + 1 poisoned** demo entries (`com.attacker-example.evil-server@0.5.0` is the poisoned one).

## Endpoints

| Method + path        | Purpose                                                  |
|----------------------|----------------------------------------------------------|
| `POST /register`     | Register a new MCP server manifest (publisher-signed).   |
| `POST /verify`       | Verify a server attempting to bind. Returns allow/deny/review. |
| `POST /publishers`   | Admin: register an ed25519 publisher pubkey.             |
| `GET  /healthz`      | Liveness probe.                                          |
| `GET  /registry/entries` | List registry entries (debug + Stage UI).            |

## Env vars

| Var                              | Default                  |
|----------------------------------|--------------------------|
| `REEF_ATLAS_DATA_DIR`            | `./data`                 |
| `REEF_ATLAS_PUBLISHER_KEYS_DIR`  | `./keys/publishers`      |
| `REEF_ATLAS_AUDIT_FILE`          | `./data/audit.jsonl`     |
| `REEF_ATLAS_SEED_ON_BOOT`        | `1` (set to `0` to skip) |

## Fail-closed contract

The Lobster Trap sidecar (`pkg/mcpsupply`) treats unreachable Atlas, 5xx, or timeout as `DENY`. Atlas itself denies any handshake whose payload doesn't match a verified signed entry. See `docs/24-GROUNDING.md` Part 3 for the six capabilities Atlas enforces.
