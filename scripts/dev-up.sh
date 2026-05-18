#!/usr/bin/env bash
# dev-up.sh — Native (non-Docker) dev quickstart for the Reef stack.
#
# Use this when `docker compose up` is not available (e.g. Docker Desktop
# daemon is stopped on Windows / WSL). Brings up the 4 Python services +
# the 2 Next.js services on the host, on the same ports docker-compose
# would map. Each service runs in its own background process; the script
# emits a single banner with PIDs + ports + log file paths so the operator
# can tail them.
#
# Prereqs (host):
#   - Python 3.11+
#   - Node 20+ with pnpm 10
#   - Go 1.22+ (only if you want the Lobster Trap proxy)
#   - All service-specific dependencies installed (`pip install -e ".[dev]"`
#     under each Python service; `pnpm install` under each Next.js service).
#
# Stops:
#   ./scripts/dev-down.sh  (or `kill $(cat /tmp/reef-*.pid)`)
#
# This script intentionally avoids `&&` chains so a single failing service
# doesn't tear down the rest of the stack.

set -u  # error on undefined vars; -e is intentionally NOT set because we
        # want partial stack bring-up to keep going.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG_DIR="/tmp/reef-logs"
mkdir -p "$LOG_DIR"

start_python_service() {
  local name="$1"
  local dir="$2"
  local entry="$3"
  local port="$4"
  local extra_env="${5:-}"

  echo "[dev-up] starting $name on :$port (logs: $LOG_DIR/$name.log)"
  (
    cd "$dir"
    # shellcheck disable=SC2086
    eval "$extra_env nohup python -m uvicorn $entry --host 0.0.0.0 --port $port > $LOG_DIR/$name.log 2>&1 &"
    echo $! > "/tmp/reef-$name.pid"
  )
}

start_next_service() {
  local name="$1"
  local dir="$2"
  local port="$3"

  echo "[dev-up] starting $name on :$port (logs: $LOG_DIR/$name.log)"
  (
    cd "$dir"
    nohup env PORT="$port" HOSTNAME=0.0.0.0 pnpm dev > "$LOG_DIR/$name.log" 2>&1 &
    echo $! > "/tmp/reef-$name.pid"
  )
}

# Atlas (MCP signature registry) — port 8080
start_python_service atlas \
  "reef/control-plane/atlas" \
  "app.main:app" \
  8080 \
  "REEF_ATLAS_SEED_ON_BOOT=1 "

# Policy bus — gRPC 50051, admin REST 50052
echo "[dev-up] starting policy-bus on :50051 grpc + :50052 admin (logs: $LOG_DIR/policy-bus.log)"
(
  cd "reef/control-plane/policy_bus"
  nohup python -m app.main > "$LOG_DIR/policy-bus.log" 2>&1 &
  echo $! > "/tmp/reef-policy-bus.pid"
)

# DAST-A — port 8083
start_python_service dast-a \
  "reef/control-plane/dast_a" \
  "app.main:app" \
  8083 \
  "REEF_DAST_A_SEED_ON_BOOT=1 REEF_DAST_A_USE_STUB_VICTIM=1 "

# Quote — port 8082
start_python_service quote \
  "reef/control-plane/quote" \
  "app.api.app:app" \
  8082 \
  "REEF_QUOTE_SAMPLE_ON_BOOT=true "

# Victim Next.js — port 3001
start_next_service victim "victim" 3001

# Stage UI Next.js — port 3000
start_next_service stage-ui "reef/stage-ui" 3000

sleep 2

cat <<'BANNER'

==============================================================================
  REEF dev stack up. Visit:
    http://localhost:3000      Public Safety Page (Stage UI)
    http://localhost:3001      Victim Copilot-clone
    http://localhost:8080      Atlas MCP registry
    http://localhost:8082      Reef Quote (RIA generator)
    http://localhost:8083      DAST-A
    http://localhost:50052     Policy bus admin REST

  Logs:  /tmp/reef-logs/<service>.log
  PIDs:  /tmp/reef-<service>.pid
  Stop:  kill $(cat /tmp/reef-*.pid)

  This script runs each service natively without Docker. Use `docker
  compose up` instead when the Docker Desktop daemon is available — it
  gives you healthchecks, depends_on gating, and shared volumes.
==============================================================================

BANNER
