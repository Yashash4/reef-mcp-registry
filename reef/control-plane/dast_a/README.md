# Reef DAST-A — RL adversary + attack pack catalog

DAST-A (Dynamic Agent Security Testing — Adversarial) is Reef's continuously-learning
red-team agent. It runs a Proximal Policy Optimization (PPO) policy against the live
victim Copilot-clone, mutating injection templates across a discrete action space, and
catalogs every novel attack as a versioned **attack pack**.

When DAST-A discovers an attack the live Reef policy does NOT block, it pushes a
policy-draft to the HUMAN_REVIEW queue (no auto-apply).

## Layout

```
dast_a/
├── app/
│   ├── env/          # gymnasium env, mutations, victim HTTP proxy, reward shaping
│   ├── agent/        # PPO trainer, checkpoint I/O, interactive run loop
│   ├── packs/        # attack pack catalog (4 seed packs + RL-discovered)
│   ├── review/       # human-review draft builder + webhook poster
│   ├── api/          # FastAPI endpoints (/run, /packs, /review-queue, /healthz)
│   └── audit/        # JSONL audit logger for episodes + discoveries
├── checkpoints/      # PPO weights — dast_a_baseline.zip committed
├── data/             # episode JSONL logs + pack store (runtime)
└── tests/
```

## Quickstart

```bash
pip install -e .[dev]

# Start the victim app on :3001 (in another terminal):
#   cd victim && pnpm dev

# Boot DAST-A
uvicorn app.main:app --host 0.0.0.0 --port 8088

# Kick off 30 adversarial episodes against the live victim
curl -X POST http://localhost:8088/dast-a/run \
  -H "Content-Type: application/json" \
  -d '{"episodes": 30, "checkpoint": "auto", "victim_url": "http://localhost:3001", "reef_on": false}'

# Inspect the attack pack catalog
curl http://localhost:8088/dast-a/packs | jq

# Review queue (drafts derived from unblocked attacks)
curl http://localhost:8088/dast-a/review-queue | jq
```

## Pre-trained checkpoint

`checkpoints/dast_a_baseline.zip` is committed. The PPO trainer ships pre-trained against
the EchoLeak demo path so the demo / tests can load weights without the full ~10k-step
training loop. Fine-tuning live in the stage UI takes ~40 episodes and produces visible
progress for the recorded demo.

## Honest framing

Attack packs marked `discovered_by: "DAST-A (synthetic — RL search against test fixture)"`
are templates the RL search found against the local victim app. They are NOT zero-day
disclosures against production systems. The MCP-RCE-26.04 pack is **catalogued** by
DAST-A using OX Security's verbatim April 2026 disclosure; it was not discovered by
DAST-A (OX Security did).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `REEF_VICTIM_URL` | `http://localhost:3001` | Victim Copilot-clone base URL |
| `REEF_DAST_A_HOST` | `0.0.0.0` | DAST-A HTTP bind host |
| `REEF_DAST_A_PORT` | `8088` | DAST-A HTTP bind port |
| `REEF_DAST_A_DATA_DIR` | `./data` | Episode logs + pack persistence |
| `REEF_DAST_A_CHECKPOINTS_DIR` | `./checkpoints` | PPO weights store |
| `REEF_HUMAN_REVIEW_WEBHOOK` | `http://localhost:8766/approval-queue` | A-4 human-review queue |
| `REEF_DAST_A_REEF_PROXY_URL` | (unset) | When set, episodes route via this proxy (simulated Reef ON) |

## Tests

```bash
pytest -v
```

Tests include unit coverage of the gym env, mutations alphabet, reward shaping, pack
schema/catalog, PPO mini-training (≤2 000 timesteps for CI speed), API endpoints, and
an integration test that drives a stub victim through both `reef_on=false` (exfil
succeeds) and `reef_on=true` (exfil blocked).
