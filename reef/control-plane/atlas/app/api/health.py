"""GET /healthz — liveness + seed summary."""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/healthz")
def healthz(request: Request) -> dict:
    """Return ``ok`` plus a count of seeded entries.

    Used by docker-compose health probes and the integration test.
    """
    store = request.app.state.store
    entries = store.list_entries()
    counts = {"verified": 0, "quarantined": 0, "poisoned": 0}
    for e in entries:
        counts[e.status] = counts.get(e.status, 0) + 1
    return {
        "status": "ok",
        "registry_entries": counts,
        "total_entries": store.count_entries(),
        "publishers": store.count_publishers(),
    }


@router.get("/registry/entries")
def list_entries(request: Request) -> dict:
    """List every registry entry. Debug + Stage UI consumption.

    Returns redacted views (no private fingerprints). The signature stays in
    the payload because it's a public artifact — anyone can verify it
    against the published publisher pubkey.
    """
    store = request.app.state.store
    return {
        "entries": [e.model_dump(mode="json") for e in store.list_entries()],
        "publishers": [
            p.model_dump(mode="json", exclude={"public_key_hex"})
            | {"public_key_hex": p.public_key_hex}
            for p in store.list_publishers()
        ],
    }
