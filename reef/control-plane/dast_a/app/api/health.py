"""GET /healthz — liveness check + catalog stats."""
from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/healthz")
def healthz(request: Request) -> dict:
    """Return ``ok`` plus catalog + review-queue summary counts."""
    catalog = request.app.state.catalog
    drafts = request.app.state.drafts
    stats = catalog.stats()
    pending = drafts.list(status=None)
    return {
        "status": "ok",
        "service": "reef-dast-a",
        "catalog": {
            "total": stats.total,
            "by_source": stats.by_source,
            "by_blocked_status": stats.by_blocked_status,
        },
        "review_queue": {
            "total": len(pending),
            "pending": sum(1 for d in pending if d.status.value == "pending"),
            "approved": sum(1 for d in pending if d.status.value == "approved"),
            "rejected": sum(1 for d in pending if d.status.value == "rejected"),
        },
    }
