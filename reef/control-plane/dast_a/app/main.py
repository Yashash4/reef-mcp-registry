"""FastAPI app entrypoint for the Reef DAST-A service."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from app.agent.checkpoint import CheckpointStore
from app.api import gemini, health, packs, review_queue, run
from app.audit import AuditLogger
from app.packs import PackCatalog, seed_packs
from app.review import DraftStore, HumanReviewWebhook

logger = logging.getLogger("dast_a")


def _resolve_paths() -> tuple[Path, Path, Path]:
    data_dir = Path(os.environ.get("REEF_DAST_A_DATA_DIR", "./data")).resolve()
    checkpoints_dir = Path(
        os.environ.get("REEF_DAST_A_CHECKPOINTS_DIR", "./checkpoints")
    ).resolve()
    audit_file = Path(
        os.environ.get("REEF_DAST_A_AUDIT_FILE", str(data_dir / "audit.jsonl"))
    ).resolve()
    return data_dir, checkpoints_dir, audit_file


@asynccontextmanager
async def lifespan(app: FastAPI):
    data_dir, checkpoints_dir, audit_file = _resolve_paths()
    data_dir.mkdir(parents=True, exist_ok=True)
    checkpoints_dir.mkdir(parents=True, exist_ok=True)
    auditor = AuditLogger(audit_file)
    catalog = PackCatalog(data_dir=data_dir)
    drafts = DraftStore(data_dir=data_dir)
    checkpoints = CheckpointStore(checkpoints_dir=checkpoints_dir)
    webhook = HumanReviewWebhook()

    seed_on_boot = os.environ.get("REEF_DAST_A_SEED_ON_BOOT", "1") != "0"
    if seed_on_boot:
        inserted = seed_packs(catalog)
        auditor.log(
            "boot_seed",
            {
                "inserted_packs": inserted,
                "data_dir": str(data_dir),
                "checkpoints_dir": str(checkpoints_dir),
            },
        )
        if inserted:
            logger.info(
                "[dast-a] seeded %d attack packs into %s", inserted, data_dir
            )

    from app.agent.session_store import RedTeamSessionStore

    app.state.auditor = auditor
    app.state.catalog = catalog
    app.state.drafts = drafts
    app.state.checkpoints = checkpoints
    app.state.review_webhook = webhook
    app.state.victim_url = os.environ.get(
        "REEF_VICTIM_URL", "http://localhost:3001"
    )
    app.state.default_use_stub = (
        os.environ.get("REEF_DAST_A_USE_STUB_VICTIM", "0") == "1"
    )
    # Bounded in-memory store of recent Gemini-Pro red-team sessions so the
    # `/dast-a/red-team/sessions/{id}/screenshots` endpoint can replay them.
    app.state.gemini_sessions = RedTeamSessionStore(
        max_sessions=int(os.environ.get("REEF_GEMINI_SESSION_CACHE_SIZE", "16"))
    )
    yield
    webhook.close()


def create_app() -> FastAPI:
    """Construct the FastAPI app. Used by tests + ASGI servers alike."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s %(message)s",
    )
    app = FastAPI(
        title="Reef DAST-A — RL adversary + attack pack catalog",
        version="0.1.0",
        description=(
            "PPO-based adversarial search over LLM Scope Violation templates. "
            "When the live policy misses an attack, DAST-A pushes a draft to "
            "the HUMAN_REVIEW queue. See docs/03-TASKS.md Layer 6."
        ),
        lifespan=lifespan,
    )
    app.include_router(health.router)
    app.include_router(packs.router)
    app.include_router(run.router)
    app.include_router(review_queue.router)
    app.include_router(gemini.router)
    return app


app = create_app()


def main() -> None:  # pragma: no cover - exercised by `dast-a` script
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=os.environ.get("REEF_DAST_A_HOST", "0.0.0.0"),
        port=int(os.environ.get("REEF_DAST_A_PORT", "8088")),
        reload=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
