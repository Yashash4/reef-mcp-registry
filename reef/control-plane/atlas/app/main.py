"""FastAPI app entrypoint for the Reef Atlas registry."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from app.api import health, publish, register, verify
from app.audit import AuditLogger
from app.seed import seed_demo
from app.store import FileStore

logger = logging.getLogger("atlas")


def _resolve_paths() -> tuple[Path, Path, Path]:
    data_dir = Path(os.environ.get("REEF_ATLAS_DATA_DIR", "./data")).resolve()
    keys_dir = Path(
        os.environ.get("REEF_ATLAS_PUBLISHER_KEYS_DIR", "./keys/publishers")
    ).resolve()
    audit_file = Path(
        os.environ.get("REEF_ATLAS_AUDIT_FILE", str(data_dir / "audit.jsonl"))
    ).resolve()
    return data_dir, keys_dir, audit_file


@asynccontextmanager
async def lifespan(app: FastAPI):
    data_dir, keys_dir, audit_file = _resolve_paths()
    store = FileStore(data_dir)
    auditor = AuditLogger(audit_file)
    seed_on_boot = os.environ.get("REEF_ATLAS_SEED_ON_BOOT", "1") != "0"
    if seed_on_boot:
        counts = seed_demo(store, keys_dir, logger=logger)
        auditor.log(
            {
                "kind": "boot",
                "event": "seed",
                "counts": counts,
            }
        )
    app.state.store = store
    app.state.auditor = auditor
    yield


def create_app() -> FastAPI:
    """Construct the FastAPI app. Used by tests + ASGI servers alike."""
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")
    app = FastAPI(
        title="Reef Atlas — MCP signature registry",
        version="0.1.0",
        description=(
            "The signed supply chain for MCP servers. Atlas verifies every "
            "MCP server bind attempt against a signed registry entry "
            "enforced under the six capabilities described in "
            "docs/24-GROUNDING.md Part 3."
        ),
        lifespan=lifespan,
    )
    app.include_router(health.router)
    app.include_router(register.router)
    app.include_router(verify.router)
    app.include_router(publish.router)
    return app


app = create_app()


def main() -> None:
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=os.environ.get("REEF_ATLAS_HOST", "0.0.0.0"),
        port=int(os.environ.get("REEF_ATLAS_PORT", "8080")),
        reload=False,
    )


if __name__ == "__main__":
    main()
