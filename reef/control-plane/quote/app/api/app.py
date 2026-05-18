"""Reef Quote FastAPI app factory.

Exposes:

* ``POST /quote/ria/generate`` — generate a new RIA.
* ``GET  /quote/ria/{ria_id}/download`` — serve the PDF + signature header.
* ``GET  /quote/ria/{ria_id}/verify`` — verify the persisted PDF + .sig.
* ``GET  /healthz`` — liveness probe.
* ``GET  /quote/ria/sample`` — sample-RIA download (boot-time committed).
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from app.api.download import router as download_router
from app.api.generate import router as generate_router
from app.api.health import router as health_router
from app.api.verify import router as verify_router
from app.ria_generator import ensure_sample_ria
from app.ria_signer import RIASigner

logger = logging.getLogger("quote.api")


def _resolve_data_dir() -> Path:
    return Path(os.environ.get("REEF_QUOTE_DATA_DIR", "./data")).resolve()


def _resolve_samples_dir() -> Path:
    here = Path(__file__).resolve()
    # Default: <repo>/reef/control-plane/quote/samples
    fallback = here.parents[3] / "samples"
    return Path(os.environ.get("REEF_QUOTE_SAMPLES_DIR", str(fallback))).resolve()


@asynccontextmanager
async def lifespan(app: FastAPI):
    data_dir = _resolve_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "ria").mkdir(parents=True, exist_ok=True)

    # Load (or auto-generate) the operator's signer key once. Reuse across
    # the process lifetime so the public-key fingerprint stays stable.
    signer = RIASigner()

    samples_dir = _resolve_samples_dir()
    boot_sample = (os.environ.get("REEF_QUOTE_SAMPLE_ON_BOOT", "true").lower()
                   not in {"0", "false", "no", ""})
    if boot_sample:
        sample_path = samples_dir / "sample-ria.pdf"
        # On a fresh container boot we regenerate the sample with the
        # operator's signer so the /quote/ria/sample/verify endpoint
        # verifies against the live key. The committed sample in the
        # public repo stays the canonical artifact judges download; this
        # boot regenerates a runtime copy in the operator's samples dir.
        logger.info("RIA sample: regenerating at %s with operator signer", sample_path)
        ensure_sample_ria(samples_dir=samples_dir, signer=signer)

    app.state.data_dir = data_dir
    app.state.samples_dir = samples_dir
    app.state.signer = signer
    yield


def create_app() -> FastAPI:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s %(message)s",
    )
    app = FastAPI(
        title="Reef Quote — Underwriter Layer + RIA generator",
        version="0.1.0",
        description=(
            "Layer 7 of Reef. Produces the signed Reef Insurance Artifact "
            "(RIA) — a 6-page Munich-Re-rubric-grounded PDF underwriters "
            "can read. See docs/01-PROJECT.md §5.5."
        ),
        lifespan=lifespan,
    )
    app.include_router(health_router)
    app.include_router(generate_router)
    app.include_router(download_router)
    app.include_router(verify_router)
    return app


app = create_app()


def main() -> None:
    import uvicorn

    uvicorn.run(
        "app.api.app:app",
        host=os.environ.get("REEF_QUOTE_HOST", "0.0.0.0"),
        port=int(os.environ.get("REEF_QUOTE_PORT", "8082")),
        log_level="info",
    )


if __name__ == "__main__":
    main()


__all__ = ["create_app", "app", "main"]
