"""GET /quote/ria/{ria_id}/download — serve the signed PDF.

The response sets:

* ``Content-Type: application/pdf``
* ``X-Reef-RIA-Signature``: base64-encoded ed25519 signature
* ``X-Reef-RIA-SHA256``: SHA-256 hex of the PDF bytes
* ``Content-Disposition: attachment; filename=<ria_id>.pdf``
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response

logger = logging.getLogger("quote.api.download")

router = APIRouter(prefix="/quote")


@router.get("/ria/sample/download")
def download_sample(request: Request) -> Response:
    samples_dir = request.app.state.samples_dir
    return _serve_pdf(samples_dir / "sample-ria.pdf")


@router.get("/ria/{ria_id}/download")
def download(ria_id: str, request: Request) -> Response:
    data_dir = request.app.state.data_dir
    return _serve_pdf(Path(data_dir) / "ria" / f"{ria_id}.pdf")


def _serve_pdf(pdf_path: Path) -> Response:
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail=f"RIA not found at {pdf_path.name}")
    sig_path = Path(str(pdf_path) + ".sig")
    pdf_bytes = pdf_path.read_bytes()
    sha = hashlib.sha256(pdf_bytes).hexdigest()
    headers = {
        "X-Reef-RIA-SHA256": sha,
        "Content-Disposition": f'attachment; filename="{pdf_path.name}"',
    }
    if sig_path.exists():
        sig_text = sig_path.read_text(encoding="ascii").strip()
        headers["X-Reef-RIA-Signature"] = sig_text
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers=headers,
    )


__all__ = ["router"]
