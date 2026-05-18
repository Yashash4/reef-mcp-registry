"""GET /quote/ria/{ria_id}/verify — re-verify a persisted RIA signature."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from app.ria_signer import SignatureVerificationFailed

router = APIRouter(prefix="/quote")


@router.get("/ria/sample/verify")
def verify_sample(request: Request) -> dict:
    samples_dir = request.app.state.samples_dir
    return _verify_path(samples_dir / "sample-ria.pdf", request)


@router.get("/ria/{ria_id}/verify")
def verify(ria_id: str, request: Request) -> dict:
    data_dir = request.app.state.data_dir
    return _verify_path(Path(data_dir) / "ria" / f"{ria_id}.pdf", request)


def _verify_path(pdf_path: Path, request: Request) -> dict:
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail=f"PDF not found at {pdf_path.name}")
    sig_path = Path(str(pdf_path) + ".sig")
    if not sig_path.exists():
        raise HTTPException(status_code=404, detail=f"signature not found at {sig_path.name}")
    pdf_bytes = pdf_path.read_bytes()
    sig_b64 = sig_path.read_text(encoding="ascii").strip()
    signer = request.app.state.signer
    try:
        verified = signer.verify(pdf_bytes, sig_b64)
    except SignatureVerificationFailed:
        verified = False
    return {
        "verified": bool(verified),
        "signer_key_id": signer.signer_key_id,
        "signed_at": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
        "pdf_sha256": _sha256_hex(pdf_bytes),
    }


def _sha256_hex(b: bytes) -> str:
    import hashlib

    return hashlib.sha256(b).hexdigest()


__all__ = ["router"]
