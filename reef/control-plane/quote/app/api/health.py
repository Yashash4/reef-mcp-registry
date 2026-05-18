"""GET /healthz — liveness probe + signer key fingerprint."""
from __future__ import annotations

import hashlib

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/healthz")
def healthz(request: Request) -> dict:
    signer = request.app.state.signer
    samples_dir = request.app.state.samples_dir
    sample_path = samples_dir / "sample-ria.pdf"
    pub_pem = signer.public_key_pem
    fingerprint = hashlib.sha256(pub_pem).hexdigest()[:16]
    return {
        "status": "ok",
        "signer_key_id": signer.signer_key_id,
        "signer_pub_fingerprint": fingerprint,
        "data_dir": str(request.app.state.data_dir),
        "samples_dir": str(samples_dir),
        "sample_exists": sample_path.exists(),
        "sample_path": str(sample_path) if sample_path.exists() else None,
    }
