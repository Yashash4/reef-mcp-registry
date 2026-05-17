"""POST /publishers — register an ed25519 publisher (admin)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from app.crypto import fingerprint
from app.models import Publisher, PublisherRegisterRequest

router = APIRouter()


@router.post("/publishers", status_code=201)
def register_publisher(req: PublisherRegisterRequest, request: Request) -> dict:
    """Persist a new trusted publisher.

    Idempotent: re-registering an existing publisher_id rotates its public
    key (and is recorded in the audit log).
    """
    try:
        bytes.fromhex(req.public_key_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="public_key_hex must be hex")
    store = request.app.state.store
    auditor = request.app.state.auditor
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    existing = store.get_publisher(req.publisher_id)
    publisher = Publisher(
        publisher_id=req.publisher_id,
        display_name=req.display_name,
        public_key_hex=req.public_key_hex,
        scopes=req.scopes,
        created_at=existing.created_at if existing else now_iso,
        revoked=False,
        fingerprint=fingerprint(req.public_key_hex),
    )
    store.upsert_publisher(publisher)
    audit_id = auditor.log(
        {
            "kind": "publisher",
            "publisher_id": publisher.publisher_id,
            "fingerprint": publisher.fingerprint,
            "rotated": existing is not None,
        }
    )
    return {
        "publisher_id": publisher.publisher_id,
        "fingerprint": publisher.fingerprint,
        "scopes": publisher.scopes,
        "rotated": existing is not None,
        "audit_id": audit_id,
    }
