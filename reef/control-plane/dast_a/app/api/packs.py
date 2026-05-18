"""GET /dast-a/packs — list catalog; GET /dast-a/packs/{id} — pack detail."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from app.packs import AttackPack, AttackPackList, PackNotFound

router = APIRouter(prefix="/dast-a")


@router.get("/packs", response_model=AttackPackList)
def list_packs(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=1000),
) -> AttackPackList:
    catalog = request.app.state.catalog
    page_packs, total = catalog.list(page=page, page_size=page_size)
    return AttackPackList(
        total=total, page=page, page_size=page_size, packs=page_packs
    )


@router.get("/packs/{pack_id}", response_model=AttackPack)
def get_pack(pack_id: str, request: Request) -> AttackPack:
    catalog = request.app.state.catalog
    try:
        return catalog.get(pack_id)
    except PackNotFound as exc:
        raise HTTPException(
            status_code=404, detail=f"pack {pack_id!r} not found"
        ) from exc
