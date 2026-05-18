"""GET /dast-a/review-queue + POST /dast-a/review-queue/{draft_id}/approve."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from app.review import (
    DraftStatus,
    HumanReviewError,
    PolicyDraft,
)

logger = logging.getLogger("dast_a.api.review_queue")

router = APIRouter(prefix="/dast-a/review-queue")


@router.get("", response_model=list[PolicyDraft])
def list_drafts(
    request: Request, status: Optional[str] = None
) -> list[PolicyDraft]:
    drafts = request.app.state.drafts
    filter_status: Optional[DraftStatus] = None
    if status:
        try:
            filter_status = DraftStatus(status)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"unknown status {status!r}; expected one of "
                    + ", ".join(s.value for s in DraftStatus)
                ),
            ) from exc
    return drafts.list(status=filter_status)


@router.get("/{draft_id}", response_model=PolicyDraft)
def get_draft(draft_id: str, request: Request) -> PolicyDraft:
    drafts = request.app.state.drafts
    try:
        return drafts.get(draft_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=404, detail=f"draft {draft_id!r} not found"
        ) from exc


@router.post("/{draft_id}/approve", response_model=PolicyDraft)
def approve_draft(draft_id: str, request: Request) -> PolicyDraft:
    drafts = request.app.state.drafts
    webhook = request.app.state.review_webhook
    try:
        draft = drafts.get(draft_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=404, detail=f"draft {draft_id!r} not found"
        ) from exc
    if draft.status == DraftStatus.APPROVED:
        return draft
    try:
        result = webhook.post_draft(draft)
    except HumanReviewError as exc:
        logger.warning(
            "approve_draft failed to POST to webhook %s: %r",
            webhook.url,
            exc,
        )
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    updated = drafts.update_status(draft_id, DraftStatus.APPROVED)
    auditor = request.app.state.auditor
    auditor.log(
        "draft_approved",
        {
            "draft_id": draft_id,
            "webhook_url": webhook.url,
            "webhook_response": result,
        },
    )
    return updated


@router.post("/{draft_id}/reject", response_model=PolicyDraft)
def reject_draft(draft_id: str, request: Request) -> PolicyDraft:
    drafts = request.app.state.drafts
    try:
        drafts.get(draft_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=404, detail=f"draft {draft_id!r} not found"
        ) from exc
    updated = drafts.update_status(draft_id, DraftStatus.REJECTED)
    auditor = request.app.state.auditor
    auditor.log("draft_rejected", {"draft_id": draft_id})
    return updated
