"""POST approved drafts to A-4's HUMAN_REVIEW webhook."""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

import httpx

from app.review.draft import PolicyDraft

logger = logging.getLogger("dast_a.review.webhook")


class HumanReviewError(RuntimeError):
    """Raised when the human-review webhook can't be reached or returns an error."""


class HumanReviewWebhook:
    """Thin wrapper around the A-4 human-review POST contract."""

    def __init__(
        self,
        url: Optional[str] = None,
        timeout_seconds: float = 1.5,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._url = (
            url
            or os.environ.get("REEF_HUMAN_REVIEW_WEBHOOK")
            or "http://localhost:8766/approval-queue"
        )
        self._timeout = timeout_seconds
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout_seconds)

    @property
    def url(self) -> str:
        return self._url

    def post_draft(self, draft: PolicyDraft) -> dict[str, str]:
        """POST the draft to the human-review queue.

        Returns the JSON the webhook responds with (or a synthetic
        ``{"review_id": ...}`` if it returns 202 with no body).
        """
        envelope = {
            "kind": "policy_draft",
            "source": "DAST-A",
            "draft_id": draft.draft_id,
            "title": draft.title,
            "rationale": draft.rationale,
            "suggested_yaml_diff": draft.suggested_yaml_diff,
            "evidence_episodes": draft.evidence_episodes,
            "proposed_pack_id": draft.proposed_pack_id,
            "status": draft.status.value,
            "created_at": draft.created_at.isoformat(),
        }
        try:
            resp = self._client.post(
                self._url,
                json=envelope,
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise HumanReviewError(
                f"webhook POST to {self._url!s} failed: {exc!r}"
            ) from exc
        if resp.status_code >= 500:
            raise HumanReviewError(
                f"webhook {self._url!s} returned {resp.status_code}: {resp.text!r}"
            )
        if resp.status_code >= 400:
            raise HumanReviewError(
                f"webhook {self._url!s} rejected draft "
                f"({resp.status_code}): {resp.text!r}"
            )
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            data = {"review_id": draft.draft_id}
        if not isinstance(data, dict):
            data = {"review_id": draft.draft_id, "raw": str(data)}
        return data

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except RuntimeError:
                return None
