"""Build and persist policy-draft entries derived from unblocked attacks."""
from __future__ import annotations

import datetime as dt
import enum
import json
import logging
import os
import secrets
import threading
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field

from app.agent.run import EpisodeResult

logger = logging.getLogger("dast_a.review.draft")


class DraftStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class PolicyDraft(BaseModel):
    """One pending policy-update draft."""

    model_config = ConfigDict(extra="forbid")

    draft_id: str
    title: str
    rationale: str
    suggested_yaml_diff: str = Field(
        ...,
        description=(
            "Plain-text YAML diff an operator can paste into Lobster Trap's "
            "default_policy.yaml. NOT auto-applied — A-4's HUMAN_REVIEW queue "
            "is the safety valve."
        ),
    )
    evidence_episodes: list[str]
    proposed_pack_id: Optional[str] = None
    status: DraftStatus = DraftStatus.PENDING
    created_at: dt.datetime
    updated_at: dt.datetime


_REVIEW_QUEUE_FILE = "review_queue.json"


class DraftStore:
    """Mutex-protected JSON-file store of pending drafts."""

    def __init__(self, data_dir: Optional[Path | str] = None) -> None:
        self._lock = threading.RLock()
        self._dir = Path(
            data_dir or os.environ.get("REEF_DAST_A_DATA_DIR", "./data")
        ).resolve()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / _REVIEW_QUEUE_FILE
        self._drafts: dict[str, PolicyDraft] = {}
        self._load()

    def add(self, draft: PolicyDraft) -> None:
        with self._lock:
            self._drafts[draft.draft_id] = draft
            self._persist()

    def get(self, draft_id: str) -> PolicyDraft:
        with self._lock:
            try:
                return self._drafts[draft_id]
            except KeyError as exc:
                raise KeyError(draft_id) from exc

    def list(self, status: Optional[DraftStatus] = None) -> list[PolicyDraft]:
        with self._lock:
            drafts = list(self._drafts.values())
        if status is not None:
            drafts = [d for d in drafts if d.status == status]
        drafts.sort(key=lambda d: d.created_at, reverse=True)
        return drafts

    def update_status(self, draft_id: str, new_status: DraftStatus) -> PolicyDraft:
        with self._lock:
            try:
                draft = self._drafts[draft_id]
            except KeyError as exc:
                raise KeyError(draft_id) from exc
            updated = draft.model_copy(
                update={
                    "status": new_status,
                    "updated_at": dt.datetime.now(tz=dt.timezone.utc),
                }
            )
            self._drafts[draft_id] = updated
            self._persist()
            return updated

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = self._path.read_text(encoding="utf-8")
            if not raw.strip():
                return
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "draft store at %s unreadable (%r); starting empty",
                self._path,
                exc,
            )
            return
        if not isinstance(data, list):
            logger.warning(
                "draft store at %s has unexpected shape; ignoring", self._path
            )
            return
        for entry in data:
            try:
                draft = PolicyDraft.model_validate(entry)
            except Exception as exc:  # noqa: BLE001
                logger.warning("skipping malformed draft entry: %r (%r)", entry, exc)
                continue
            self._drafts[draft.draft_id] = draft

    def _persist(self) -> None:
        tmp = self._path.with_suffix(".json.tmp")
        payload = [d.model_dump(mode="json") for d in self._drafts.values()]
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        os.replace(tmp, self._path)


def _build_modify_rule_yaml(
    *,
    rule_id: str,
    description: str,
    untrusted_hosts: list[str],
) -> str:
    """Render a YAML snippet for an egress MODIFY rule.

    Result is a *diff*-style block — the leading ``# +`` markers signal lines
    the operator should add. The block is also valid YAML so the operator
    can paste it into ``configs/default_policy.yaml`` under ``egress.rules``.
    """
    rule_obj = {
        "rule_id": rule_id,
        "description": description,
        "match": {
            "field": "egress.contains_markdown_image_with_external_url",
            "op": "equals",
            "value": True,
        },
        "exclude": {
            "field": "egress.target_domains",
            "op": "any_in",
            "value": ["corp-internal.example.com"],
        },
        "action": {
            "kind": "MODIFY",
            "strategy": "strip_markdown_images_to_untrusted_domains",
            "untrusted_hosts": untrusted_hosts,
        },
    }
    body = yaml.safe_dump(
        {"egress": {"rules": [rule_obj]}},
        sort_keys=False,
    )
    diff_lines = ["# DAST-A-generated policy draft — paste into default_policy.yaml"]
    for line in body.splitlines():
        diff_lines.append(f"+ {line}")
    return "\n".join(diff_lines)


def build_draft_from_episode(
    episode: EpisodeResult,
    *,
    proposed_pack_id: Optional[str] = None,
    extra_episode_ids: Optional[list[str]] = None,
) -> PolicyDraft:
    """Construct a :class:`PolicyDraft` from one unblocked successful episode.

    The proposed YAML diff targets the markdown-image exfil pattern A-4 already
    has a MODIFY action for; the diff just registers a fresh rule (with a fresh
    ``rule_id``) so the operator can see what DAST-A would add.
    """
    rule_id = f"dast_a_modify_{secrets.token_hex(4)}"
    description = (
        "DAST-A discovered a markdown-image egress carrying the internal "
        "secret to an untrusted host. MODIFY rule strips the image."
    )
    host = episode.exfil_destination or "attacker.example.com"
    diff = _build_modify_rule_yaml(
        rule_id=rule_id,
        description=description,
        untrusted_hosts=[host],
    )
    now = dt.datetime.now(tz=dt.timezone.utc)
    rationale = (
        f"Episode {episode.episode_id} produced a markdown-image exfil to "
        f"{host!s} via signature {episode.payload_signature!r}. Reef's "
        "live policy did not block this; the suggested MODIFY rule covers "
        "the rendered payload."
    )
    return PolicyDraft(
        draft_id=f"draft-{secrets.token_hex(8)}",
        title=f"MODIFY rule for {host}",
        rationale=rationale,
        suggested_yaml_diff=diff,
        evidence_episodes=[episode.episode_id, *(extra_episode_ids or [])],
        proposed_pack_id=proposed_pack_id,
        status=DraftStatus.PENDING,
        created_at=now,
        updated_at=now,
    )
