"""Gemini red-team + blue-team API surfaces (A-9).

* ``POST /dast-a/red-team/gemini-run`` — Run a Gemini-Pro-driven red-team
  session via Playwright. Returns a :class:`SessionResult` shaped like the
  PPO ``RunResponse`` so the review-queue UI consumes both uniformly.
* ``POST /dast-a/blue-team/observe`` — Server-sent event stream of blue-team
  policy drafts derived from a given ``episode_id`` or run identifier. Each
  emitted draft is also persisted to the :class:`DraftStore` so the
  ``/dast-a/review-queue`` endpoint will surface it.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import os
import secrets
from typing import AsyncIterator, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from app.agent.gemini_blue import (
    GeminiBlueTeam,
    GeminiBlueTeamError,
    MissingGeminiAPIKey as BlueMissingGeminiAPIKey,
    MissingGeminiFlashModel,
    GeminiCallFailed as BlueGeminiCallFailed,
    PolicyDraft as BluePolicyDraft,
    TraceEvent,
    trace_source_from_list,
)
from app.agent.gemini_red import (
    GeminiRedTeam,
    GeminiRedTeamError,
    MissingGeminiAPIKey as RedMissingGeminiAPIKey,
    MissingGeminiProModel,
    GeminiCallFailed as RedGeminiCallFailed,
    BrowserCallFailed,
    SessionResult,
)
from app.review.draft import (
    DraftStatus,
    PolicyDraft as StoredPolicyDraft,
)

logger = logging.getLogger("dast_a.api.gemini")

router = APIRouter(prefix="/dast-a")


# ---------------------------------------------------------------------------
# Red-team
# ---------------------------------------------------------------------------


class GeminiRedRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    victim_url: Optional[str] = None
    max_rounds: int = Field(default=5, ge=1, le=50)
    reef_on: bool = False
    stop_on_success: bool = True


class GeminiRoundRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    round_index: int
    template: str
    host: str
    encoding: str
    payload_excerpt: str
    browser_status_code: int
    exfil_succeeded: bool
    exfil_destination: Optional[str]
    exfil_url: Optional[str]
    secret_fragment_visible: bool
    reasoning: str
    payload_signature: str


class GeminiRedRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    started_at: dt.datetime
    finished_at: dt.datetime
    victim_url: str
    reef_on: bool
    succeeded: bool
    first_success_round: Optional[int]
    pro_call_count: int
    novel_signatures: list[str]
    rounds: list[GeminiRoundRecord]


def _session_to_response(session: SessionResult) -> GeminiRedRunResponse:
    rounds = [
        GeminiRoundRecord(
            round_index=r.round_index,
            template=r.template,
            host=r.host,
            encoding=r.encoding,
            payload_excerpt=r.payload[:512],
            browser_status_code=r.browser_status_code,
            exfil_succeeded=r.exfil_succeeded,
            exfil_destination=r.exfil_destination,
            exfil_url=r.exfil_url,
            secret_fragment_visible=r.secret_fragment_visible,
            reasoning=r.reasoning,
            payload_signature=r.payload_signature,
        )
        for r in session.rounds
    ]
    return GeminiRedRunResponse(
        session_id=session.session_id,
        started_at=session.started_at,
        finished_at=session.finished_at,
        victim_url=session.victim_url,
        reef_on=session.reef_on,
        succeeded=session.succeeded,
        first_success_round=session.first_success_round,
        pro_call_count=session.pro_call_count,
        novel_signatures=session.novel_signatures,
        rounds=rounds,
    )


def _red_team_factory(request: Request) -> GeminiRedTeam:
    """Build a GeminiRedTeam.

    Tests may install a factory override on ``app.state.gemini_red_factory``
    to inject mocks; production uses the default constructor which reads
    env-config from :class:`GoogleGenAIProClient` /
    :class:`PlaywrightBrowserDriver`.
    """
    factory = getattr(request.app.state, "gemini_red_factory", None)
    if factory is not None:
        return factory()
    catalog = request.app.state.catalog
    return GeminiRedTeam(discovered_signatures=tuple(catalog.signatures()))


@router.post("/red-team/gemini-run", response_model=GeminiRedRunResponse)
def post_red_team_run(
    body: GeminiRedRunRequest, request: Request
) -> GeminiRedRunResponse:
    try:
        red = _red_team_factory(request)
    except RedMissingGeminiAPIKey as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "MISSING_GEMINI_API_KEY", "message": str(exc)},
        ) from exc
    except MissingGeminiProModel as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "MISSING_GEMINI_PRO_MODEL", "message": str(exc)},
        ) from exc
    except (RedGeminiCallFailed, BrowserCallFailed) as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": exc.code, "message": str(exc)},
        ) from exc
    except GeminiRedTeamError as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": exc.code, "message": str(exc)},
        ) from exc

    victim_url = body.victim_url or getattr(
        request.app.state, "victim_url", "http://localhost:3001"
    )
    try:
        session = red.run_session(
            victim_url=victim_url,
            max_rounds=body.max_rounds,
            reef_on=body.reef_on,
            stop_on_success=body.stop_on_success,
        )
    except (RedMissingGeminiAPIKey, MissingGeminiProModel) as exc:
        # Possible if the factory deferred client construction to run_session.
        raise HTTPException(
            status_code=503,
            detail={"error": exc.code, "message": str(exc)},
        ) from exc
    except BrowserCallFailed as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": exc.code, "message": str(exc)},
        ) from exc
    except RedGeminiCallFailed as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": exc.code, "message": str(exc)},
        ) from exc
    except GeminiRedTeamError as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": exc.code, "message": str(exc)},
        ) from exc

    auditor = request.app.state.auditor
    auditor.log(
        "gemini_red_session",
        {
            "session_id": session.session_id,
            "victim_url": session.victim_url,
            "reef_on": session.reef_on,
            "rounds": len(session.rounds),
            "succeeded": session.succeeded,
            "first_success_round": session.first_success_round,
            "pro_call_count": session.pro_call_count,
            "novel_signatures": session.novel_signatures,
        },
    )
    return _session_to_response(session)


# ---------------------------------------------------------------------------
# Blue-team
# ---------------------------------------------------------------------------


class GeminiBlueObserveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    episode_id: Optional[str] = Field(
        default=None,
        description=(
            "If provided, only events matching this episode/session/run "
            "identifier are pulled from the audit tail."
        ),
    )
    max_events: int = Field(default=50, ge=1, le=500)
    emit_on_blocked: bool = False


def _trace_events_from_audit(
    request: Request, *, episode_id: Optional[str], max_events: int
) -> list[TraceEvent]:
    """Reconstruct trace events from the audit-log tail."""
    auditor = request.app.state.auditor
    events = auditor.tail(max_lines=max(max_events * 4, 200))
    out: list[TraceEvent] = []
    for ev in events:
        if ev.kind != "episode":
            continue
        payload = ev.payload or {}
        if episode_id is not None and payload.get("episode_id") != episode_id:
            # We also tolerate run_id matches so a caller can observe a
            # whole run instead of a single episode.
            if payload.get("run_id") != episode_id:
                continue
        out.append(
            TraceEvent(
                event_id=str(payload.get("episode_id") or secrets.token_hex(6)),
                timestamp=ev.timestamp,
                source="ppo",
                template=None,
                payload_excerpt=payload.get("payload_excerpt"),
                payload_signature=payload.get("payload_signature"),
                exfil_succeeded=bool(payload.get("exfil_success", False)),
                blocked_by_reef=bool(payload.get("blocked_by_reef", False)),
                exfil_destination=None,
                extra={
                    "run_id": payload.get("run_id"),
                    "checkpoint": payload.get("checkpoint"),
                    "total_reward": payload.get("total_reward"),
                },
            )
        )
        if len(out) >= max_events:
            break
    return out


def _blue_team_factory(request: Request, *, emit_on_blocked: bool) -> GeminiBlueTeam:
    factory = getattr(request.app.state, "gemini_blue_factory", None)
    if factory is not None:
        return factory(emit_on_blocked)
    return GeminiBlueTeam(emit_on_blocked=emit_on_blocked)


def _persist_blue_draft(request: Request, draft: BluePolicyDraft) -> StoredPolicyDraft:
    """Persist a blue-team draft into the existing DraftStore.

    Drafts default to ``DraftStatus.PENDING`` per D-018 (advisory only,
    operator approval gates promotion to A-4's HUMAN_REVIEW webhook).
    """
    drafts_store = request.app.state.drafts
    now = dt.datetime.now(tz=dt.timezone.utc)
    stored = StoredPolicyDraft(
        draft_id=f"draft-{secrets.token_hex(8)}",
        title=f"Blue-team {draft.action} — {draft.rule_id_hint}",
        rationale=draft.justification,
        suggested_yaml_diff=draft.suggested_yaml_diff,
        evidence_episodes=list(draft.evidence_event_ids),
        proposed_pack_id=None,
        status=DraftStatus.PENDING,
        created_at=now,
        updated_at=now,
    )
    drafts_store.add(stored)
    auditor = request.app.state.auditor
    auditor.log(
        "blue_team_draft_created",
        {
            "draft_id": stored.draft_id,
            "rule_id_hint": draft.rule_id_hint,
            "action": draft.action,
            "evidence_event_ids": draft.evidence_event_ids,
            "advisory": draft.advisory,
        },
    )
    return stored


@router.post("/blue-team/observe")
def post_blue_team_observe(
    body: GeminiBlueObserveRequest, request: Request
) -> StreamingResponse:
    """SSE-stream policy drafts derived from past episode trace events.

    Drafts auto-populate the review queue as they're emitted. The SSE
    surface lets the Stage UI live-render the blue-team output during a
    demo recording.
    """
    try:
        observer = _blue_team_factory(request, emit_on_blocked=body.emit_on_blocked)
    except BlueMissingGeminiAPIKey as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "MISSING_GEMINI_API_KEY", "message": str(exc)},
        ) from exc
    except MissingGeminiFlashModel as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "MISSING_GEMINI_FLASH_MODEL", "message": str(exc)},
        ) from exc
    except GeminiBlueTeamError as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": exc.code, "message": str(exc)},
        ) from exc

    events = _trace_events_from_audit(
        request,
        episode_id=body.episode_id,
        max_events=body.max_events,
    )

    async def _stream() -> AsyncIterator[bytes]:
        if not events:
            yield b": no matching trace events\n\n"
            return
        trace_source = trace_source_from_list(events)
        try:
            async for draft in observer.start_observer(trace_source):
                stored = _persist_blue_draft(request, draft)
                line = (
                    "event: policy_draft\ndata: "
                    + StoredPolicyDraft.model_validate(stored).model_dump_json()
                    + "\n\n"
                )
                yield line.encode("utf-8")
        except (
            BlueMissingGeminiAPIKey,
            MissingGeminiFlashModel,
            BlueGeminiCallFailed,
        ) as exc:
            payload = (
                "event: error\ndata: "
                + f'{{"error": "{exc.code}", "message": "{str(exc).replace(chr(34), chr(39))}"}}'
                + "\n\n"
            )
            yield payload.encode("utf-8")

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
