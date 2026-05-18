"""POST /dast-a/run — kick off N adversarial episodes."""
from __future__ import annotations

import datetime as dt
import logging
import threading
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.agent import EpisodeRunConfig, EpisodeRunner, RunSummary
from app.env.injection_env import InjectionEnv
from app.packs.schema import (
    AttackPack,
    MitreAtlasTag,
    OwaspAsiTag,
    PackDiscoveryEvidence,
    PackSource,
)
from app.review import build_draft_from_episode

logger = logging.getLogger("dast_a.api.run")

router = APIRouter(prefix="/dast-a")


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    episodes: int = Field(default=30, ge=1, le=10_000)
    checkpoint: str = Field(default="auto")
    victim_url: Optional[str] = None
    reef_on: bool = False
    deterministic: bool = False
    use_stub_victim: Optional[bool] = None
    max_steps: int = Field(default=15, ge=1, le=200)


class EpisodeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    episode_id: str
    total_reward: float
    steps: int
    exfil_success: bool
    blocked_by_reef: bool
    payload_excerpt: Optional[str]
    payload_signature: Optional[str]
    exfil_destination: Optional[str]
    mutations: list[str]


class RunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    started_at: dt.datetime
    finished_at: dt.datetime
    summary: dict
    episodes: list[EpisodeRecord]
    drafts_created: list[str]
    packs_created: list[str]


_ASYNC_RUNS: dict[str, dict] = {}
_ASYNC_LOCK = threading.RLock()


def _run_to_response(
    summary: RunSummary,
    *,
    drafts_created: list[str],
    packs_created: list[str],
) -> RunResponse:
    episodes_payload = [
        EpisodeRecord(
            episode_id=r.episode_id,
            total_reward=r.total_reward,
            steps=r.steps,
            exfil_success=r.exfil_success,
            blocked_by_reef=r.blocked_by_reef,
            payload_excerpt=r.payload_excerpt,
            payload_signature=r.payload_signature,
            exfil_destination=r.exfil_destination,
            mutations=r.mutations,
        )
        for r in summary.results
    ]
    summary_payload = {
        "episodes": summary.episodes,
        "successes": summary.successes,
        "blocks": summary.blocks,
        "block_rate": summary.block_rate,
        "success_rate": summary.success_rate,
        "mean_reward": summary.mean_reward,
        "unique_payload_signatures": summary.unique_payload_signatures,
        "by_template": summary.by_template,
        "novel_unblocked_count": len(summary.novel_unblocked),
    }
    return RunResponse(
        run_id=summary.run_id,
        started_at=summary.started_at,
        finished_at=summary.finished_at,
        summary=summary_payload,
        episodes=episodes_payload,
        drafts_created=drafts_created,
        packs_created=packs_created,
    )


def _execute_run(request: Request, body: RunRequest) -> RunResponse:
    catalog = request.app.state.catalog
    drafts_store = request.app.state.drafts
    auditor = request.app.state.auditor
    checkpoints = request.app.state.checkpoints

    use_stub = body.use_stub_victim
    if use_stub is None:
        use_stub = bool(getattr(request.app.state, "default_use_stub", False))

    discovered_signatures = catalog.signatures()

    def _env_factory() -> InjectionEnv:
        return InjectionEnv(
            victim_url=body.victim_url
            or getattr(request.app.state, "victim_url", "http://localhost:3001"),
            max_steps=body.max_steps,
            reef_on=body.reef_on,
            use_stub_victim=use_stub,
            discovered_signatures=discovered_signatures,
        )

    runner = EpisodeRunner(
        env_factory=_env_factory,
        checkpoint_store=checkpoints,
        auditor=auditor,
    )
    config = EpisodeRunConfig(
        episodes=body.episodes,
        checkpoint=body.checkpoint,
        victim_url=body.victim_url
        or getattr(request.app.state, "victim_url", "http://localhost:3001"),
        reef_on=body.reef_on,
        use_stub_victim=use_stub,
        deterministic=body.deterministic,
        max_steps=body.max_steps,
        discovered_signatures=discovered_signatures,
    )
    summary = runner.run(config)

    drafts_created: list[str] = []
    packs_created: list[str] = []
    seen_signatures: set[str] = set()
    for episode in summary.novel_unblocked:
        if not episode.exfil_success or episode.blocked_by_reef:
            continue
        sig = episode.payload_signature or ""
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)
        pack_id = f"DAST-A-RL-{summary.run_id.split('-', 1)[1][:6]}-{sig[:6] or 'na'}"
        pack = AttackPack(
            pack_id=pack_id,
            name=f"RL-discovered exfil to {episode.exfil_destination or 'unknown host'}",
            source=PackSource.DAST_A_SYNTHETIC,
            discovered_by="DAST-A (synthetic — RL search against test fixture)",
            cve_mapping="no-cve (RL-found template)",
            owasp_asi=[OwaspAsiTag.ASI09],
            mitre_atlas=[MitreAtlasTag.AML_T0051],
            trigger_template=(episode.payload_excerpt or "")[:512],
            victim_signal="egress.contains_markdown_image_with_external_url",
            reef_policy_signal="MODIFY: strip markdown images to untrusted domains",
            discovered_at=dt.datetime.now(tz=dt.timezone.utc),
            exemplar_request_id=episode.episode_id,
            successful_episodes=1,
            blocked_by_reef=False,
            evidence=PackDiscoveryEvidence(
                episode_id=episode.episode_id,
                payload_signature=sig or None,
                payload_excerpt=(episode.payload_excerpt or None),
                blocked_by_reef=False,
            ),
        )
        if catalog.put_if_absent(pack):
            packs_created.append(pack_id)
            auditor.log(
                "pack_added_from_episode",
                {
                    "pack_id": pack_id,
                    "run_id": summary.run_id,
                    "episode_id": episode.episode_id,
                },
            )
        draft = build_draft_from_episode(
            episode, proposed_pack_id=pack_id
        )
        drafts_store.add(draft)
        drafts_created.append(draft.draft_id)
        auditor.log(
            "draft_created",
            {
                "draft_id": draft.draft_id,
                "proposed_pack_id": pack_id,
                "episode_id": episode.episode_id,
            },
        )

    return _run_to_response(
        summary, drafts_created=drafts_created, packs_created=packs_created
    )


@router.post("/run")
def post_run(
    body: RunRequest,
    request: Request,
    background: BackgroundTasks,
    async_run: bool = Query(default=False, alias="async"),
) -> dict:
    if async_run:
        run_handle = f"pending-{int(dt.datetime.now(tz=dt.timezone.utc).timestamp())}"
        with _ASYNC_LOCK:
            _ASYNC_RUNS[run_handle] = {"status": "scheduled"}

        def _bg() -> None:
            try:
                response = _execute_run(request, body)
                with _ASYNC_LOCK:
                    _ASYNC_RUNS[run_handle] = {
                        "status": "completed",
                        "response": response.model_dump(mode="json"),
                    }
            except Exception as exc:  # noqa: BLE001 - persist for polling
                logger.exception("async run failed: %r", exc)
                with _ASYNC_LOCK:
                    _ASYNC_RUNS[run_handle] = {
                        "status": "error",
                        "error": repr(exc),
                    }

        background.add_task(_bg)
        return {"run_handle": run_handle, "status": "scheduled"}

    return _execute_run(request, body).model_dump(mode="json")


@router.get("/run/{run_handle}")
def get_run(run_handle: str) -> dict:
    with _ASYNC_LOCK:
        state = _ASYNC_RUNS.get(run_handle)
    if state is None:
        raise HTTPException(status_code=404, detail=f"run {run_handle!r} not found")
    return {"run_handle": run_handle, **state}
