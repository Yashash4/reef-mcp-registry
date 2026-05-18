"""Interactive run loop — load a checkpoint, drive N episodes, log results."""
from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import secrets
import threading
import uuid
from typing import Callable, Optional

import numpy as np
from stable_baselines3 import PPO

from app.agent.checkpoint import (
    CheckpointNotFound,
    CheckpointStore,
    DEFAULT_CHECKPOINT_NAME,
)
from app.audit.logger import AuditLogger
from app.env.injection_env import InjectionEnv

logger = logging.getLogger("dast_a.agent.run")


@dataclasses.dataclass
class EpisodeRunConfig:
    episodes: int = 30
    checkpoint: str = "auto"  # "auto" → DEFAULT_CHECKPOINT_NAME if present
    victim_url: str = "http://localhost:3001"
    reef_on: bool = False
    use_stub_victim: bool = False
    deterministic: bool = False
    max_steps: int = 15
    discovered_signatures: tuple[str, ...] = ()


@dataclasses.dataclass
class EpisodeResult:
    episode_id: str
    total_reward: float
    steps: int
    exfil_success: bool
    blocked_by_reef: bool
    payload_excerpt: Optional[str]
    payload_signature: Optional[str]
    exfil_destination: Optional[str]
    mutations: list[str]


@dataclasses.dataclass
class RunSummary:
    run_id: str
    started_at: dt.datetime
    finished_at: dt.datetime
    episodes: int
    successes: int
    blocks: int
    block_rate: float
    success_rate: float
    mean_reward: float
    unique_payload_signatures: int
    by_template: dict[str, int]
    novel_unblocked: list[EpisodeResult]
    results: list[EpisodeResult]


class EpisodeRunner:
    """Loads (or skips) a checkpoint and drives N episodes of the env."""

    def __init__(
        self,
        env_factory: Callable[[InjectionEnv], InjectionEnv] | Callable[[], InjectionEnv],
        checkpoint_store: Optional[CheckpointStore] = None,
        auditor: Optional[AuditLogger] = None,
    ) -> None:
        self._env_factory = env_factory
        self._checkpoints = checkpoint_store or CheckpointStore()
        self._auditor = auditor

    def run(self, config: EpisodeRunConfig) -> RunSummary:
        env = self._env_factory()
        if not isinstance(env, InjectionEnv):
            raise TypeError(
                "env_factory must return an InjectionEnv instance; got "
                f"{type(env).__name__}"
            )

        model: Optional[PPO] = None
        checkpoint_label = config.checkpoint
        try:
            if config.checkpoint == "auto":
                if self._checkpoints.exists(DEFAULT_CHECKPOINT_NAME):
                    model = self._checkpoints.load(env, name=DEFAULT_CHECKPOINT_NAME)
                    checkpoint_label = DEFAULT_CHECKPOINT_NAME
                else:
                    logger.info(
                        "no checkpoint at %s; running with a random policy "
                        "(use --checkpoint or POST /dast-a/run with a path)",
                        self._checkpoints.path_for(DEFAULT_CHECKPOINT_NAME),
                    )
                    checkpoint_label = "<random>"
            elif config.checkpoint and config.checkpoint != "random":
                model = self._checkpoints.load(env, name=config.checkpoint)
        except CheckpointNotFound:
            logger.warning(
                "checkpoint %r not found; using a random policy", config.checkpoint
            )
            checkpoint_label = "<random-fallback>"

        run_id = f"run-{secrets.token_hex(8)}"
        started = dt.datetime.now(tz=dt.timezone.utc)
        results: list[EpisodeResult] = []
        successes = 0
        blocks = 0
        rewards: list[float] = []
        by_template: dict[str, int] = {}
        seen_signatures: set[str] = set()
        novel_unblocked: list[EpisodeResult] = []

        for _ in range(config.episodes):
            ep_id = f"ep-{uuid.uuid4().hex[:12]}"
            obs, _ = env.reset()
            terminated = False
            truncated = False
            ep_reward = 0.0
            steps = 0
            mutations_taken: list[str] = []
            ep_exfil = False
            ep_blocked = False
            ep_payload_excerpt: Optional[str] = None
            ep_signature: Optional[str] = None
            ep_destination: Optional[str] = None

            while not (terminated or truncated):
                if model is not None:
                    action_arr, _ = model.predict(
                        obs, deterministic=config.deterministic
                    )
                    action = int(np.asarray(action_arr).item())
                else:
                    action = int(env.action_space.sample())
                obs, reward, terminated, truncated, info = env.step(action)
                ep_reward += reward
                steps += 1
                mutations_taken.append(str(info.get("mutation", "?")))
                if info.get("sent_this_step"):
                    response = info.get("response", {}) or {}
                    if response.get("exfil_detected"):
                        ep_exfil = True
                        ep_payload_excerpt = (info.get("payload") or "")[:512]
                        ep_destination = response.get("exfil_destination")
                    if response.get("blocked_by_reef"):
                        ep_blocked = True
                    sigs = info.get("episode_signatures") or ()
                    if sigs:
                        ep_signature = str(sigs[-1])
                        # Crude template fingerprint = first letter set after t=
                        try:
                            template_idx = int(sigs[-1].split("t=")[1].split("|")[0])
                            from app.env.injection_env import TEMPLATES

                            template_name = TEMPLATES[template_idx] if 0 <= template_idx < len(TEMPLATES) else "?"
                            by_template[template_name] = by_template.get(
                                template_name, 0
                            ) + 1
                        except (ValueError, IndexError):
                            pass

            rewards.append(ep_reward)
            if ep_exfil:
                successes += 1
            if ep_blocked:
                blocks += 1
            result = EpisodeResult(
                episode_id=ep_id,
                total_reward=ep_reward,
                steps=steps,
                exfil_success=ep_exfil,
                blocked_by_reef=ep_blocked,
                payload_excerpt=ep_payload_excerpt,
                payload_signature=ep_signature,
                exfil_destination=ep_destination,
                mutations=mutations_taken,
            )
            results.append(result)
            if ep_signature:
                seen_signatures.add(ep_signature)
            if (
                ep_exfil
                and not ep_blocked
                and ep_signature is not None
                and ep_signature not in config.discovered_signatures
            ):
                novel_unblocked.append(result)
            if self._auditor:
                self._auditor.log(
                    "episode",
                    {
                        "run_id": run_id,
                        "episode_id": ep_id,
                        "checkpoint": checkpoint_label,
                        "reef_on": config.reef_on,
                        "total_reward": ep_reward,
                        "exfil_success": ep_exfil,
                        "blocked_by_reef": ep_blocked,
                        "payload_signature": ep_signature,
                        "payload_excerpt": ep_payload_excerpt,
                    },
                )

        env.close()
        finished = dt.datetime.now(tz=dt.timezone.utc)
        episodes_n = max(1, config.episodes)
        summary = RunSummary(
            run_id=run_id,
            started_at=started,
            finished_at=finished,
            episodes=config.episodes,
            successes=successes,
            blocks=blocks,
            block_rate=blocks / episodes_n,
            success_rate=successes / episodes_n,
            mean_reward=float(np.mean(rewards)) if rewards else 0.0,
            unique_payload_signatures=len(seen_signatures),
            by_template=by_template,
            novel_unblocked=novel_unblocked,
            results=results,
        )
        if self._auditor:
            self._auditor.log(
                "run_summary",
                {
                    "run_id": run_id,
                    "episodes": summary.episodes,
                    "successes": summary.successes,
                    "blocks": summary.blocks,
                    "block_rate": summary.block_rate,
                    "success_rate": summary.success_rate,
                    "mean_reward": summary.mean_reward,
                    "unique_signatures": summary.unique_payload_signatures,
                    "by_template": summary.by_template,
                    "novel_unblocked_count": len(summary.novel_unblocked),
                    "reef_on": config.reef_on,
                    "checkpoint": checkpoint_label,
                },
            )
        return summary
