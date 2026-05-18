"""Stable-baselines3 PPO trainer for the DAST-A adversary."""
from __future__ import annotations

import dataclasses
import logging
from typing import Callable, Optional

import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback
from stable_baselines3.common.monitor import Monitor
from stable_baselines3.common.vec_env import DummyVecEnv

from app.agent.checkpoint import CheckpointStore, DEFAULT_CHECKPOINT_NAME
from app.env.injection_env import InjectionEnv

logger = logging.getLogger("dast_a.agent.ppo")


@dataclasses.dataclass
class PPOTrainConfig:
    """Hyperparameters for one PPO training run.

    Defaults are tuned for a small CPU machine — the demo / CI run uses
    fewer timesteps (``learn_timesteps`` ~10k); the full pre-training pass
    raises this to 30k+ but stays under a few minutes on CPU.
    """

    learn_timesteps: int = 10_000
    learning_rate: float = 3e-4
    n_steps: int = 256
    batch_size: int = 64
    n_epochs: int = 4
    gamma: float = 0.99
    gae_lambda: float = 0.95
    clip_range: float = 0.2
    ent_coef: float = 0.01
    verbose: int = 1
    seed: int = 42
    policy: str = "MlpPolicy"
    checkpoint_name: str = DEFAULT_CHECKPOINT_NAME
    log_interval: int = 1


@dataclasses.dataclass
class TrainingResult:
    """Summary returned by :meth:`PPOTrainer.train`."""

    timesteps: int
    final_episode_reward_mean: float
    episodes_observed: int
    checkpoint_path: str


class _RewardTracker(BaseCallback):
    """Tracks per-rollout episode rewards without spamming stdout."""

    def __init__(self) -> None:
        super().__init__(verbose=0)
        self.episode_rewards: list[float] = []
        self.last_reward: float = 0.0

    def _on_step(self) -> bool:
        infos = self.locals.get("infos") or []
        for info in infos:
            ep_info = info.get("episode") if isinstance(info, dict) else None
            if ep_info and "r" in ep_info:
                self.episode_rewards.append(float(ep_info["r"]))
                self.last_reward = float(ep_info["r"])
        return True


class PPOTrainer:
    """Wraps PPO so the API / CLI / tests can train + save in one call."""

    def __init__(
        self,
        env_factory: Callable[[], InjectionEnv],
        config: Optional[PPOTrainConfig] = None,
        checkpoint_store: Optional[CheckpointStore] = None,
    ) -> None:
        self._env_factory = env_factory
        self.config = config or PPOTrainConfig()
        self._checkpoints = checkpoint_store or CheckpointStore()

    def _build_vec_env(self) -> DummyVecEnv:
        def _make() -> Monitor:
            return Monitor(self._env_factory())

        return DummyVecEnv([_make])

    def train(
        self,
        *,
        resume_from: Optional[str] = None,
        seed: Optional[int] = None,
    ) -> TrainingResult:
        """Run a training pass, save the checkpoint, return the summary."""
        vec_env = self._build_vec_env()
        seed_val = seed if seed is not None else self.config.seed
        try:
            if resume_from and self._checkpoints.exists(resume_from):
                model = self._checkpoints.load(vec_env, name=resume_from)
                logger.info("resumed PPO from %s", resume_from)
            else:
                model = PPO(
                    self.config.policy,
                    vec_env,
                    learning_rate=self.config.learning_rate,
                    n_steps=self.config.n_steps,
                    batch_size=self.config.batch_size,
                    n_epochs=self.config.n_epochs,
                    gamma=self.config.gamma,
                    gae_lambda=self.config.gae_lambda,
                    clip_range=self.config.clip_range,
                    ent_coef=self.config.ent_coef,
                    verbose=self.config.verbose,
                    seed=seed_val,
                )
            tracker = _RewardTracker()
            model.learn(
                total_timesteps=self.config.learn_timesteps,
                callback=tracker,
                log_interval=self.config.log_interval,
            )
            path = self._checkpoints.save(model, name=self.config.checkpoint_name)
            rewards = tracker.episode_rewards
            final_mean = float(np.mean(rewards[-20:])) if rewards else 0.0
            logger.info(
                "PPO training complete: %d timesteps, %d episodes observed, "
                "mean reward (last 20) = %.3f",
                self.config.learn_timesteps,
                len(rewards),
                final_mean,
            )
            return TrainingResult(
                timesteps=self.config.learn_timesteps,
                final_episode_reward_mean=final_mean,
                episodes_observed=len(rewards),
                checkpoint_path=str(path),
            )
        finally:
            vec_env.close()
