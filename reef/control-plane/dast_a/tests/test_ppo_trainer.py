"""PPO trainer sanity test.

This test runs a tiny training loop (≤2 000 timesteps) to verify the trainer
converges without errors. It's NOT meant to produce a high-quality policy
in this budget — that's the pre-training pass owned by ``scripts/train.py``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.agent import (
    CheckpointStore,
    PPOTrainConfig,
    PPOTrainer,
)
from app.env.injection_env import InjectionEnv


@pytest.mark.slow
def test_ppo_trainer_runs_and_saves(tmp_dast_a_dirs: dict) -> None:
    checkpoints_dir = tmp_dast_a_dirs["checkpoints_dir"]
    store = CheckpointStore(checkpoints_dir=checkpoints_dir)
    config = PPOTrainConfig(
        learn_timesteps=2_000,
        n_steps=256,
        batch_size=64,
        n_epochs=2,
        verbose=0,
        checkpoint_name="test_baseline.zip",
    )
    trainer = PPOTrainer(
        env_factory=lambda: InjectionEnv(use_stub_victim=True, max_steps=12),
        config=config,
        checkpoint_store=store,
    )
    result = trainer.train()
    assert result.timesteps == 2_000
    assert store.exists("test_baseline.zip")
    saved_path = Path(result.checkpoint_path)
    assert saved_path.is_file()
    # Checkpoint should be small (MLP policy on 12-d obs × 24 actions).
    assert saved_path.stat().st_size < 2_000_000  # < 2 MB
