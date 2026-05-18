"""Pre-train the DAST-A baseline PPO checkpoint against the stub victim.

Usage::

    python scripts/train_baseline.py

The output is committed to ``checkpoints/dast_a_baseline.zip``. The script is
idempotent — if a checkpoint already exists, the run resumes from it.
"""
from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

# Allow running this script directly from the dast_a root without an install.
import sys
HERE = Path(__file__).resolve().parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


from app.agent import (  # noqa: E402
    CheckpointStore,
    DEFAULT_CHECKPOINT_NAME,
    PPOTrainConfig,
    PPOTrainer,
)
from app.env.injection_env import InjectionEnv  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--timesteps",
        type=int,
        default=int(os.environ.get("REEF_DAST_A_PRETRAIN_TIMESTEPS", "12000")),
    )
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument(
        "--checkpoints-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "checkpoints",
    )
    parser.add_argument(
        "--name",
        type=str,
        default=DEFAULT_CHECKPOINT_NAME,
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--reef-on",
        action="store_true",
        help=(
            "Train against the Reef-blocked stub. Default is reef_off (the "
            "adversary learns to find exfil paths before Reef is wired in)."
        ),
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s %(message)s",
    )
    log = logging.getLogger("dast_a.train_baseline")

    store = CheckpointStore(checkpoints_dir=args.checkpoints_dir)

    config = PPOTrainConfig(
        learn_timesteps=args.timesteps,
        n_steps=512,
        batch_size=64,
        n_epochs=4,
        learning_rate=3e-4,
        gamma=0.99,
        ent_coef=0.02,
        verbose=1,
        seed=args.seed,
        checkpoint_name=args.name,
    )

    def _make_env() -> InjectionEnv:
        return InjectionEnv(
            use_stub_victim=True,
            reef_on=args.reef_on,
            max_steps=args.max_steps,
            seed=args.seed,
        )

    trainer = PPOTrainer(_make_env, config=config, checkpoint_store=store)
    resume = args.name if store.exists(args.name) else None
    if resume:
        log.info("resuming from existing checkpoint %s", resume)
    result = trainer.train(resume_from=resume)
    log.info(
        "training done: timesteps=%d, episodes=%d, mean reward (last 20)=%.3f, "
        "checkpoint=%s",
        result.timesteps,
        result.episodes_observed,
        result.final_episode_reward_mean,
        result.checkpoint_path,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
