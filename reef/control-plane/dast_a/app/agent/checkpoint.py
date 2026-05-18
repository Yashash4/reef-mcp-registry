"""Save / load PPO checkpoints to disk."""
from __future__ import annotations

import logging
import os
import shutil
import threading
from pathlib import Path
from typing import Optional

from stable_baselines3 import PPO

logger = logging.getLogger("dast_a.agent.checkpoint")

DEFAULT_CHECKPOINT_NAME = "dast_a_baseline.zip"


class CheckpointNotFound(FileNotFoundError):
    """Raised when ``CheckpointStore.load`` cannot find the requested file."""


class CheckpointStore:
    """Mutex-protected wrapper around PPO checkpoint files.

    The store is intentionally thin — PPO ships its own
    ``save``/``load`` to disk. We add atomic write semantics (write to
    ``.tmp`` then rename) and consistent path handling so the rest of the
    code only needs a checkpoint name, not a path.
    """

    def __init__(self, checkpoints_dir: Optional[Path | str] = None) -> None:
        self._lock = threading.RLock()
        self._dir = Path(
            checkpoints_dir
            or os.environ.get("REEF_DAST_A_CHECKPOINTS_DIR", "./checkpoints")
        ).resolve()
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def directory(self) -> Path:
        return self._dir

    def path_for(self, name: str = DEFAULT_CHECKPOINT_NAME) -> Path:
        if not name.endswith(".zip"):
            name = name + ".zip"
        return self._dir / name

    def exists(self, name: str = DEFAULT_CHECKPOINT_NAME) -> bool:
        return self.path_for(name).is_file()

    def save(self, model: PPO, name: str = DEFAULT_CHECKPOINT_NAME) -> Path:
        """Write the PPO model to ``name`` atomically. Returns the saved path."""
        target = self.path_for(name)
        with self._lock:
            # PPO.save appends ``.zip`` ONLY when its argument has no suffix
            # at all (Path.suffix == ""). Use an extensionless tmp stem
            # ``<basename>_tmp`` so the produced file is ``<basename>_tmp.zip``
            # — then atomically rename it onto the target.
            tmp_stem = target.parent / (target.stem + "_tmp")
            tmp_zip = tmp_stem.with_suffix(".zip")
            for stale in (tmp_stem, tmp_zip):
                if stale.exists():
                    stale.unlink()
            model.save(str(tmp_stem))
            if not tmp_zip.exists():
                raise OSError(
                    f"PPO.save did not produce {tmp_zip!s}; cannot finalise."
                )
            if target.exists():
                target.unlink()
            os.replace(tmp_zip, target)
        return target

    def load(self, env, name: str = DEFAULT_CHECKPOINT_NAME) -> PPO:
        target = self.path_for(name)
        if not target.exists():
            raise CheckpointNotFound(str(target))
        with self._lock:
            return PPO.load(str(target), env=env)

    def copy_to(self, name: str, destination: Path) -> Path:
        src = self.path_for(name)
        if not src.exists():
            raise CheckpointNotFound(str(src))
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, destination)
        return destination

    def list_checkpoints(self) -> list[Path]:
        return sorted(self._dir.glob("*.zip"))
