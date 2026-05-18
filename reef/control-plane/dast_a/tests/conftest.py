"""Pytest configuration — isolates each test's data dir + checkpoints dir."""
from __future__ import annotations

import os
import sys
import warnings
from pathlib import Path

# Ensure `app` package resolves when pytest runs from the dast_a root.
_HERE = Path(__file__).resolve().parent
_DAST_A_ROOT = _HERE.parent
if str(_DAST_A_ROOT) not in sys.path:
    sys.path.insert(0, str(_DAST_A_ROOT))


import pytest  # noqa: E402

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=PendingDeprecationWarning)


@pytest.fixture()
def tmp_dast_a_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    data_dir = tmp_path / "data"
    checkpoints_dir = tmp_path / "checkpoints"
    data_dir.mkdir(parents=True)
    checkpoints_dir.mkdir(parents=True)
    monkeypatch.setenv("REEF_DAST_A_DATA_DIR", str(data_dir))
    monkeypatch.setenv("REEF_DAST_A_CHECKPOINTS_DIR", str(checkpoints_dir))
    monkeypatch.setenv("REEF_DAST_A_AUDIT_FILE", str(data_dir / "audit.jsonl"))
    monkeypatch.setenv("REEF_DAST_A_SEED_ON_BOOT", "1")
    monkeypatch.setenv("REEF_DAST_A_USE_STUB_VICTIM", "1")
    return {
        "data_dir": data_dir,
        "checkpoints_dir": checkpoints_dir,
        "audit_file": data_dir / "audit.jsonl",
    }
