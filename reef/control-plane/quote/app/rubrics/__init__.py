"""Munich Re-grounded rubric files for the Reef underwriter agent."""

import os
from pathlib import Path

_HERE = Path(__file__).resolve().parent

FRAMEWORK_PATH = _HERE / "munich_re_framework.md"
ANTI_PATTERNS_PATH = _HERE / "munich_re_anti_patterns.md"


def read_framework() -> str:
    """Return the Munich Re framework rubric markdown.

    The rubric path can be overridden via ``REEF_UNDERWRITER_RUBRIC`` env
    so operators can pin a snapshot in their own deployment dir.
    """
    override = os.environ.get("REEF_UNDERWRITER_RUBRIC")
    path = Path(override) if override else FRAMEWORK_PATH
    return path.read_text(encoding="utf-8")


def read_anti_patterns() -> str:
    return ANTI_PATTERNS_PATH.read_text(encoding="utf-8")


__all__ = [
    "FRAMEWORK_PATH",
    "ANTI_PATTERNS_PATH",
    "read_framework",
    "read_anti_patterns",
]
