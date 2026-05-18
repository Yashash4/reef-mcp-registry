"""Pytest configuration for reef-quote — makes ``app`` package importable."""
from __future__ import annotations

import sys
import warnings
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_QUOTE_ROOT = _HERE.parent
if str(_QUOTE_ROOT) not in sys.path:
    sys.path.insert(0, str(_QUOTE_ROOT))

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=PendingDeprecationWarning)
