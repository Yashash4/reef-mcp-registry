"""FastAPI routers + app factory for the Reef Quote service."""
from __future__ import annotations

from app.api.app import create_app

__all__ = ["create_app"]
