"""File-backed JSON storage with mutex-protected concurrent writes."""

from app.store.file_store import FileStore

__all__ = ["FileStore"]
