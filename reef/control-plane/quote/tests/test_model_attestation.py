"""Phase B round 1 R-3 — model_attestation block tests.

Records which Gemini model + rubric files produced the underwriter
score. The auditor verifies this block against the NYDFS Part 500 / OCC
SR-21-14 model-risk-management programme — that's why ``.env.example``
defaults to GA model IDs (no ``*-exp``) and the rubric files are hashed
into the artifact itself.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path

import pytest

from app.ria_generator import (
    ModelAttestation,
    build_model_attestation,
    REEF_VERSION,
)
from app.rubrics import ANTI_PATTERNS_PATH, FRAMEWORK_PATH


def test_sample_mode_records_stub_model_id(monkeypatch) -> None:
    """Sample mode MUST NOT record a Gemini model id — there was no call."""
    monkeypatch.setenv("GEMINI_PRO_MODEL", "gemini-2.5-pro")
    attestation = build_model_attestation(
        sample_mode=True,
        generated_at=dt.datetime(2026, 5, 18, 0, 0, 0, tzinfo=dt.timezone.utc),
    )
    assert isinstance(attestation, ModelAttestation)
    assert attestation.sample_mode is True
    assert "sample-underwriter-stub" in attestation.underwriter_model_id
    assert "(no Gemini call)" in attestation.underwriter_model_id


def test_live_mode_reads_env_model_id(monkeypatch) -> None:
    """Live mode reads GEMINI_PRO_MODEL — D-017 forbids hardcoding."""
    monkeypatch.setenv("GEMINI_PRO_MODEL", "gemini-2.5-pro")
    attestation = build_model_attestation(
        sample_mode=False,
        generated_at=dt.datetime(2026, 5, 18, 0, 0, 0, tzinfo=dt.timezone.utc),
    )
    assert attestation.underwriter_model_id == "gemini-2.5-pro"
    assert attestation.sample_mode is False


def test_live_mode_with_missing_env_marks_unspecified(monkeypatch) -> None:
    """When env is missing we record 'unspecified' rather than crashing."""
    monkeypatch.delenv("GEMINI_PRO_MODEL", raising=False)
    attestation = build_model_attestation(
        sample_mode=False,
        generated_at=dt.datetime(2026, 5, 18, 0, 0, 0, tzinfo=dt.timezone.utc),
    )
    assert attestation.underwriter_model_id == "unspecified"


def test_rubric_sha256_matches_disk(monkeypatch) -> None:
    """The committed framework + anti-patterns rubric file hashes match."""
    monkeypatch.setenv("GEMINI_PRO_MODEL", "gemini-2.5-pro")
    attestation = build_model_attestation(
        sample_mode=False,
        generated_at=dt.datetime(2026, 5, 18, 0, 0, 0, tzinfo=dt.timezone.utc),
    )
    expected_framework = hashlib.sha256(FRAMEWORK_PATH.read_bytes()).hexdigest()
    expected_anti = hashlib.sha256(ANTI_PATTERNS_PATH.read_bytes()).hexdigest()
    assert attestation.rubric_file_sha256_framework == expected_framework
    assert attestation.rubric_file_sha256_antipatterns == expected_anti


def test_missing_rubric_path_marks_unavailable(monkeypatch, tmp_path) -> None:
    """Missing rubric files don't crash — they record 'unavailable'."""
    monkeypatch.setenv("GEMINI_PRO_MODEL", "gemini-2.5-pro")
    attestation = build_model_attestation(
        sample_mode=False,
        generated_at=dt.datetime(2026, 5, 18, 0, 0, 0, tzinfo=dt.timezone.utc),
        framework_path=tmp_path / "absent.md",
        anti_patterns_path=tmp_path / "also-absent.md",
    )
    assert attestation.rubric_file_sha256_framework == "unavailable"
    assert attestation.rubric_file_sha256_antipatterns == "unavailable"


def test_attestation_carries_generator_version(monkeypatch) -> None:
    """ria_generator_version embeds the constant the artifact was built with."""
    monkeypatch.setenv("GEMINI_PRO_MODEL", "gemini-2.5-pro")
    attestation = build_model_attestation(
        sample_mode=False,
        generated_at=dt.datetime(2026, 5, 18, 0, 0, 0, tzinfo=dt.timezone.utc),
    )
    assert attestation.ria_generator_version == f"reef-quote-v{REEF_VERSION}"
    assert REEF_VERSION  # non-empty


def test_as_table_rows_emits_expected_keys(monkeypatch) -> None:
    """The model_attestation block's table-rows view names every required key."""
    monkeypatch.setenv("GEMINI_PRO_MODEL", "gemini-2.5-pro")
    attestation = build_model_attestation(
        sample_mode=False,
        generated_at=dt.datetime(2026, 5, 18, 0, 0, 0, tzinfo=dt.timezone.utc),
    )
    keys = [k for k, _ in attestation.as_table_rows()]
    assert "underwriter_model_id" in keys
    assert "underwriter_model_build_hash" in keys
    assert "rubric_file_sha256 (framework)" in keys
    assert "rubric_file_sha256 (anti-patterns)" in keys
    assert "ria_generated_at_unix" in keys
    assert "ria_generator_version" in keys
    assert "sample_mode" in keys


def test_attestation_is_serializable() -> None:
    """ModelAttestation is a dataclass — it must round-trip via __dict__."""
    attestation = ModelAttestation(
        underwriter_model_id="gemini-2.5-pro",
        underwriter_model_build_hash="unspecified",
        rubric_file_sha256_framework="ab" * 32,
        rubric_file_sha256_antipatterns="cd" * 32,
        ria_generated_at_unix=1779070000,
        ria_generator_version="reef-quote-v0.2.0",
        sample_mode=False,
    )
    rows = attestation.as_table_rows()
    assert len(rows) == 7
    # Every row's value is a non-None string for table-cell rendering.
    for _key, value in rows:
        assert isinstance(value, str)
