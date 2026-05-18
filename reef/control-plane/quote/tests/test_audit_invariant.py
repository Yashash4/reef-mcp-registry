"""Phase B round 1 R-6 — D-018 advisory-only invariant scan tests.

D-018 says Reef NEVER auto-applies a Gemini-Flash-drafted policy bundle —
every such bundle must carry a non-empty ``human_review.approval_id`` in
the policy-bus audit log before it can take effect.

The :func:`scan_audit_for_invariants` helper inside
``app/ria_generator.py`` walks the audit JSONL and surfaces any event
that violates the rule. The page-6 builder renders a red banner if the
returned ``AuditInvariantReport.violations`` is non-empty, and the
artifact NEVER hides the violation from the auditor.
"""
from __future__ import annotations

from pathlib import Path

from app.ria_generator import (
    AuditInvariantReport,
    AuditInvariantViolation,
    scan_audit_for_invariants,
)


def test_clean_log_produces_no_violations(tmp_path: Path) -> None:
    """A log with only operator-approved Flash drafts is clean."""
    report = scan_audit_for_invariants(
        policy_bus_audit_path=tmp_path / "audit.jsonl",
        events_override=[
            {
                "kind": "policy_bundle_applied",
                "event_id": "evt-1",
                "bundle_id": "b-1",
                "source": "gemini_blue_draft",
                "timestamp": "2026-05-17T10:00:00Z",
                "human_review": {"approval_id": "approval-7af3"},
            },
            {
                "kind": "policy_bundle_applied",
                "event_id": "evt-2",
                "bundle_id": "b-2",
                "source": "operator_signed",  # not draft-sourced
                "timestamp": "2026-05-17T11:00:00Z",
                # No human_review needed for operator-signed bundles.
            },
        ],
    )
    assert isinstance(report, AuditInvariantReport)
    assert report.has_violations is False
    assert report.violations == []
    assert report.scanned_event_count == 2
    assert report.draft_applied_event_count == 1


def test_missing_approval_id_is_a_violation(tmp_path: Path) -> None:
    """A Flash-drafted apply with NO approval_id MUST surface as violation."""
    report = scan_audit_for_invariants(
        policy_bus_audit_path=tmp_path / "audit.jsonl",
        events_override=[
            {
                "kind": "policy_bundle_applied",
                "event_id": "evt-bad-1",
                "bundle_id": "b-bad",
                "source": "gemini_blue_draft",
                "timestamp": "2026-05-17T12:00:00Z",
                "human_review": {},  # missing approval_id
            }
        ],
    )
    assert report.has_violations is True
    assert len(report.violations) == 1
    violation = report.violations[0]
    assert isinstance(violation, AuditInvariantViolation)
    assert violation.event_id == "evt-bad-1"
    assert violation.bundle_id == "b-bad"
    assert "D-018" in violation.reason


def test_empty_approval_id_is_also_a_violation(tmp_path: Path) -> None:
    """A blank-string approval_id MUST NOT pass — D-018 requires a non-empty id."""
    report = scan_audit_for_invariants(
        policy_bus_audit_path=tmp_path / "audit.jsonl",
        events_override=[
            {
                "kind": "policy_bundle_applied",
                "event_id": "evt-bad-2",
                "bundle_id": "b-bad-2",
                "source": "gemini_blue_draft",
                "timestamp": "2026-05-17T13:00:00Z",
                "human_review": {"approval_id": "   "},
            }
        ],
    )
    assert report.has_violations
    assert report.violations[0].event_id == "evt-bad-2"


def test_jsonl_file_path_is_read_when_no_override(tmp_path: Path) -> None:
    """The scanner reads the JSONL audit file when events_override is None."""
    audit_file = tmp_path / "policy_bus_audit.jsonl"
    audit_file.write_text(
        "\n".join(
            [
                '{"kind":"policy_bundle_applied","event_id":"a","bundle_id":"b1","source":"gemini_blue_draft","human_review":{"approval_id":"ok"}}',
                '{"kind":"policy_bundle_applied","event_id":"b","bundle_id":"b2","source":"gemini_blue_draft","human_review":{}}',
                "",  # blank line — must be skipped silently
                'malformed json line — must not crash the scanner',
                '{"kind":"some_other_event","event_id":"c"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    report = scan_audit_for_invariants(policy_bus_audit_path=audit_file)
    # Scanner skips blank + malformed lines; counts parseable rows.
    assert report.scanned_event_count == 3
    assert report.draft_applied_event_count == 2
    assert len(report.violations) == 1
    assert report.violations[0].event_id == "b"


def test_missing_file_is_treated_as_empty(tmp_path: Path) -> None:
    """A missing JSONL audit file means no events — no violations."""
    report = scan_audit_for_invariants(
        policy_bus_audit_path=tmp_path / "does-not-exist.jsonl"
    )
    assert report.scanned_event_count == 0
    assert report.violations == []
