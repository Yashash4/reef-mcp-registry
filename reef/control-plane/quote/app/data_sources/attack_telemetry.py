"""30-day rolling attack heatmap from the policy bus + DAST-A audit logs.

The heatmap is a category × day grid the RIA's page-4 renders. Data comes
from:

* ``policy_bus/data/audit.jsonl`` — every publish/reject event the bus
  records (file-backed JSONL, append-only).
* ``dast_a/data/audit.jsonl`` — every episode the DAST-A FastAPI service
  records.

When either log is empty (fresh deployment) we honestly mark the cells
``demo seed`` and synthesise a realistic but explicitly-labelled
distribution so the PDF section never renders blank.

The aggregator is in this module so the underwriter agent can score
against the same shape the PDF renders — single source of truth.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("quote.data_sources.attack_telemetry")


# Category buckets the heatmap rows are keyed on. These cluster a wide
# set of OWASP/MITRE codes into the 6 visually-distinct rows the page-4
# heatmap renders. The DAST-A pack catalog provides the canonical detail.
TELEMETRY_BUCKETS: tuple[str, ...] = (
    "MCP supply chain",
    "Markdown exfil",
    "Prompt injection",
    "Tool-chain drift",
    "Identity / SVID",
    "Other",
)


# Keyword → bucket. Substring case-insensitive match against the audit
# event's ``rule_id`` / ``decision`` / ``pack_id`` strings.
BUCKET_KEYWORDS: dict[str, list[str]] = {
    "MCP supply chain": ["mcp_bind", "mcp_supply_chain", "mcp-rce", "mcp_rce", "mcprce"],
    "Markdown exfil": ["markdown_exfil", "markdownexfil", "echoleak", "exfil"],
    "Prompt injection": ["injection", "promptinjection", "prompt_injection"],
    "Tool-chain drift": ["asi_category_ewma", "toolchain", "tool_chain", "drift"],
    "Identity / SVID": ["svid", "identity_spoof", "intent_mismatch"],
}


@dataclass
class TelemetryDay:
    """One day in the heatmap — counts by bucket."""

    date_iso: str  # YYYY-MM-DD
    by_bucket: dict[str, int]
    is_demo_seed: bool = False

    @property
    def total(self) -> int:
        return sum(self.by_bucket.values())


def _bucket_for_event(event: dict[str, Any]) -> str:
    """Classify an audit event into one of :data:`TELEMETRY_BUCKETS`."""
    haystack = " ".join(
        str(event.get(k, "")) for k in ("rule_id", "decision", "pack_id", "kind", "reason")
    ).lower()
    for bucket, keywords in BUCKET_KEYWORDS.items():
        for kw in keywords:
            if kw in haystack:
                return bucket
    return "Other"


def _parse_timestamp(raw: Any) -> Optional[dt.datetime]:
    """Best-effort parse of the variety of timestamp shapes the logs ship."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        # Unix seconds (policy bus stores `published_at_unix`).
        try:
            return dt.datetime.fromtimestamp(float(raw), tz=dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(raw, str):
        # Try ISO 8601 with optional Z suffix.
        s = raw.strip().replace("Z", "+00:00")
        try:
            return dt.datetime.fromisoformat(s)
        except ValueError:
            return None
    return None


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Stream-load a JSONL audit log. Empty / missing → ``[]``."""
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                # We surface this to the caller's logger rather than
                # silently dropping — a malformed audit line is an
                # operational red flag the operator should see.
                logger.warning(
                    "skipping malformed audit line at %s: %r", path, line[:120]
                )
                continue
            if isinstance(row, dict):
                out.append(row)
    return out


def aggregate_heatmap(
    *,
    policy_bus_audit: Path,
    dast_a_audit: Path,
    end_date: Optional[dt.date] = None,
    window_days: int = 30,
    include_demo_seed: bool = True,
    rng_seed: int = 1337,
) -> list[TelemetryDay]:
    """Return a list of :class:`TelemetryDay` covering the rolling window.

    Days are ordered oldest-to-newest. ``end_date`` defaults to today.
    ``window_days`` is inclusive of ``end_date``.

    Honest-framing: when the real logs cover fewer than ``window_days``
    days, missing days are filled with synthetic seed data clearly
    flagged ``is_demo_seed=True``. The PDF section legend says so.
    """
    end_date = end_date or dt.datetime.now(tz=dt.timezone.utc).date()
    start_date = end_date - dt.timedelta(days=window_days - 1)
    days: dict[dt.date, dict[str, int]] = {
        start_date + dt.timedelta(days=i): {b: 0 for b in TELEMETRY_BUCKETS}
        for i in range(window_days)
    }

    real_event_dates: set[dt.date] = set()
    for path in (policy_bus_audit, dast_a_audit):
        for ev in read_jsonl(path):
            ts = _parse_timestamp(ev.get("ts") or ev.get("timestamp") or ev.get("published_at_unix"))
            if ts is None:
                continue
            d = ts.date()
            if d < start_date or d > end_date:
                continue
            bucket = _bucket_for_event(ev)
            days[d][bucket] = days[d].get(bucket, 0) + 1
            real_event_dates.add(d)

    out: list[TelemetryDay] = []
    rng = random.Random(rng_seed)
    for i in range(window_days):
        date = start_date + dt.timedelta(days=i)
        cells = days[date]
        is_demo = include_demo_seed and date not in real_event_dates
        if is_demo and sum(cells.values()) == 0:
            cells = _synthesize_day(rng, date)
        out.append(
            TelemetryDay(
                date_iso=date.isoformat(),
                by_bucket=cells,
                is_demo_seed=is_demo,
            )
        )
    return out


def _synthesize_day(rng: random.Random, date: dt.date) -> dict[str, int]:
    """Realistic synthetic per-day distribution for honest demo display.

    Skews higher around April 16 2026 (MCP-RCE disclosure) and higher on
    weekdays. Distribution is deterministic per ``rng`` seed + date so
    sample RIAs render the same heatmap across builds.
    """
    # Day-of-week multiplier (Mon=0..Sun=6).
    dow_mult = (1.0, 1.0, 1.2, 1.1, 1.0, 0.4, 0.3)[date.weekday()]
    # MCP-RCE disclosure shock window: April 14–18 2026.
    in_shock_window = dt.date(2026, 4, 14) <= date <= dt.date(2026, 4, 18)
    shock_mult = 4.0 if in_shock_window else 1.0

    base = {
        "MCP supply chain": int(rng.randint(2, 6) * dow_mult * shock_mult),
        "Markdown exfil": int(rng.randint(3, 9) * dow_mult),
        "Prompt injection": int(rng.randint(4, 14) * dow_mult),
        "Tool-chain drift": int(rng.randint(0, 3) * dow_mult),
        "Identity / SVID": int(rng.randint(0, 2) * dow_mult),
        "Other": int(rng.randint(0, 4) * dow_mult),
    }
    return base


def telemetry_to_audit_window(
    days: list[TelemetryDay],
    *,
    merkle_root_hex: str,
    merkle_count: int,
    fleet_id: str,
) -> dict[str, Any]:
    """Pack the heatmap + Merkle root into the ``audit_window`` snapshot
    the underwriter agent reads (matches the existing
    :class:`UnderwriterInput.audit_window` dict).
    """
    totals_by_bucket = {b: 0 for b in TELEMETRY_BUCKETS}
    for d in days:
        for b, c in d.by_bucket.items():
            totals_by_bucket[b] = totals_by_bucket.get(b, 0) + c
    total = sum(totals_by_bucket.values())
    demo_days = sum(1 for d in days if d.is_demo_seed)
    return {
        "days": len(days),
        "fleet_id": fleet_id,
        "merkle_root_sha256": merkle_root_hex,
        "merkle_event_count": merkle_count,
        "total_events": total,
        "totals_by_bucket": totals_by_bucket,
        "demo_seed_day_count": demo_days,
        "has_real_data": demo_days < len(days),
    }


__all__ = [
    "TELEMETRY_BUCKETS",
    "TelemetryDay",
    "read_jsonl",
    "aggregate_heatmap",
    "telemetry_to_audit_window",
]
