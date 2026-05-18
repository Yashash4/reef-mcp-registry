"""Data-source clients the RIA generator queries.

Each helper is responsible for one upstream service:

* :mod:`app.data_sources.ai_bom` — pulls the AI-BOM (Atlas registry,
  policy bus fleet+bundle, DAST-A pack catalog) into a single dict shape
  the underwriter agent + PDF renderer consume.
* :mod:`app.data_sources.audit_root` — calls the Go ``lobstertrap audit
  signed-root`` subcommand to fetch the signed Merkle root.
* :mod:`app.data_sources.coverage_matrix` — assembles the OWASP Agentic
  Top 10 + MITRE ATLAS coverage matrix from the live policy YAML +
  DAST-A pack catalog.
* :mod:`app.data_sources.attack_telemetry` — produces the 30-day rolling
  attack heatmap from the policy bus + DAST-A audit logs.

Each module fails closed on transport errors with a stable
:class:`DataSourceError` subclass so the RIA generator can decide whether
to surface the failure (live mode) or fall back to a deterministic stub
(sample-RIA mode without GEMINI_API_KEY).
"""
from __future__ import annotations


class DataSourceError(RuntimeError):
    """Base error for any RIA data source.

    Sub-errors are raised for specific failure modes — never swallowed.
    """

    code: str = "DATA_SOURCE_ERROR"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class AtlasUnreachable(DataSourceError):
    code = "ATLAS_UNREACHABLE"


class PolicyBusUnreachable(DataSourceError):
    code = "POLICY_BUS_UNREACHABLE"


class DastAUnreachable(DataSourceError):
    code = "DAST_A_UNREACHABLE"


class AuditRootError(DataSourceError):
    code = "AUDIT_ROOT_ERROR"


__all__ = [
    "DataSourceError",
    "AtlasUnreachable",
    "PolicyBusUnreachable",
    "DastAUnreachable",
    "AuditRootError",
]
