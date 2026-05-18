"""Pydantic schema for an attack pack."""
from __future__ import annotations

import datetime as dt
import enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class PackSource(str, enum.Enum):
    """Where the pack originated from.

    Used for honest framing in the catalog — Reef does NOT claim DAST-A
    discovered MCP-RCE-26.04 (that's OX Security's disclosure). It claims
    DAST-A catalogues it as part of the canonical attack registry.
    """

    EXTERNAL_DISCLOSURE = "external_disclosure"
    DAST_A_SYNTHETIC = "dast_a_synthetic"
    OPERATOR_ADDED = "operator_added"


class OwaspAsiTag(str, enum.Enum):
    """OWASP Top 10 for Agentic Applications categories.

    Names mirror the canonical IDs documented in
    ``docs/30-GLOSSARY.md`` under ``ASI``.
    """

    ASI01 = "ASI01"  # Memory Poisoning
    ASI02 = "ASI02"  # Tool Misuse
    ASI03 = "ASI03"  # Cascading Failures
    ASI04 = "ASI04"  # Privilege Compromise
    ASI05 = "ASI05"  # Goal Manipulation
    ASI06 = "ASI06"  # Identity Spoofing (sic: glossary has 06+02 both labelled "Tool Misuse" — keep ID, not name)
    ASI07 = "ASI07"  # Identity Spoofing
    ASI08 = "ASI08"  # Resource Hijacking
    ASI09 = "ASI09"  # Misaligned Behaviors
    ASI10 = "ASI10"  # Capability Abuse


class MitreAtlasTag(str, enum.Enum):
    """MITRE ATLAS tactics / techniques referenced by attack packs."""

    AML_T0010 = "AML.T0010"  # ML Supply Chain Compromise
    AML_T0051 = "AML.T0051"  # LLM Prompt Injection
    AML_T0040 = "AML.T0040"  # ML Model Inference API Access
    AML_T0050 = "AML.T0050"  # Command and Scripting Interpreter


class PackDiscoveryEvidence(BaseModel):
    """Pointer back to the episode (or external disclosure) the pack derives from."""

    model_config = ConfigDict(extra="forbid")

    episode_id: Optional[str] = Field(
        default=None, description="DAST-A episode UUID, when source is synthetic."
    )
    payload_signature: Optional[str] = Field(
        default=None,
        description="Canonical mutation-slot signature the RL agent landed on.",
    )
    payload_excerpt: Optional[str] = Field(
        default=None,
        description="Up to 512-char redacted preview of the rendered payload.",
    )
    blocked_by_reef: Optional[bool] = Field(
        default=None,
        description=(
            "True if the live Reef policy stopped this attack. False if it slipped "
            "and the policy needs an update."
        ),
    )


class AttackPack(BaseModel):
    """The canonical attack-pack record stored in the catalog."""

    model_config = ConfigDict(extra="forbid")

    pack_id: str = Field(
        ...,
        description="Stable identifier (e.g. 'MCP-RCE-26.04').",
        min_length=3,
    )
    name: str = Field(..., min_length=1)
    source: PackSource
    discovered_by: str = Field(
        ...,
        description=(
            "Human-readable attribution. DAST-A-synthetic packs MUST be labelled "
            "'DAST-A (synthetic — RL search against test fixture)' per the "
            "honest-framing rule in docs/00-README.md."
        ),
    )
    cve_mapping: str = Field(
        default="",
        description=(
            "Comma-separated CVE list or the literal string explaining why no CVE "
            "applies. MCP-RCE-26.04 uses 'no-mcp-cve (Anthropic declined to patch; "
            "OX Security PoC)'."
        ),
    )
    owasp_asi: list[OwaspAsiTag] = Field(default_factory=list)
    mitre_atlas: list[MitreAtlasTag] = Field(default_factory=list)
    trigger_template: str = Field(
        ...,
        description="Short, demo-grade rendering of the attack trigger.",
    )
    victim_signal: str = Field(
        ...,
        description="What the victim app emits when the attack lands.",
    )
    reef_policy_signal: str = Field(
        ...,
        description="The Reef policy decision that should be returned.",
    )
    discovered_at: dt.datetime
    exemplar_request_id: str = Field(
        default="",
        description="Audit-log request ID for the canonical demo trigger.",
    )
    successful_episodes: int = Field(default=0, ge=0)
    blocked_by_reef: bool = Field(
        default=False,
        description="Whether the current live Reef policy blocks this attack.",
    )
    ox_security_citation: str = Field(
        default="",
        description=(
            "When source is the April 2026 MCP disclosure, the OX Security verbatim "
            "citation lives here. Other packs leave this empty."
        ),
    )
    evidence: Optional[PackDiscoveryEvidence] = None


class AttackPackList(BaseModel):
    """Paginated catalog response shape."""

    model_config = ConfigDict(extra="forbid")

    total: int
    page: int
    page_size: int
    packs: list[AttackPack]
