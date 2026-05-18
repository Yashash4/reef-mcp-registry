"""OWASP Agentic Top 10 + MITRE ATLAS coverage matrix.

The honest-framing contract from ``docs/24-GROUNDING.md`` requires Reef to
declare gap states (full / partial / none) per category, not blanket
"full coverage". This module assembles the matrix from two inputs:

* The DAST-A attack-pack catalog (each pack has an ``owasp_asi`` list and
  ``mitre_atlas`` list + ``blocked_by_reef`` flag).
* The active policy YAML's rule set (rule names referencing
  ``injection_patterns`` / ``markdown_exfil`` / ``mcp_supply_chain`` etc.
  align with categories; ``asi_category_ewma`` rules map to ASI01).

A category is:

* ``full``      — at least one attack pack covers it AND ``blocked_by_reef = true`` AND
                  at least one matching policy rule exists.
* ``partial``   — a pack covers the category but only some attack vectors are
                  blocked, OR a policy rule exists without a pack to prove it,
                  OR the category mapping is partial (e.g. MITRE T0040 = "ML
                  Inference API Access" is covered by rate-limit + identity but
                  not by exfiltration controls).
* ``none``      — no pack and no policy signal.

The output is the dict the underwriter agent + page-3 renderer both consume.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("quote.data_sources.coverage_matrix")


# Canonical ID lists pinned by the v1 spec. Update these in lock-step with
# the upstream catalogues — A-8 keeps the enum in
# ``reef/control-plane/dast_a/app/packs/schema.py``.

OWASP_ASI_IDS: tuple[str, ...] = (
    "ASI01",  # Memory Poisoning
    "ASI02",  # Tool Misuse
    "ASI03",  # Cascading Failures
    "ASI04",  # Privilege Compromise
    "ASI05",  # Goal Manipulation
    "ASI06",  # Identity Spoofing (per glossary; ASI07 used in dast_a enum)
    "ASI07",  # Identity Spoofing (alternate ID seen in dast_a enum)
    "ASI08",  # Resource Hijacking
    "ASI09",  # Misaligned Behaviors
    "ASI10",  # Capability Abuse
)

OWASP_ASI_NAMES: dict[str, str] = {
    "ASI01": "Memory Poisoning",
    "ASI02": "Tool Misuse",
    "ASI03": "Cascading Failures",
    "ASI04": "Privilege Compromise",
    "ASI05": "Goal Manipulation",
    "ASI06": "Identity Spoofing",
    "ASI07": "Identity Spoofing (alt)",
    "ASI08": "Resource Hijacking",
    "ASI09": "Misaligned Behaviors",
    "ASI10": "Capability Abuse",
}

MITRE_ATLAS_IDS: tuple[str, ...] = (
    "AML.T0010",  # ML Supply Chain Compromise
    "AML.T0040",  # ML Model Inference API Access
    "AML.T0050",  # Command and Scripting Interpreter
    "AML.T0051",  # LLM Prompt Injection
)

MITRE_ATLAS_NAMES: dict[str, str] = {
    "AML.T0010": "ML Supply Chain Compromise",
    "AML.T0040": "ML Model Inference API Access",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051": "LLM Prompt Injection",
}

# Policy-rule keyword -> categories these rules cover. Drives the
# "policy-rule signal" axis. Kept lowercase for case-insensitive match.
POLICY_RULE_KEYWORDS: dict[str, list[str]] = {
    # OWASP ASI
    "injection": ["ASI09", "ASI02"],
    "markdown_exfil": ["ASI09"],
    "asi_category_ewma": ["ASI01", "ASI05"],
    "mcp_supply_chain": ["ASI10"],
    "mcp_bind": ["ASI10"],
    "svid": ["ASI06", "ASI07"],
    "rate_limit": ["ASI08"],
    "human_review": ["ASI03", "ASI04"],
    "quarantine": ["ASI03"],
    # MITRE
    "supply_chain": ["AML.T0010"],
    "command_injection": ["AML.T0050"],
    "prompt_injection": ["AML.T0051"],
}


def _packs_by_category(packs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group packs by OWASP/MITRE ID they tag."""
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for pack in packs:
        for tag in pack.get("owasp_asi", []) or []:
            by_cat.setdefault(str(tag), []).append(pack)
        for tag in pack.get("mitre_atlas", []) or []:
            by_cat.setdefault(str(tag), []).append(pack)
    return by_cat


def _categories_from_rule_names(rule_names: list[str]) -> set[str]:
    """Coarse-grained keyword scan of policy rule names → category IDs."""
    matched: set[str] = set()
    for name in rule_names:
        lc = (name or "").lower()
        for keyword, cats in POLICY_RULE_KEYWORDS.items():
            if keyword in lc:
                matched.update(cats)
    return matched


def build_owasp_coverage(
    *,
    packs: list[dict[str, Any]],
    rule_names: list[str],
) -> dict[str, dict[str, Any]]:
    """Map each ASI01..ASI10 to ``{state, name, packs, rules}``.

    State values: ``full``, ``partial``, ``none``. The honest framing rule
    forbids declaring ``full`` without (a) a pack tagging the category
    AND (b) ``blocked_by_reef`` true on that pack AND (c) a matching
    policy rule signal. Anything weaker collapses to ``partial`` or
    ``none``.
    """
    by_cat = _packs_by_category(packs)
    rule_cats = _categories_from_rule_names(rule_names)
    matrix: dict[str, dict[str, Any]] = {}
    for asi_id in OWASP_ASI_IDS:
        packs_for_cat = by_cat.get(asi_id, [])
        has_blocked_pack = any(p.get("blocked_by_reef") for p in packs_for_cat)
        has_rule_signal = asi_id in rule_cats
        if has_blocked_pack and has_rule_signal:
            state = "full"
        elif has_blocked_pack or has_rule_signal or packs_for_cat:
            state = "partial"
        else:
            state = "none"
        matrix[asi_id] = {
            "state": state,
            "name": OWASP_ASI_NAMES.get(asi_id, asi_id),
            "pack_ids": [p.get("pack_id", "") for p in packs_for_cat],
            "blocked_by_reef": has_blocked_pack,
            "policy_rule_signal": has_rule_signal,
        }
    return matrix


def build_mitre_coverage(
    *,
    packs: list[dict[str, Any]],
    rule_names: list[str],
) -> dict[str, dict[str, Any]]:
    """Same scheme as :func:`build_owasp_coverage` but for MITRE ATLAS IDs."""
    by_cat = _packs_by_category(packs)
    rule_cats = _categories_from_rule_names(rule_names)
    matrix: dict[str, dict[str, Any]] = {}
    for mid in MITRE_ATLAS_IDS:
        packs_for_cat = by_cat.get(mid, [])
        has_blocked_pack = any(p.get("blocked_by_reef") for p in packs_for_cat)
        has_rule_signal = mid in rule_cats
        if has_blocked_pack and has_rule_signal:
            state = "full"
        elif has_blocked_pack or has_rule_signal or packs_for_cat:
            state = "partial"
        else:
            state = "none"
        matrix[mid] = {
            "state": state,
            "name": MITRE_ATLAS_NAMES.get(mid, mid),
            "pack_ids": [p.get("pack_id", "") for p in packs_for_cat],
            "blocked_by_reef": has_blocked_pack,
            "policy_rule_signal": has_rule_signal,
        }
    return matrix


def extract_policy_rule_names_from_bundles(bundles: list[dict[str, Any]]) -> list[str]:
    """Pull rule names out of the policy bus's ``/bundles`` shape.

    The list endpoint scrubs ``bundle_yaml_b64`` so we can't always parse
    the YAML on the client. When we can (``bundle_yaml`` field present),
    a coarse regex over rule names yields the data. When we can't, we
    fall back to the bundle metadata's ``rule_names`` if A-7 ever publishes
    one (today it does not, so the list is empty and the coverage matrix
    degrades to "partial only via packs" — which is the honest answer).
    """
    rule_names: list[str] = []
    for b in bundles:
        rn = b.get("rule_names")
        if isinstance(rn, list):
            rule_names.extend(str(x) for x in rn)
        yaml_text = b.get("bundle_yaml") or b.get("bundle_yaml_b64") or ""
        if isinstance(yaml_text, str) and "name:" in yaml_text:
            # Quick line scan — robust enough for the policy YAML we ship,
            # which uses one rule per `- name: <id>` block.
            for line in yaml_text.splitlines():
                stripped = line.strip()
                if stripped.startswith("- name:") or stripped.startswith("name:"):
                    parts = stripped.split(":", 1)
                    if len(parts) == 2:
                        rule_names.append(parts[1].strip().strip('"').strip("'"))
    return rule_names


__all__ = [
    "OWASP_ASI_IDS",
    "OWASP_ASI_NAMES",
    "MITRE_ATLAS_IDS",
    "MITRE_ATLAS_NAMES",
    "POLICY_RULE_KEYWORDS",
    "build_owasp_coverage",
    "build_mitre_coverage",
    "extract_policy_rule_names_from_bundles",
]
