"""
Risk scoring engine.
Computes normalized I/S/H/A components and the composite document risk score.
"""
from __future__ import annotations

from typing import List

from papershield.models.document import (
    Finding, FindingCategory, RiskComponents, RiskScore, Severity,
)

_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.4,
    Severity.LOW: 0.15,
}


def compute_risk(findings: List[Finding]) -> RiskScore:
    """Compute a RiskScore from a list of findings."""
    injection = [f for f in findings if f.category == FindingCategory.PROMPT_INJECTION]
    sensitive = [f for f in findings if f.category == FindingCategory.SENSITIVE_DATA]
    hidden = [f for f in findings if f.category == FindingCategory.VISIBILITY_DISCREPANCY]
    active = [f for f in findings if f.category in (FindingCategory.ACTIVE_CONTENT, FindingCategory.SUSPICIOUS_LINK, FindingCategory.METADATA)]

    I = _component_score(injection)
    S = _component_score(sensitive)
    H = _component_score(hidden)
    A = _component_score(active)

    components = RiskComponents(injection=I, sensitive=S, hidden=H, active=A)

    has_confirmed_critical = any(
        f.severity == Severity.CRITICAL
        for f in findings
        if f.category in (FindingCategory.PROMPT_INJECTION, FindingCategory.ACTIVE_CONTENT)
    )

    return RiskScore.from_components(components, has_confirmed_critical=has_confirmed_critical)


def _component_score(findings: List[Finding]) -> float:
    if not findings:
        return 0.0
    # Density factor: more findings increases the score, but with diminishing returns
    base = sum(_SEVERITY_WEIGHT[f.severity] * f.confidence for f in findings)
    # Normalize: cap at 5 weighted units = full score
    normalized = min(base / 5.0, 1.0)
    return round(normalized, 3)
