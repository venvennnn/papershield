"""
Human review component.
Renders findings table, evidence panel, and Redact/Keep/Escalate controls.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List

import pandas as pd
import streamlit as st

from papershield.models.document import Finding, FindingCategory, FindingDecision, Severity

SEVERITY_SORT = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}

SEVERITY_BADGE = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
}

CATEGORY_LABEL = {
    FindingCategory.PROMPT_INJECTION: "Prompt Injection",
    FindingCategory.SENSITIVE_DATA: "Sensitive Data",
    FindingCategory.SUSPICIOUS_LINK: "Suspicious Link",
    FindingCategory.ACTIVE_CONTENT: "Active Content",
    FindingCategory.VISIBILITY_DISCREPANCY: "Hidden Content",
    FindingCategory.METADATA: "Metadata",
}


def render_review(
    findings: List[Finding],
    reviewer_name: str,
) -> List[Finding]:
    """
    Render the human-review interface. Returns the (mutated) findings list
    with review_decision fields set.
    """
    st.markdown("## Human Review")
    st.markdown(
        "Review every finding below. **Critical** and **High** findings default to **Redact** "
        "but are never silently applied — confirm your selections before sanitizing."
    )

    if not findings:
        st.success("No findings to review.")
        return findings

    # Sort: severity first, then category
    sorted_findings = sorted(findings, key=lambda f: (SEVERITY_SORT.get(f.severity, 99), f.category.value))

    # Bulk actions by category
    with st.expander("Bulk actions by category"):
        categories = list({f.category for f in findings})
        for cat in categories:
            cat_label = CATEGORY_LABEL.get(cat, cat.value)
            cat_findings = [f for f in findings if f.category == cat]
            col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
            col1.markdown(f"**{cat_label}** ({len(cat_findings)} findings)")
            if col2.button("Redact all", key=f"bulk_redact_{cat.value}"):
                _bulk_apply(cat_findings, FindingDecision.REDACT, reviewer_name)
                st.rerun()
            if col3.button("Keep all", key=f"bulk_keep_{cat.value}"):
                _bulk_apply(cat_findings, FindingDecision.KEEP, reviewer_name)
                st.rerun()
            if col4.button("Escalate all", key=f"bulk_escalate_{cat.value}"):
                _bulk_apply(cat_findings, FindingDecision.ESCALATE, reviewer_name)
                st.rerun()

    # Summary row
    pending = sum(1 for f in findings if not f.review_decision or f.review_decision == FindingDecision.PENDING)
    redact_count = sum(1 for f in findings if f.review_decision == FindingDecision.REDACT)
    keep_count = sum(1 for f in findings if f.review_decision == FindingDecision.KEEP)
    escalate_count = sum(1 for f in findings if f.review_decision == FindingDecision.ESCALATE)
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Pending", pending)
    col2.metric("→ Redact", redact_count)
    col3.metric("→ Keep", keep_count)
    col4.metric("→ Escalate", escalate_count)
    st.divider()

    # Per-finding controls
    for finding in sorted_findings:
        _render_finding_card(finding, reviewer_name)

    return findings


def _render_finding_card(finding: Finding, reviewer_name: str) -> None:
    badge = SEVERITY_BADGE.get(finding.severity.value, "⚪")
    cat_label = CATEGORY_LABEL.get(finding.category, finding.category.value)

    decision_display = finding.review_decision.value if finding.review_decision else "Pending"
    decision_color = {
        "Redact": "#dc2626",
        "Keep": "#16a34a",
        "Escalate": "#d97706",
        "Pending": "#6b7280",
    }.get(decision_display, "#6b7280")

    with st.container():
        st.markdown(
            f"<div style='background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;"
            f"padding:14px 16px;margin-bottom:10px;'>"
            f"<div style='display:flex;justify-content:space-between;align-items:center;'>"
            f"<span style='font-weight:600;font-size:13px'>{badge} {finding.severity.value} · {cat_label}</span>"
            f"<span style='font-size:11px;color:#6b7280'>Page {finding.page} · "
            f"<code style='font-size:10px'>{finding.finding_id}</code></span>"
            f"</div>"
            f"<div style='font-size:11px;color:#6b7280;margin-top:2px;'>"
            f"Detector: <code>{finding.detector}</code> · Confidence: {finding.confidence:.0%} · "
            f"Subtype: {finding.subtype}"
            f"</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

        with st.expander(f"Evidence: {finding.evidence[:80]}{'…' if len(finding.evidence)>80 else ''}"):
            col1, col2 = st.columns([2, 1])
            with col1:
                st.markdown(f"**Extracted text:**")
                st.code(finding.evidence, language=None)
                st.markdown(
                    f"- **Page:** {finding.page}  \n"
                    f"- **Visibility:** {finding.visibility.value}  \n"
                    f"- **Recommended:** {finding.recommended_action.value}  \n"
                    f"- **Bounding box:** {finding.bbox}"
                )
            with col2:
                # Decision controls
                default_idx = _decision_default_idx(finding)
                decision = st.radio(
                    "Decision",
                    options=["Redact", "Keep", "Escalate"],
                    index=default_idx,
                    key=f"decision_{finding.finding_id}",
                    horizontal=False,
                )
                reason = None
                if decision == "Keep" and finding.severity.value in ("Critical", "High"):
                    reason = st.text_input(
                        "Reason required for Keep on Critical/High",
                        key=f"reason_{finding.finding_id}",
                        placeholder="Explain why this should be kept…",
                    )
                    if not reason:
                        st.warning("A reason is required to Keep a Critical/High finding.")

                if st.button("Apply decision", key=f"apply_{finding.finding_id}"):
                    finding.review_decision = FindingDecision(decision)
                    finding.review_reason = reason
                    finding.reviewed_at = datetime.now(timezone.utc).isoformat()
                    finding.reviewed_by = reviewer_name
                    st.success(f"Decision recorded: **{decision}**")
                    st.rerun()


def _decision_default_idx(finding: Finding) -> int:
    if finding.review_decision:
        mapping = {"Redact": 0, "Keep": 1, "Escalate": 2}
        return mapping.get(finding.review_decision.value, 0)
    if finding.recommended_action == FindingDecision.REDACT:
        return 0
    if finding.recommended_action == FindingDecision.ESCALATE:
        return 2
    return 1


def _bulk_apply(findings: List[Finding], decision: FindingDecision, reviewer_name: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for f in findings:
        f.review_decision = decision
        f.reviewed_at = now
        f.reviewed_by = reviewer_name
