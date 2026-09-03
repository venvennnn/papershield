"""
Report component: download controls and audit summary.
"""
from __future__ import annotations

import json
from typing import Optional

import streamlit as st

from papershield.models.document import AuditRecord, WorkflowStatus
from papershield.services.audit_builder import to_markdown


def render_report(
    audit: AuditRecord,
    sanitized_pdf: Optional[bytes],
    original_filename: str,
) -> None:
    st.markdown("## Audit Report & Downloads")

    status = audit.workflow_status
    status_color = {
        WorkflowStatus.SANITIZED: "green",
        WorkflowStatus.BLOCKED: "red",
        WorkflowStatus.REVIEW_INCOMPLETE: "orange",
        WorkflowStatus.NEEDS_REVIEW: "blue",
        WorkflowStatus.SANITIZATION_PENDING: "orange",
        WorkflowStatus.UNINSPECTED: "gray",
    }.get(status, "gray")

    st.markdown(
        f"<div style='background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;"
        f"padding:16px 20px;margin-bottom:16px;'>"
        f"<div style='font-size:13px;color:#6b7280'>Workflow Status</div>"
        f"<div style='font-size:22px;font-weight:700;color:{status_color}'>{status.value}</div>"
        f"<div style='font-size:12px;color:#6b7280;margin-top:4px;'>"
        f"Session: <code>{audit.session_id[:16]}…</code> · "
        f"Reviewer: {audit.reviewer_name} · "
        f"Provider: {audit.provider_mode}"
        f"</div></div>",
        unsafe_allow_html=True,
    )

    # Downloads
    st.markdown("### Downloads")
    stem = original_filename.replace(".pdf", "").replace(" ", "_")
    col1, col2, col3 = st.columns(3)

    with col1:
        if sanitized_pdf and status == WorkflowStatus.SANITIZED:
            st.download_button(
                label="Download sanitized PDF",
                data=sanitized_pdf,
                file_name=f"{stem}_sanitized.pdf",
                mime="application/pdf",
                type="primary",
            )
        elif sanitized_pdf:
            st.download_button(
                label="Download diagnostic PDF (unverified)",
                data=sanitized_pdf,
                file_name=f"{stem}_diagnostic.pdf",
                mime="application/pdf",
                help="Verification did not fully pass. Use with caution.",
            )
        else:
            st.button("No sanitized PDF available", disabled=True)

    with col2:
        audit_json = json.dumps(audit.model_dump(mode="json"), indent=2)
        st.download_button(
            label="Download audit record (JSON)",
            data=audit_json,
            file_name=f"{stem}_audit.json",
            mime="application/json",
        )

    with col3:
        audit_md = to_markdown(audit)
        st.download_button(
            label="Download audit report (Markdown)",
            data=audit_md,
            file_name=f"{stem}_audit.md",
            mime="text/markdown",
        )

    # Findings summary table
    st.markdown("### Findings Summary")
    if audit.findings:
        import pandas as pd
        rows = []
        for f in audit.findings:
            rows.append({
                "ID": f["finding_id"],
                "Category": f["category"],
                "Severity": f["severity"],
                "Page": f["page"],
                "Decision": f.get("review_decision") or "Pending",
                "Detector": f["detector"],
                "Evidence": (f["evidence"] or "")[:60],
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

    # Unresolved critical note
    if audit.unresolved_critical_count > 0:
        st.error(
            f"⚠️ {audit.unresolved_critical_count} critical/high finding(s) remain unresolved. "
            "The output cannot be marked as trusted until these are addressed."
        )
