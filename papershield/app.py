"""
PaperShield — Document trust boundary for AI systems.

State machine: Upload → Inspect → Review → Sanitize → Report
Run with: streamlit run app.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Ensure the package root is on the path when run directly
_pkg_root = Path(__file__).parent.parent
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

import streamlit as st

# ── Page config (must be first Streamlit call) ──────────────────────────────
st.set_page_config(
    page_title="PaperShield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Force white background everywhere ───────────────────────────────────────
st.markdown(
    """
    <style>
    html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"],
    [data-testid="stSidebar"], section.main, .block-container,
    [data-testid="stVerticalBlock"] {
        background-color: #ffffff !important;
    }
    [data-testid="stSidebar"] {background-color: #f9fafb !important;}
    h1,h2,h3,h4,h5,h6 {color: #111827 !important;}
    .stMetric label {color: #6b7280;}
    .stAlert {border-radius: 6px;}
    </style>
    """,
    unsafe_allow_html=True,
)

from papershield.components.upload import render_upload
from papershield.components.inspection import render_risk_summary, render_page_preview
from papershield.components.review import render_review
from papershield.components.comparison import render_comparison
from papershield.components.report import render_report
from papershield.models.document import (
    Finding, FindingDecision, ProcessingStage, WorkflowStatus,
)
from papershield.services.nutrient_client import get_provider, DemoNutrientProvider
from papershield.services.extraction_normalizer import extract_with_pymupdf
from papershield.services.pdf_static_inspector import inspect_pdf_structure
from papershield.services.injection_detector import detect_injections
from papershield.services.sensitive_data_detector import detect_sensitive_data
from papershield.services.visibility_comparator import find_hidden_elements
from papershield.services.risk_engine import compute_risk
from papershield.services.redaction_service import apply_redactions, verify_redactions
from papershield.services.audit_builder import build_audit_record


# ── Load secrets ─────────────────────────────────────────────────────────────
def _load_secrets() -> None:
    try:
        if hasattr(st, "secrets"):
            for key in ("NUTRIENT_API_KEY", "NUTRIENT_BASE_URL", "DEMO_MODE"):
                val = st.secrets.get(key)
                if val and not os.environ.get(key):
                    os.environ[key] = str(val)
    except Exception:
        pass


_load_secrets()

# ── States ───────────────────────────────────────────────────────────────────
STAGES = [
    "Upload",
    "Inspect",
    "Review",
    "Sanitize",
    "Report",
]

# ── Init session state ────────────────────────────────────────────────────────
_defaults = {
    "stage": "Upload",
    "session_id": str(uuid.uuid4()),
    "pdf_bytes": None,
    "filename": "",
    "findings": [],
    "digital_elements": [],
    "page_count": 0,
    "risk": None,
    "sanitized_pdf": None,
    "verification": {},
    "audit": None,
    "reviewer_name": "Reviewer",
    "started_at": None,
    "provider_mode": "Demo",
}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        "<div style='font-size:26px;font-weight:700;letter-spacing:-.5px'>🛡️ PaperShield</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<div style='font-size:12px;color:#6b7280;margin-top:-4px;margin-bottom:16px'>"
        "Document trust boundary for AI systems</div>",
        unsafe_allow_html=True,
    )

    # Provider badge
    provider = get_provider()
    is_demo = isinstance(provider, DemoNutrientProvider)
    badge_color = "#6b7280" if is_demo else "#16a34a"
    badge_text = "Prepared demo" if is_demo else "Live · Nutrient"
    st.markdown(
        f"<div style='background:#f3f4f6;border:1px solid #e5e7eb;border-radius:6px;"
        f"padding:6px 10px;font-size:11px;font-weight:600;color:{badge_color};"
        f"text-transform:uppercase;letter-spacing:.05em;margin-bottom:16px'>"
        f"⚙ {badge_text}</div>",
        unsafe_allow_html=True,
    )

    # Stage progress
    st.markdown("**Workflow**")
    for s in STAGES:
        active = st.session_state["stage"] == s
        done = STAGES.index(s) < STAGES.index(st.session_state["stage"])
        icon = "✓" if done else ("▶" if active else "○")
        weight = "700" if active else "400"
        color = "#111827" if active else ("#16a34a" if done else "#9ca3af")
        st.markdown(
            f"<div style='font-size:13px;font-weight:{weight};color:{color};margin-bottom:2px'>"
            f"{icon} {s}</div>",
            unsafe_allow_html=True,
        )

    st.divider()
    st.session_state["reviewer_name"] = st.text_input(
        "Reviewer name", value=st.session_state["reviewer_name"]
    )

    if st.button("Start over", type="secondary"):
        for k in _defaults:
            st.session_state[k] = _defaults[k]
        st.session_state["session_id"] = str(uuid.uuid4())
        st.rerun()


# ── Stage: Upload ─────────────────────────────────────────────────────────────
if st.session_state["stage"] == "Upload":
    pdf_bytes, filename = render_upload()

    if pdf_bytes:
        st.session_state["pdf_bytes"] = pdf_bytes
        st.session_state["filename"] = filename
        st.divider()
        if st.button("Inspect document", type="primary", use_container_width=True):
            st.session_state["started_at"] = datetime.now(timezone.utc).isoformat()
            st.session_state["stage"] = "Inspect"
            st.rerun()


# ── Stage: Inspect ────────────────────────────────────────────────────────────
elif st.session_state["stage"] == "Inspect":
    st.markdown("## Inspecting Document")

    pdf_bytes: bytes = st.session_state["pdf_bytes"]
    filename: str = st.session_state["filename"]
    provider = get_provider()
    st.session_state["provider_mode"] = provider.provider_name

    stages_order = [
        "Hashing file",
        "Rendering pages",
        "Extracting machine-readable content",
        "Running OCR comparison",
        "Checking sensitive data",
        "Analyzing suspicious instructions",
        "Running static PDF checks",
        "Building review queue",
    ]

    progress_bar = st.progress(0)
    status_text = st.empty()

    def update_progress(stage: str) -> None:
        idx = stages_order.index(stage) if stage in stages_order else 0
        progress_bar.progress((idx + 1) / len(stages_order), text=f"⏳ {stage}")
        status_text.markdown(f"**{stage}…**")

    findings: list[Finding] = []

    try:
        # 1 Hash
        update_progress("Hashing file")
        sha = hashlib.sha256(pdf_bytes).hexdigest()
        time.sleep(0.1)

        # 2 Render / get page count
        update_progress("Rendering pages")
        from papershield.services.extraction_normalizer import extract_with_pymupdf
        digital_elements, page_count = extract_with_pymupdf(pdf_bytes)
        st.session_state["digital_elements"] = digital_elements
        st.session_state["page_count"] = page_count
        time.sleep(0.1)

        # 3 Nutrient extraction (or demo fixture)
        update_progress("Extracting machine-readable content")
        try:
            nutrient_elements = provider.extract_document(pdf_bytes, filename=filename)
            if not nutrient_elements:
                nutrient_elements = digital_elements
        except Exception:
            nutrient_elements = digital_elements
        time.sleep(0.1)

        # 4 OCR comparison / visibility
        update_progress("Running OCR comparison")
        try:
            ocr_elements = provider.apply_ocr(pdf_bytes)
            if not ocr_elements:
                ocr_elements = digital_elements
        except Exception:
            ocr_elements = digital_elements

        hidden_elements, hidden_findings = find_hidden_elements(digital_elements, ocr_elements)
        findings.extend(hidden_findings)
        time.sleep(0.1)

        # 5 Sensitive data
        update_progress("Checking sensitive data")
        all_elements = digital_elements + hidden_elements
        sensitive_findings = detect_sensitive_data(all_elements)
        findings.extend(sensitive_findings)
        time.sleep(0.1)

        # 6 Injection detection
        update_progress("Analyzing suspicious instructions")
        injection_findings = detect_injections(digital_elements, hidden_elements)
        findings.extend(injection_findings)
        time.sleep(0.1)

        # 7 Static PDF
        update_progress("Running static PDF checks")
        static_findings = inspect_pdf_structure(pdf_bytes)
        findings.extend(static_findings)
        time.sleep(0.1)

        # 8 Risk + queue
        update_progress("Building review queue")
        risk = compute_risk(findings)
        st.session_state["findings"] = findings
        st.session_state["risk"] = risk
        time.sleep(0.1)

        progress_bar.progress(1.0, text="✓ Inspection complete")
        status_text.empty()

    except Exception as e:
        st.error(f"Inspection failed: {e}")
        st.stop()

    # Display results
    st.divider()
    render_risk_summary(st.session_state["risk"], findings)
    st.divider()
    render_page_preview(pdf_bytes, findings, page_count)

    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Proceed to Review →", type="primary", use_container_width=True):
            st.session_state["stage"] = "Review"
            st.rerun()
    with col2:
        if st.button("Re-run inspection", use_container_width=True):
            st.rerun()


# ── Stage: Review ─────────────────────────────────────────────────────────────
elif st.session_state["stage"] == "Review":
    findings = render_review(
        st.session_state["findings"],
        st.session_state["reviewer_name"],
    )
    st.session_state["findings"] = findings

    st.divider()
    pending = sum(1 for f in findings if not f.review_decision or f.review_decision == FindingDecision.PENDING)
    redact_count = sum(1 for f in findings if f.review_decision == FindingDecision.REDACT)

    if pending > 0:
        st.warning(f"{pending} finding(s) still pending a decision.")
    else:
        st.success(f"All findings reviewed. {redact_count} finding(s) selected for redaction.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("← Back to Inspection", use_container_width=True):
            st.session_state["stage"] = "Inspect"
            st.rerun()
    with col2:
        disabled = pending > 0
        if st.button(
            "Create sanitized document →",
            type="primary",
            use_container_width=True,
            disabled=disabled,
            help="Decide all findings first." if disabled else None,
        ):
            # Confirmation
            st.session_state["stage"] = "Sanitize"
            st.rerun()


# ── Stage: Sanitize ───────────────────────────────────────────────────────────
elif st.session_state["stage"] == "Sanitize":
    st.markdown("## Creating Sanitized Document")

    findings: list[Finding] = st.session_state["findings"]
    pdf_bytes: bytes = st.session_state["pdf_bytes"]
    filename: str = st.session_state["filename"]
    provider = get_provider()

    approved = [f for f in findings if f.review_decision == FindingDecision.REDACT]
    st.info(f"Applying **{len(approved)}** permanent redaction(s)…")

    with st.spinner("Applying redactions via Nutrient…"):
        try:
            sanitized_bytes, redact_results = apply_redactions(
                provider, pdf_bytes, approved, filename=filename
            )
        except Exception as e:
            st.error(f"Redaction failed: {e}")
            sanitized_bytes = pdf_bytes
            redact_results = []

    with st.spinner("Verifying sanitized document…"):
        verification = verify_redactions(pdf_bytes, sanitized_bytes, approved, redact_results)

    st.session_state["sanitized_pdf"] = sanitized_bytes
    st.session_state["verification"] = verification

    # Re-inspect sanitized PDF
    with st.spinner("Re-extracting sanitized document…"):
        re_elements, _ = extract_with_pymupdf(sanitized_bytes)
        re_inj = detect_injections(re_elements)
        re_sens = detect_sensitive_data(re_elements)
        re_risk = compute_risk(re_inj + re_sens)

    if verification.get("passed"):
        st.success("✓ Sanitized document verified successfully.")
    else:
        st.error("✗ Verification found issues. Download marked as diagnostic only.")

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk score (original)", st.session_state["risk"].score if st.session_state["risk"] else "N/A")
    col2.metric("Risk score (sanitized)", re_risk.score)
    col3.metric("Redactions applied", len([r for r in redact_results if r.success]))

    # Build audit record
    audit = build_audit_record(
        session_id=st.session_state["session_id"],
        reviewer_name=st.session_state["reviewer_name"],
        original_filename=filename,
        original_pdf_bytes=pdf_bytes,
        findings=findings,
        provider_mode=provider.provider_name,
        page_count=st.session_state["page_count"],
        sanitized_pdf_bytes=sanitized_bytes,
        verification_details=verification,
        started_at=st.session_state["started_at"],
    )
    st.session_state["audit"] = audit

    st.divider()
    if st.button("View comparison & report →", type="primary", use_container_width=True):
        st.session_state["stage"] = "Report"
        st.rerun()


# ── Stage: Report ─────────────────────────────────────────────────────────────
elif st.session_state["stage"] == "Report":
    sanitized = st.session_state.get("sanitized_pdf")
    verification = st.session_state.get("verification", {})
    audit = st.session_state.get("audit")
    filename = st.session_state.get("filename", "document.pdf")
    original_pdf = st.session_state.get("pdf_bytes")
    page_count = st.session_state.get("page_count", 1)

    if sanitized and original_pdf:
        render_comparison(original_pdf, sanitized, page_count, verification)
        st.divider()

    if audit:
        render_report(audit, sanitized, filename)
    else:
        st.warning("No audit record available. Complete the sanitization step first.")

    st.divider()
    if st.button("← Back to Review", use_container_width=True):
        st.session_state["stage"] = "Review"
        st.rerun()
