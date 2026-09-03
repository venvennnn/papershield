"""
Inspection component: runs the full pipeline and shows risk summary + page preview with overlays.
"""
from __future__ import annotations

import io
import time
from typing import List

import streamlit as st
from PIL import Image, ImageDraw, ImageFont

from papershield.models.document import (
    Finding, FindingCategory, RiskScore, ProcessingStage,
)
from papershield.services.extraction_normalizer import (
    render_page_to_png, get_page_dimensions,
)

# Color map for finding categories (RGBA)
CATEGORY_COLORS = {
    FindingCategory.PROMPT_INJECTION: (220, 38, 38, 180),      # red
    FindingCategory.SENSITIVE_DATA: (124, 58, 237, 180),        # purple
    FindingCategory.SUSPICIOUS_LINK: (217, 119, 6, 180),        # amber
    FindingCategory.ACTIVE_CONTENT: (217, 119, 6, 180),         # amber
    FindingCategory.VISIBILITY_DISCREPANCY: (37, 99, 235, 180), # blue
    FindingCategory.METADATA: (107, 114, 128, 180),             # gray
}

SEVERITY_LABEL_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#16a34a",
}


def render_processing_progress(stages: List[str], current_stage: str) -> None:
    """Show a progress bar and stage list."""
    total = len(stages)
    done = stages.index(current_stage) if current_stage in stages else 0
    st.progress(done / total, text=f"⏳ {current_stage}")


def render_risk_summary(risk: RiskScore, findings: List[Finding]) -> None:
    """Display risk score and component breakdown."""
    color = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#ca8a04",
        "Low": "#16a34a",
    }.get(risk.label, "#374151")

    st.markdown(
        f"""
        <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:20px 24px;margin-bottom:16px;">
          <div style="font-size:13px;color:#6b7280;font-weight:500;letter-spacing:.05em;text-transform:uppercase;">
            Document Risk Score
          </div>
          <div style="display:flex;align-items:baseline;gap:12px;margin-top:4px;">
            <span style="font-size:52px;font-weight:700;color:{color};line-height:1">{risk.score}</span>
            <span style="font-size:22px;font-weight:600;color:{color}">{risk.label}</span>
          </div>
          {"<div style='font-size:11px;color:#6b7280;margin-top:2px;'>Minimum enforced due to confirmed critical finding.</div>" if risk.forced_minimum else ""}
        </div>
        """,
        unsafe_allow_html=True,
    )

    c = risk.components
    st.markdown("**Risk component breakdown**")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Injection (40%)", f"{c.injection:.2f}", delta=None)
    col2.metric("Sensitive (25%)", f"{c.sensitive:.2f}", delta=None)
    col3.metric("Hidden (20%)", f"{c.hidden:.2f}", delta=None)
    col4.metric("Active (15%)", f"{c.active:.2f}", delta=None)

    with st.expander("Component bar chart"):
        import pandas as pd
        df = pd.DataFrame({
            "Component": ["Injection", "Sensitive Data", "Hidden Content", "Active Content"],
            "Score": [c.injection, c.sensitive, c.hidden, c.active],
            "Weight": [0.40, 0.25, 0.20, 0.15],
        })
        st.bar_chart(df.set_index("Component")["Score"])

    # Summary counts
    inj_count = sum(1 for f in findings if f.category == FindingCategory.PROMPT_INJECTION)
    sens_count = sum(1 for f in findings if f.category == FindingCategory.SENSITIVE_DATA)
    hidden_count = sum(1 for f in findings if f.category == FindingCategory.VISIBILITY_DISCREPANCY)
    active_count = sum(1 for f in findings if f.category in (FindingCategory.ACTIVE_CONTENT, FindingCategory.SUSPICIOUS_LINK, FindingCategory.METADATA))
    pages_affected = len({f.page for f in findings})

    cols = st.columns(5)
    cols[0].metric("Injection findings", inj_count)
    cols[1].metric("Sensitive data", sens_count)
    cols[2].metric("Hidden content", hidden_count)
    cols[3].metric("Active content", active_count)
    cols[4].metric("Pages affected", pages_affected)


def render_page_preview(
    pdf_bytes: bytes,
    findings: List[Finding],
    page_count: int,
    selected_finding_id: str | None = None,
) -> str | None:
    """Render page navigator + annotated page image. Returns clicked finding_id or None."""
    st.markdown("### Page Preview")

    col_nav, col_legend = st.columns([3, 2])
    with col_nav:
        page_num = st.number_input(
            "Page", min_value=1, max_value=max(page_count, 1), value=1, step=1,
            key="page_navigator",
        )
    with col_legend:
        st.markdown(
            "<div style='font-size:12px;line-height:1.8'>"
            "<span style='color:#dc2626'>■</span> Prompt injection &nbsp;"
            "<span style='color:#7c3aed'>■</span> Sensitive data &nbsp;"
            "<span style='color:#d97706'>■</span> Suspicious/active &nbsp;"
            "<span style='color:#2563eb'>■</span> Hidden text"
            "</div>",
            unsafe_allow_html=True,
        )

    try:
        png_bytes = render_page_to_png(pdf_bytes, page_num, dpi=110)
        img = Image.open(io.BytesIO(png_bytes)).convert("RGBA")
        width_pt, height_pt = get_page_dimensions(pdf_bytes, page_num)
        img_w, img_h = img.size
        scale_x = img_w / width_pt
        scale_y = img_h / height_pt

        overlay = Image.new("RGBA", img.size, (255, 255, 255, 0))
        draw = ImageDraw.Draw(overlay)

        page_findings = [f for f in findings if f.page == page_num]
        for f in page_findings:
            if not f.bbox:
                continue
            x1, y1, x2, y2 = f.bbox
            px1 = int(x1 * scale_x)
            py1 = int(y1 * scale_y)
            px2 = int(x2 * scale_x)
            py2 = int(y2 * scale_y)
            color = CATEGORY_COLORS.get(f.category, (107, 114, 128, 180))
            # Fill
            draw.rectangle([px1, py1, px2, py2], fill=color[:3] + (50,))
            # Border
            draw.rectangle([px1, py1, px2, py2], outline=color[:3] + (220,), width=2)

        combined = Image.alpha_composite(img, overlay).convert("RGB")
        st.image(combined, use_container_width=True, caption=f"Page {page_num} of {page_count}")

        if page_findings:
            st.markdown(f"**{len(page_findings)} finding(s) on this page:**")
            for f in page_findings:
                sev_color = SEVERITY_LABEL_COLORS.get(f.severity.value, "#374151")
                label = f.category.value.replace("_", " ").title()
                is_selected = f.finding_id == selected_finding_id
                border = "2px solid #2563eb" if is_selected else "1px solid #e5e7eb"
                st.markdown(
                    f"<div style='background:#f9fafb;border:{border};border-radius:6px;"
                    f"padding:8px 12px;margin-bottom:6px;cursor:pointer;'>"
                    f"<span style='color:{sev_color};font-weight:600;font-size:12px'>{f.severity.value}</span>"
                    f" · <span style='font-size:12px'>{label}</span>"
                    f"<br/><span style='color:#374151;font-size:12px'>{f.evidence[:80]}{'…' if len(f.evidence)>80 else ''}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
    except Exception as e:
        st.warning(f"Could not render page preview: {e}")

    return None
