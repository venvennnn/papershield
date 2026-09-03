"""
Side-by-side comparison of original vs sanitized PDF pages.
"""
from __future__ import annotations

import io
from typing import Optional

import streamlit as st
from PIL import Image

from papershield.services.extraction_normalizer import render_page_to_png


def render_comparison(
    original_pdf: bytes,
    sanitized_pdf: bytes,
    page_count: int,
    verification: dict,
) -> None:
    st.markdown("## Original vs Sanitized")

    page_num = st.number_input(
        "Compare page", min_value=1, max_value=max(page_count, 1), value=1, step=1,
        key="compare_page",
    )

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Original**")
        try:
            img = Image.open(io.BytesIO(render_page_to_png(original_pdf, page_num, dpi=100)))
            st.image(img, use_container_width=True)
        except Exception as e:
            st.error(f"Could not render original page: {e}")

    with col2:
        st.markdown("**Sanitized**")
        try:
            img = Image.open(io.BytesIO(render_page_to_png(sanitized_pdf, page_num, dpi=100)))
            st.image(img, use_container_width=True)
        except Exception as e:
            st.error(f"Could not render sanitized page: {e}")

    # Verification checklist
    st.markdown("### Verification Checklist")
    overall_ok = verification.get("passed", False)
    if overall_ok:
        st.success("✓ All verification checks passed — output is marked **Sanitized and rechecked**")
    else:
        st.error("✗ One or more verification checks failed — output is marked **Review incomplete**")

    for check in verification.get("checks", []):
        icon = "✓" if check.get("passed") else "✗"
        color = "green" if check.get("passed") else "red"
        reason = check.get("reason") or check.get("check", "")
        finding_id = check.get("finding_id", "")
        label = f"{icon} [{finding_id}] {reason}" if finding_id else f"{icon} {reason}"
        st.markdown(f"<span style='color:{color}'>{label}</span>", unsafe_allow_html=True)

    # Hash comparison
    st.markdown("### Document Hashes")
    col1, col2 = st.columns(2)
    col1.code(f"Original:\n{verification.get('original_sha256','N/A')}")
    col2.code(f"Sanitized:\n{verification.get('sanitized_sha256','N/A')}")
