"""Upload component: file picker, sample document selector, privacy notice."""
from __future__ import annotations

import hashlib
import io
from pathlib import Path

import streamlit as st

SAMPLE_DIR = Path(__file__).parent.parent / "sample_documents"
MAX_SIZE_MB = 25
MAX_PAGES = 100


def render_upload() -> tuple[bytes | None, str]:
    """
    Render the upload UI. Returns (pdf_bytes, filename) or (None, "").
    """
    st.markdown("## Upload Document")

    # Privacy notice
    with st.expander("Privacy & Data Notice", expanded=False):
        st.markdown(
            """
            - Your document is processed **in this session only** and deleted when the session ends.
            - No document content is stored, logged, or sent to third parties beyond the configured Nutrient API.
            - API keys are kept server-side and are never exposed to the browser.
            - Do not upload documents containing real production secrets or live credentials.
            """
        )

    tab_upload, tab_sample = st.tabs(["Upload your PDF", "Use sample document"])

    with tab_upload:
        uploaded = st.file_uploader(
            "Choose a PDF file (max 25 MB)",
            type=["pdf"],
            label_visibility="collapsed",
        )
        if uploaded is not None:
            raw = uploaded.read()
            err = _validate(raw, uploaded.name)
            if err:
                st.error(err)
                return None, ""
            _show_summary(raw, uploaded.name)
            return raw, uploaded.name

    with tab_sample:
        samples = sorted(SAMPLE_DIR.glob("*.pdf"))
        if not samples:
            st.info("No sample documents found. Run `python -m papershield.fixtures.create_demo_pdf` to generate one.")
            return None, ""

        names = [s.name for s in samples]
        choice = st.selectbox("Select a sample document", names)
        sample_path = SAMPLE_DIR / choice
        raw = sample_path.read_bytes()
        err = _validate(raw, choice)
        if err:
            st.error(err)
            return None, ""
        st.info(f"Sample document: **{choice}** — contains deliberately embedded synthetic threats for demo purposes.")
        _show_summary(raw, choice)
        return raw, choice

    return None, ""


def _validate(data: bytes, name: str) -> str | None:
    # MIME check: PDF starts with %PDF
    if not data[:4] == b"%PDF":
        return f"'{name}' is not a valid PDF file (MIME signature mismatch)."
    size_mb = len(data) / (1024 * 1024)
    if size_mb > MAX_SIZE_MB:
        return f"File is {size_mb:.1f} MB, exceeding the {MAX_SIZE_MB} MB limit."
    return None


def _show_summary(data: bytes, name: str) -> None:
    sha = hashlib.sha256(data).hexdigest()
    size_kb = len(data) / 1024
    col1, col2, col3 = st.columns(3)
    col1.metric("Filename", name[:28] + ("…" if len(name) > 28 else ""))
    col2.metric("Size", f"{size_kb:.1f} KB")
    col3.metric("SHA-256", sha[:12] + "…")
    with st.expander("Full SHA-256"):
        st.code(sha, language=None)
