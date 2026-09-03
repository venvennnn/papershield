"""
Normalize raw extraction output from Nutrient or PyMuPDF into DocumentElements.
Also provides a local fallback extractor using PyMuPDF.
"""
from __future__ import annotations

from typing import List, Tuple
import fitz  # PyMuPDF

from papershield.models.document import DocumentElement, BoundingBox


def extract_with_pymupdf(pdf_bytes: bytes) -> Tuple[List[DocumentElement], int]:
    """Extract text and coordinates from a PDF using PyMuPDF (digital layer only)."""
    elements: List[DocumentElement] = []
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    page_count = len(doc)
    for page_num, page in enumerate(doc, start=1):
        blocks = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)["blocks"]
        order = 0
        for block in blocks:
            if block.get("type") != 0:  # 0 = text
                continue
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    text = span.get("text", "").strip()
                    if not text:
                        continue
                    bbox_raw = span.get("bbox")
                    bbox = BoundingBox(x1=bbox_raw[0], y1=bbox_raw[1], x2=bbox_raw[2], y2=bbox_raw[3]) if bbox_raw else None
                    elements.append(DocumentElement(
                        page=page_num,
                        text=text,
                        bbox=bbox,
                        source="digital",
                        reading_order=order,
                    ))
                    order += 1
    doc.close()
    return elements, page_count


def render_page_to_png(pdf_bytes: bytes, page_num: int, dpi: int = 120) -> bytes:
    """Render a single PDF page (1-indexed) to PNG bytes."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    if page_num < 1 or page_num > len(doc):
        doc.close()
        raise ValueError(f"Page {page_num} out of range")
    page = doc[page_num - 1]
    mat = fitz.Matrix(dpi / 72, dpi / 72)
    pix = page.get_pixmap(matrix=mat, alpha=False)
    png_bytes = pix.tobytes("png")
    doc.close()
    return png_bytes


def get_page_dimensions(pdf_bytes: bytes, page_num: int) -> Tuple[float, float]:
    """Return (width, height) of a page in PDF points."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    page = doc[page_num - 1]
    rect = page.rect
    doc.close()
    return rect.width, rect.height
