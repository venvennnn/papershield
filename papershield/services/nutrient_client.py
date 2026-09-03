"""
Nutrient provider interface.

LiveNutrientProvider: calls the real Nutrient DWS APIs.
  - Extraction:  POST https://api.nutrient.io/extraction/parse
  - Redaction:   POST https://api.nutrient.io/build  (Processor API)
  Authentication: Authorization: Bearer <pdf_live_...>

DemoNutrientProvider: returns fixture data; shown when credentials are absent.

Hackathon note
--------------
The campaign URL https://api.nutrient.io/campaigns/api-world-cloudx-ai-hackathon-2026/
redirects to the Nutrient dashboard (dashboard.nutrient.io).
Sign in there with the hackathon credentials to retrieve a pdf_live_... API key,
then set NUTRIENT_API_KEY to that value and DEMO_MODE=false.
"""
from __future__ import annotations

import io
import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from papershield.models.document import DocumentElement, BoundingBox


NUTRIENT_BASE_URL = os.environ.get("NUTRIENT_BASE_URL", "https://api.nutrient.io")
NUTRIENT_API_KEY = os.environ.get("NUTRIENT_API_KEY", "")

_DEMO_FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "demo_extraction.json"

# Extraction parse endpoint — returns spatial elements with bounding boxes
_PARSE_ENDPOINT = "/extraction/parse"

# Processor API build endpoint — for permanent redaction
_BUILD_ENDPOINT = "/build"


class NutrientProvider(ABC):
    """Abstract provider interface."""

    @abstractmethod
    def extract_document(self, pdf_bytes: bytes, filename: str = "document.pdf") -> List[DocumentElement]:
        """Extract text and spatial elements from a PDF."""
        ...

    @abstractmethod
    def apply_ocr(self, pdf_bytes: bytes) -> List[DocumentElement]:
        """Apply OCR to a scanned PDF and return elements."""
        ...

    @abstractmethod
    def apply_redactions(
        self,
        pdf_bytes: bytes,
        redaction_regions: List[Dict[str, Any]],
        filename: str = "document.pdf",
    ) -> bytes:
        """Apply permanent redactions and return the sanitized PDF bytes."""
        ...

    def render_pages(self, pdf_bytes: bytes) -> List[bytes]:
        raise NotImplementedError

    @property
    def provider_name(self) -> str:
        return self.__class__.__name__

    @property
    def version(self) -> str:
        return "1.0"


class LiveNutrientProvider(NutrientProvider):
    """
    Calls Nutrient DWS APIs with a pdf_live_... API key.

    Extraction uses POST /extraction/parse (Data Extraction API).
    Redaction uses POST /build (Processor API).
    Both use Bearer token authentication.
    """

    def __init__(self, api_key: str = "", base_url: str = ""):
        self._api_key = api_key or NUTRIENT_API_KEY
        self._base_url = (base_url or NUTRIENT_BASE_URL).rstrip("/")
        if not self._api_key:
            raise ValueError("NUTRIENT_API_KEY is not configured.")

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._api_key}"}

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=16))
    def extract_document(self, pdf_bytes: bytes, filename: str = "document.pdf") -> List[DocumentElement]:
        """
        POST /extraction/parse with mode=structure (fast OCR + spatial elements).
        Uses structure mode to get bounding boxes without consuming understand credits
        for every page during inspection.
        """
        url = f"{self._base_url}{_PARSE_ENDPOINT}"
        instructions = json.dumps({
            "mode": "structure",
            "output": {"format": "spatial"},
        })
        with httpx.Client(timeout=90.0) as client:
            resp = client.post(
                url,
                headers=self._headers(),
                files={"file": (filename, pdf_bytes, "application/pdf")},
                data={"instructions": instructions},
            )
            resp.raise_for_status()
        return _parse_extraction_response(resp.json())

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=16))
    def apply_ocr(self, pdf_bytes: bytes) -> List[DocumentElement]:
        """
        POST /extraction/parse with mode=structure — structure mode runs OCR internally.
        We request a second pass with includeWords to get word-level text for comparison.
        """
        url = f"{self._base_url}{_PARSE_ENDPOINT}"
        instructions = json.dumps({
            "mode": "structure",
            "output": {"format": "spatial", "includeWords": True},
        })
        with httpx.Client(timeout=120.0) as client:
            resp = client.post(
                url,
                headers=self._headers(),
                files={"file": ("document.pdf", pdf_bytes, "application/pdf")},
                data={"instructions": instructions},
            )
            resp.raise_for_status()
        return _parse_extraction_response(resp.json())

    def apply_redactions(
        self,
        pdf_bytes: bytes,
        redaction_regions: List[Dict[str, Any]],
        filename: str = "document.pdf",
    ) -> bytes:
        """
        Permanent redaction via Nutrient Processor API POST /build.

        Falls back to PyMuPDF if the account does not have Processor API access
        (e.g. a Data-Extraction-only hackathon key returns 403 on /build).
        The fallback is clearly labeled in the provider_name.
        """
        # Try Nutrient /build first
        try:
            return self._apply_redactions_nutrient(pdf_bytes, redaction_regions, filename)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                # Processor API not enabled for this key — fall back to PyMuPDF
                self._processor_api_available = False
                return _pymupdf_redact(pdf_bytes, redaction_regions)
            raise

    def _apply_redactions_nutrient(
        self,
        pdf_bytes: bytes,
        redaction_regions: List[Dict[str, Any]],
        filename: str,
    ) -> bytes:
        """Call Nutrient /build with coordinate-based redaction annotations."""
        import fitz
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        page_heights = {i + 1: doc[i].rect.height for i in range(len(doc))}
        doc.close()

        annotations = []
        for region in redaction_regions:
            page = region.get("page", 1)
            bbox = region.get("bbox")
            if not bbox or len(bbox) != 4:
                continue
            x1, y1, x2, y2 = bbox
            ph = page_heights.get(page, 792.0)
            # Convert top-left origin → PDF bottom-left origin
            pdf_y = ph - y2
            annotations.append({
                "v": 1,
                "type": "pspdfkit/markup/redaction",
                "pageIndex": page - 1,
                "rects": [[x1, pdf_y, x2 - x1, y2 - y1]],
                "fillColor": "#000000",
                "overlayText": "",
            })

        instructions = {
            "parts": [{"file": "document"}],
            "actions": [
                {"type": "addRedactions", "redactions": annotations},
                {"type": "applyRedactions"},
            ],
        }

        url = f"{self._base_url}{_BUILD_ENDPOINT}"
        with httpx.Client(timeout=120.0) as client:
            resp = client.post(
                url,
                headers=self._headers(),
                files={
                    "document": (filename, pdf_bytes, "application/pdf"),
                    "instructions": (None, json.dumps(instructions), "application/json"),
                },
            )
            resp.raise_for_status()
        return resp.content

    @property
    def provider_name(self) -> str:
        if getattr(self, "_processor_api_available", True) is False:
            return "LiveNutrient·Extract+LocalRedact"
        return "LiveNutrient"


class DemoNutrientProvider(NutrientProvider):
    """
    Returns fixture data when Nutrient credentials are absent or DEMO_MODE=true.
    Redaction is applied locally via PyMuPDF.
    Shows 'Prepared demo' badge in the UI.
    """

    def extract_document(self, pdf_bytes: bytes, filename: str = "document.pdf") -> List[DocumentElement]:
        return _load_fixture_elements()

    def apply_ocr(self, pdf_bytes: bytes) -> List[DocumentElement]:
        # In demo mode, OCR returns same elements (digital extraction is already done)
        return _load_fixture_elements()

    def apply_redactions(
        self,
        pdf_bytes: bytes,
        redaction_regions: List[Dict[str, Any]],
        filename: str = "document.pdf",
    ) -> bytes:
        """Demo redaction via PyMuPDF — permanent within the copy."""
        try:
            import fitz
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            for region in redaction_regions:
                page_num = region.get("page", 1) - 1
                bbox = region.get("bbox")
                if bbox and len(bbox) == 4 and 0 <= page_num < len(doc):
                    page = doc[page_num]
                    rect = fitz.Rect(bbox[0], bbox[1], bbox[2], bbox[3])
                    page.add_redact_annot(rect, fill=(0, 0, 0))
            for page in doc:
                page.apply_redactions()
            return doc.tobytes(garbage=4, deflate=True)
        except Exception:
            return pdf_bytes

    @property
    def provider_name(self) -> str:
        return "Demo"


def get_provider() -> NutrientProvider:
    """Return the appropriate provider based on environment configuration."""
    demo_mode = os.environ.get("DEMO_MODE", "true").lower() in ("1", "true", "yes")
    api_key = os.environ.get("NUTRIENT_API_KEY", "")
    if demo_mode or not api_key:
        return DemoNutrientProvider()
    return LiveNutrientProvider(api_key=api_key)


# ---------------------------------------------------------------------------
# Response normalizers
# ---------------------------------------------------------------------------

def _parse_extraction_response(payload: Dict[str, Any]) -> List[DocumentElement]:
    """
    Normalize the Nutrient /extraction/parse spatial response.

    Response schema:
      payload["output"]["elements"][i]:
        {
          "type": "paragraph" | "table" | ...,
          "text": "...",
          "confidence": 0.95,
          "readingOrder": 0,
          "bounds": { "x": 100, "y": 50, "width": 400, "height": 35 },
          "page": { "pageIndex": 0, "pageNumber": 1, "width": 1818, "height": 2422 }
        }

    bounds origin: top-left, in render-space pixels.
    We store as BoundingBox(x1, y1, x2, y2) in the same coordinate space.
    """
    elements: List[DocumentElement] = []
    raw_elements = payload.get("output", {}).get("elements", [])

    for item in raw_elements:
        text = _extract_text(item)
        if not text:
            continue

        page_info = item.get("page", {})
        page_num = page_info.get("pageNumber", 1)

        bounds = item.get("bounds")
        bbox = None
        if bounds:
            x = bounds.get("x", 0)
            y = bounds.get("y", 0)
            w = bounds.get("width", 0)
            h = bounds.get("height", 0)
            bbox = BoundingBox(x1=x, y1=y, x2=x + w, y2=y + h)

        elements.append(DocumentElement(
            page=page_num,
            text=text,
            bbox=bbox,
            confidence=item.get("confidence"),
            source="digital",
            reading_order=item.get("readingOrder"),
        ))

    return elements


def _extract_text(item: Dict[str, Any]) -> str:
    """Extract text from an element, handling paragraphs, tables, etc."""
    # Paragraph / handwriting / formula
    if "text" in item:
        return item["text"].strip()

    # Table: concatenate cell text
    if item.get("type") == "table":
        parts = []
        for cell in item.get("cells", []):
            cell_text = cell.get("text", "").strip()
            if cell_text:
                parts.append(cell_text)
        return " ".join(parts)

    # Key-value region
    if item.get("type") == "keyValueRegion":
        parts = []
        for pair in item.get("pairs", []):
            k = pair.get("key", {}).get("text", "")
            v = pair.get("value", {}).get("text", "")
            if k or v:
                parts.append(f"{k}: {v}".strip(": "))
        return " ".join(parts)

    return ""


def _pymupdf_redact(pdf_bytes: bytes, redaction_regions: List[Dict[str, Any]]) -> bytes:
    """Local permanent redaction via PyMuPDF (fallback when Processor API is unavailable)."""
    import fitz
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    for region in redaction_regions:
        page_num = region.get("page", 1) - 1
        bbox = region.get("bbox")
        if bbox and len(bbox) == 4 and 0 <= page_num < len(doc):
            page = doc[page_num]
            rect = fitz.Rect(bbox[0], bbox[1], bbox[2], bbox[3])
            page.add_redact_annot(rect, fill=(0, 0, 0))
    for page in doc:
        page.apply_redactions()
    result = doc.tobytes(garbage=4, deflate=True)
    doc.close()
    return result


def _load_fixture_elements() -> List[DocumentElement]:
    """Load demo extraction fixture from disk."""
    if _DEMO_FIXTURE_PATH.exists():
        data = json.loads(_DEMO_FIXTURE_PATH.read_text())
        return [DocumentElement(**e) for e in data]
    return []
