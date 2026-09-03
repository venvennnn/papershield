"""
Nutrient provider interface.

LiveNutrientProvider: calls real Nutrient APIs.
DemoNutrientProvider: returns fixture data for demo/testing.
"""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, List, Dict, Any

import io

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from papershield.models.document import DocumentElement, BoundingBox


NUTRIENT_BASE_URL = os.environ.get("NUTRIENT_BASE_URL", "https://api.nutrient.io")
NUTRIENT_API_KEY = os.environ.get("NUTRIENT_API_KEY", "")

_DEMO_FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "demo_extraction.json"


class NutrientProvider(ABC):
    """Abstract provider interface."""

    @abstractmethod
    def extract_document(self, pdf_bytes: bytes, filename: str = "document.pdf") -> List[DocumentElement]:
        ...

    @abstractmethod
    def apply_ocr(self, pdf_bytes: bytes) -> List[DocumentElement]:
        ...

    @abstractmethod
    def apply_redactions(
        self,
        pdf_bytes: bytes,
        redaction_regions: List[Dict[str, Any]],
        filename: str = "document.pdf",
    ) -> bytes:
        ...

    def render_pages(self, pdf_bytes: bytes) -> List[bytes]:
        """Optional: render each page to PNG bytes. Default: not implemented."""
        raise NotImplementedError

    @property
    def provider_name(self) -> str:
        return self.__class__.__name__

    @property
    def version(self) -> str:
        return "1.0"


class LiveNutrientProvider(NutrientProvider):
    """Calls Nutrient Data Extraction and DWS Processor APIs."""

    def __init__(self, api_key: str = "", base_url: str = ""):
        self._api_key = api_key or NUTRIENT_API_KEY
        self._base_url = (base_url or NUTRIENT_BASE_URL).rstrip("/")
        if not self._api_key:
            raise ValueError("NUTRIENT_API_KEY is not configured.")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
        }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=16))
    def extract_document(self, pdf_bytes: bytes, filename: str = "document.pdf") -> List[DocumentElement]:
        """Use Nutrient Data Extraction API to extract text with coordinates."""
        url = f"{self._base_url}/v1/extract"
        files = {"file": (filename, pdf_bytes, "application/pdf")}
        data = {"output_formats": "json", "extract_coordinates": "true"}
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(url, headers=self._headers(), files=files, data=data)
            resp.raise_for_status()
        return _parse_nutrient_extraction(resp.json())

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=16))
    def apply_ocr(self, pdf_bytes: bytes) -> List[DocumentElement]:
        """Apply OCR via Nutrient processing endpoint and extract text."""
        url = f"{self._base_url}/v1/process"
        files = {"file": ("document.pdf", pdf_bytes, "application/pdf")}
        data = {"operations": json.dumps({"ocr": {}})}
        with httpx.Client(timeout=120.0) as client:
            resp = client.post(url, headers=self._headers(), files=files, data=data)
            resp.raise_for_status()
        ocr_pdf = resp.content
        return self.extract_document(ocr_pdf, "ocr_result.pdf")

    def apply_redactions(
        self,
        pdf_bytes: bytes,
        redaction_regions: List[Dict[str, Any]],
        filename: str = "document.pdf",
    ) -> bytes:
        """Apply permanent redactions via Nutrient DWS Processor API."""
        # Build redaction annotation objects per Nutrient spec
        annotations = []
        for region in redaction_regions:
            page = region.get("page", 1)
            bbox = region.get("bbox", [0, 0, 100, 20])
            annotations.append({
                "type": "pspdfkit/markup/redaction",
                "pageIndex": page - 1,
                "rects": [[bbox[0], bbox[1], bbox[2] - bbox[0], bbox[3] - bbox[1]]],
                "fillColor": "#000000",
            })

        operations = [
            {"type": "addRedactions", "annotations": annotations},
            {"type": "applyRedactions"},
        ]
        payload = json.dumps({"parts": [{"file": "file"}], "operations": operations})

        url = f"{self._base_url}/v1/process"
        files = {
            "file": (filename, pdf_bytes, "application/pdf"),
            "instructions": (None, payload, "application/json"),
        }
        with httpx.Client(timeout=120.0) as client:
            resp = client.post(url, headers=self._headers(), files=files)
            resp.raise_for_status()
        return resp.content

    @property
    def provider_name(self) -> str:
        return "LiveNutrient"


class DemoNutrientProvider(NutrientProvider):
    """Returns fixture data; used when credentials are absent or DEMO_MODE=true."""

    def extract_document(self, pdf_bytes: bytes, filename: str = "document.pdf") -> List[DocumentElement]:
        return _load_fixture_elements()

    def apply_ocr(self, pdf_bytes: bytes) -> List[DocumentElement]:
        return _load_fixture_elements()

    def apply_redactions(
        self,
        pdf_bytes: bytes,
        redaction_regions: List[Dict[str, Any]],
        filename: str = "document.pdf",
    ) -> bytes:
        """Demo redaction: use PyMuPDF to apply visual redactions locally."""
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            for region in redaction_regions:
                page_num = region.get("page", 1) - 1
                bbox = region.get("bbox")
                if bbox and 0 <= page_num < len(doc):
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
    """Return the appropriate provider based on environment."""
    demo_mode = os.environ.get("DEMO_MODE", "true").lower() in ("1", "true", "yes")
    api_key = os.environ.get("NUTRIENT_API_KEY", "")
    if demo_mode or not api_key:
        return DemoNutrientProvider()
    return LiveNutrientProvider(api_key=api_key)


def _parse_nutrient_extraction(payload: Dict[str, Any]) -> List[DocumentElement]:
    """Normalize Nutrient extraction API response into DocumentElements."""
    elements: List[DocumentElement] = []
    pages = payload.get("pages", payload.get("data", {}).get("pages", []))
    for page_data in pages:
        page_num = page_data.get("pageNumber", page_data.get("index", 0)) + 1
        for block in page_data.get("textBlocks", page_data.get("blocks", [])):
            text = block.get("text", "").strip()
            if not text:
                continue
            raw_bbox = block.get("boundingBox", block.get("bbox"))
            bbox = None
            if raw_bbox:
                if isinstance(raw_bbox, dict):
                    bbox = BoundingBox(
                        x1=raw_bbox.get("left", raw_bbox.get("x1", 0)),
                        y1=raw_bbox.get("top", raw_bbox.get("y1", 0)),
                        x2=raw_bbox.get("right", raw_bbox.get("x2", 100)),
                        y2=raw_bbox.get("bottom", raw_bbox.get("y2", 20)),
                    )
                elif isinstance(raw_bbox, list) and len(raw_bbox) == 4:
                    bbox = BoundingBox(x1=raw_bbox[0], y1=raw_bbox[1], x2=raw_bbox[2], y2=raw_bbox[3])
            elements.append(DocumentElement(
                page=page_num,
                text=text,
                bbox=bbox,
                confidence=block.get("confidence"),
                source="digital",
            ))
    return elements


def _load_fixture_elements() -> List[DocumentElement]:
    """Load demo extraction fixture."""
    if _DEMO_FIXTURE_PATH.exists():
        data = json.loads(_DEMO_FIXTURE_PATH.read_text())
        return [DocumentElement(**e) for e in data]
    return []
