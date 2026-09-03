"""
Visibility comparator.
Finds text present in the digital (embedded) layer but absent from OCR rendering.
Discrepancies containing injection or sensitive-data language are elevated.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from rapidfuzz import fuzz

from papershield.models.document import (
    DocumentElement, Finding, FindingCategory, FindingDecision,
    Severity, VisibilityType,
)


_INSTRUCTION_HINTS = re.compile(
    r"(ignore|disregard|forget|override|system\s+prompt|assistant|you\s+are|new\s+instruction"
    r"|reveal|secret|api\s+key|tool\s+call|send\s+to|https?://)",
    re.IGNORECASE,
)


def find_hidden_elements(
    digital_elements: List[DocumentElement],
    ocr_elements: List[DocumentElement],
    similarity_threshold: float = 75.0,
) -> Tuple[List[DocumentElement], List[Finding]]:
    """
    Compare digital (embedded text layer) elements against OCR elements.

    Returns:
        hidden_elements: DocumentElements present in digital layer but not OCR.
        findings: Finding objects for significant discrepancies.
    """
    ocr_texts = [e.text.strip().lower() for e in ocr_elements]
    ocr_combined = " ".join(ocr_texts)

    hidden_elements: List[DocumentElement] = []
    findings: List[Finding] = []

    for element in digital_elements:
        text = element.text.strip()
        if not text or len(text) < 4:
            continue

        # Check if digital text has a close match in OCR output
        best_score = 0.0
        for ocr_text in ocr_texts:
            score = fuzz.partial_ratio(text.lower(), ocr_text)
            if score > best_score:
                best_score = score
            if best_score >= similarity_threshold:
                break

        if best_score < similarity_threshold:
            element_hidden = element.model_copy(update={"source": "digital_hidden"})
            hidden_elements.append(element_hidden)

            severity = Severity.MEDIUM
            if _INSTRUCTION_HINTS.search(text):
                severity = Severity.CRITICAL

            findings.append(Finding(
                category=FindingCategory.VISIBILITY_DISCREPANCY,
                subtype="text_layer_only",
                page=element.page,
                bbox=element.bbox.as_list() if element.bbox else None,
                evidence=text[:300],
                detector="visibility:layer_comparison_v1",
                confidence=round((100 - best_score) / 100, 2),
                severity=severity,
                visibility=VisibilityType.TEXT_LAYER_ONLY,
                recommended_action=FindingDecision.REDACT if severity in (Severity.CRITICAL, Severity.HIGH) else FindingDecision.ESCALATE,
            ))

    return hidden_elements, findings
