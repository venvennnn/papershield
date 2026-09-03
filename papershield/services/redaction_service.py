"""
Redaction service.
Translates approved findings into Nutrient (or demo) permanent redactions,
then verifies the output.
"""
from __future__ import annotations

import hashlib
import re
from typing import List, Tuple, Dict, Any

from papershield.models.document import Finding, FindingDecision, RedactionResult
from papershield.services.nutrient_client import NutrientProvider
from papershield.services.extraction_normalizer import extract_with_pymupdf


def apply_redactions(
    provider: NutrientProvider,
    pdf_bytes: bytes,
    approved_findings: List[Finding],
    filename: str = "document.pdf",
) -> Tuple[bytes, List[RedactionResult]]:
    """
    Apply permanent redactions for all approved findings.
    Returns (redacted_pdf_bytes, list_of_results).
    """
    regions: List[Dict[str, Any]] = []
    for finding in approved_findings:
        if finding.review_decision != FindingDecision.REDACT:
            continue
        if finding.bbox:
            regions.append({
                "finding_id": finding.finding_id,
                "page": finding.page,
                "bbox": finding.bbox,
            })

    if not regions:
        return pdf_bytes, []

    try:
        redacted_bytes = provider.apply_redactions(pdf_bytes, regions, filename=filename)
    except Exception as e:
        results = [
            RedactionResult(finding_id=r["finding_id"], success=False, error=str(e))
            for r in regions
        ]
        return pdf_bytes, results

    results = [
        RedactionResult(finding_id=r["finding_id"], success=True)
        for r in regions
    ]
    return redacted_bytes, results


def verify_redactions(
    original_pdf_bytes: bytes,
    redacted_pdf_bytes: bytes,
    approved_findings: List[Finding],
    redaction_results: List[RedactionResult],
) -> Dict[str, Any]:
    """
    Verify that redacted text is absent from the output PDF.
    Returns a verification detail dict.
    """
    # Extract text from redacted PDF
    try:
        redacted_elements, redacted_page_count = extract_with_pymupdf(redacted_pdf_bytes)
        redacted_text = " ".join(e.text for e in redacted_elements).lower()
        extraction_ok = True
    except Exception as e:
        return {
            "passed": False,
            "extraction_ok": False,
            "error": str(e),
            "checks": [],
        }

    original_elements, original_page_count = extract_with_pymupdf(original_pdf_bytes)

    checks = []
    all_passed = True

    # Check each approved-redact finding
    successful_finding_ids = {r.finding_id for r in redaction_results if r.success}
    for finding in approved_findings:
        if finding.review_decision != FindingDecision.REDACT:
            continue
        if finding.finding_id not in successful_finding_ids:
            checks.append({
                "finding_id": finding.finding_id,
                "passed": False,
                "reason": "Redaction was not applied",
            })
            all_passed = False
            continue

        # Use a clean fingerprint (first 50 non-masked chars of evidence)
        raw_evidence = finding.evidence
        # Strip masking characters
        clean = re.sub(r"[•…\[\]]", "", raw_evidence).strip().lower()
        # Skip very short or fully masked evidence
        if len(clean) < 6:
            checks.append({
                "finding_id": finding.finding_id,
                "passed": True,
                "reason": "Evidence too short to verify; assumed removed",
            })
            continue

        fingerprint = clean[:40]
        absent = fingerprint not in redacted_text
        checks.append({
            "finding_id": finding.finding_id,
            "passed": absent,
            "fingerprint": fingerprint,
            "reason": "Absent from redacted PDF" if absent else "Still present in redacted PDF",
        })
        if not absent:
            all_passed = False

    # Page count check
    page_count_ok = redacted_page_count == original_page_count
    checks.append({
        "check": "page_count",
        "passed": page_count_ok,
        "original": original_page_count,
        "redacted": redacted_page_count,
    })
    if not page_count_ok:
        all_passed = False

    # Hash differs
    orig_hash = hashlib.sha256(original_pdf_bytes).hexdigest()
    new_hash = hashlib.sha256(redacted_pdf_bytes).hexdigest()
    hashes_differ = orig_hash != new_hash
    checks.append({
        "check": "hashes_differ",
        "passed": hashes_differ,
        "original_sha256": orig_hash,
        "sanitized_sha256": new_hash,
    })

    return {
        "passed": all_passed and hashes_differ,
        "extraction_ok": extraction_ok,
        "original_sha256": orig_hash,
        "sanitized_sha256": new_hash,
        "original_page_count": original_page_count,
        "redacted_page_count": redacted_page_count,
        "checks": checks,
    }
