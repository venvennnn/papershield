"""
Builds the immutable audit record for a PaperShield session.
Sensitive values are masked; raw credentials are never included.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from papershield.models.document import (
    AuditRecord, Finding, FindingDecision, WorkflowStatus,
)


def build_audit_record(
    session_id: str,
    reviewer_name: str,
    original_filename: str,
    original_pdf_bytes: bytes,
    findings: List[Finding],
    provider_mode: str,
    page_count: int,
    sanitized_pdf_bytes: Optional[bytes] = None,
    verification_details: Optional[Dict[str, Any]] = None,
    started_at: Optional[str] = None,
) -> AuditRecord:
    original_sha256 = hashlib.sha256(original_pdf_bytes).hexdigest()
    sanitized_sha256 = hashlib.sha256(sanitized_pdf_bytes).hexdigest() if sanitized_pdf_bytes else None

    now = datetime.now(timezone.utc).isoformat()
    started_at = started_at or now

    detectors = [
        {"name": "injection_detector", "version": "rule:injection_v2"},
        {"name": "sensitive_data_detector", "version": "rule:sensitive_v1"},
        {"name": "visibility_comparator", "version": "visibility:layer_comparison_v1"},
        {"name": "pdf_static_inspector", "version": "static:v1"},
    ]

    serialized_findings = [_serialize_finding(f) for f in findings]

    # Determine workflow status
    unresolved_critical = sum(
        1 for f in findings
        if f.review_decision in (None, FindingDecision.PENDING, FindingDecision.ESCALATE)
        and f.severity.value in ("Critical", "High")
    )

    if sanitized_sha256 and verification_details and verification_details.get("passed"):
        status = WorkflowStatus.SANITIZED
    elif any(f.review_decision == FindingDecision.ESCALATE for f in findings):
        status = WorkflowStatus.BLOCKED
    elif unresolved_critical > 0:
        status = WorkflowStatus.REVIEW_INCOMPLETE
    elif sanitized_sha256:
        status = WorkflowStatus.SANITIZATION_PENDING
    else:
        status = WorkflowStatus.NEEDS_REVIEW

    return AuditRecord(
        session_id=session_id,
        reviewer_name=reviewer_name,
        original_filename=original_filename,
        original_sha256=original_sha256,
        sanitized_sha256=sanitized_sha256,
        processing_started_at=started_at,
        processing_completed_at=now,
        provider_mode=provider_mode,
        extraction_version="1.0",
        detectors=detectors,
        findings=serialized_findings,
        verification_details=verification_details or {},
        verification_passed=bool(verification_details and verification_details.get("passed")),
        unresolved_critical_count=unresolved_critical,
        workflow_status=status,
        page_count=page_count,
        sanitized_page_count=verification_details.get("redacted_page_count") if verification_details else None,
    )


def _serialize_finding(f: Finding) -> Dict[str, Any]:
    """Serialize finding for audit log, masking raw sensitive evidence."""
    return {
        "finding_id": f.finding_id,
        "category": f.category.value,
        "subtype": f.subtype,
        "page": f.page,
        "bbox": f.bbox,
        "evidence": _mask_evidence(f),
        "detector": f.detector,
        "confidence": f.confidence,
        "severity": f.severity.value,
        "visibility": f.visibility.value,
        "recommended_action": f.recommended_action.value,
        "review_decision": f.review_decision.value if f.review_decision else None,
        "review_reason": f.review_reason,
        "reviewed_at": f.reviewed_at,
        "reviewed_by": f.reviewed_by,
    }


def _mask_evidence(f: Finding) -> str:
    """Evidence is already masked at detection time for sensitive data."""
    return f.evidence[:300]


def to_markdown(audit: AuditRecord) -> str:
    lines = [
        "# PaperShield Audit Report",
        f"",
        f"**Session ID:** `{audit.session_id}`  ",
        f"**Reviewer:** {audit.reviewer_name}  ",
        f"**File:** {audit.original_filename}  ",
        f"**Processing started:** {audit.processing_started_at}  ",
        f"**Processing completed:** {audit.processing_completed_at}  ",
        f"**Provider mode:** {audit.provider_mode}  ",
        f"**Workflow status:** {audit.workflow_status.value}  ",
        f"",
        f"## Document Integrity",
        f"",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Original SHA-256 | `{audit.original_sha256}` |",
        f"| Sanitized SHA-256 | `{audit.sanitized_sha256 or 'N/A'}` |",
        f"| Original page count | {audit.page_count} |",
        f"| Sanitized page count | {audit.sanitized_page_count or 'N/A'} |",
        f"| Verification passed | {'✓ Yes' if audit.verification_passed else '✗ No'} |",
        f"",
        f"## Findings Summary",
        f"",
        f"Total findings: {len(audit.findings)}  ",
        f"Unresolved critical/high: {audit.unresolved_critical_count}  ",
        f"",
        f"| # | Category | Severity | Page | Decision | Detector |",
        f"|---|---|---|---|---|---|",
    ]
    for i, f in enumerate(audit.findings, 1):
        decision = f.get("review_decision") or "Pending"
        lines.append(
            f"| {i} | {f['category']} | {f['severity']} | {f['page']} | {decision} | {f['detector']} |"
        )

    lines += [
        f"",
        f"## Detectors Used",
        f"",
    ]
    for d in audit.detectors:
        lines.append(f"- **{d['name']}** `{d['version']}`")

    if audit.verification_details:
        lines += [
            f"",
            f"## Verification Checks",
            f"",
        ]
        for check in audit.verification_details.get("checks", []):
            status = "✓" if check.get("passed") else "✗"
            reason = check.get("reason", check.get("check", ""))
            lines.append(f"- {status} {reason}")

    lines += [
        f"",
        f"---",
        f"*Generated by PaperShield. This report shows what was detected and reviewed.*",
        f"*It does not certify that the document is safe or legally compliant.*",
    ]
    return "\n".join(lines)
