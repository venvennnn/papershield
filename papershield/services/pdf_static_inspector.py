"""
Static PDF structure inspection using pikepdf.
Detects active content, suspicious links, metadata anomalies.
Reports presence only — never executes or dereferences anything.
"""
from __future__ import annotations

import re
from typing import List, Dict, Any
from pathlib import Path

import io as _io

import pikepdf

from papershield.models.document import Finding, FindingCategory, FindingDecision, Severity, VisibilityType


SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    re.compile(r"data:[^;]+;base64,", re.IGNORECASE),
]

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy",
    "is.gd", "buff.ly", "short.io", "cutt.ly",
]


def inspect_pdf_structure(pdf_bytes: bytes) -> List[Finding]:
    findings: List[Finding] = []
    try:
        pdf = pikepdf.open(_io.BytesIO(pdf_bytes))
    except Exception as e:
        return findings

    # JavaScript actions
    findings.extend(_check_javascript(pdf))
    # Launch actions
    findings.extend(_check_launch_actions(pdf))
    # Embedded files
    findings.extend(_check_embedded_files(pdf))
    # Form submit actions
    findings.extend(_check_form_actions(pdf))
    # Suspicious external URLs
    findings.extend(_check_urls(pdf))
    # Metadata
    findings.extend(_check_metadata(pdf))

    pdf.close()
    return findings


def _check_javascript(pdf: pikepdf.Pdf) -> List[Finding]:
    findings = []
    js_found = False
    try:
        if "/Names" in pdf.Root:
            names = pdf.Root["/Names"]
            if "/JavaScript" in names:
                js_found = True
    except Exception:
        pass

    # Walk all pages for AA/JS actions
    for i, page in enumerate(pdf.pages, start=1):
        try:
            page_obj = page.obj
            for key in ["/AA", "/JS", "/JavaScript"]:
                if key in page_obj:
                    js_found = True
        except Exception:
            pass

    if js_found:
        findings.append(Finding(
            category=FindingCategory.ACTIVE_CONTENT,
            subtype="javascript_action",
            page=1,
            bbox=None,
            evidence="JavaScript actions detected in PDF structure",
            detector="static:javascript_action",
            confidence=0.95,
            severity=Severity.CRITICAL,
            visibility=VisibilityType.NORMAL,
            recommended_action=FindingDecision.REDACT,
        ))
    return findings


def _check_launch_actions(pdf: pikepdf.Pdf) -> List[Finding]:
    findings = []
    for i, page in enumerate(pdf.pages, start=1):
        try:
            annots = page.get("/Annots", [])
            for annot in annots:
                try:
                    a = annot.get("/A", {})
                    if a.get("/S") == pikepdf.Name("/Launch"):
                        findings.append(Finding(
                            category=FindingCategory.ACTIVE_CONTENT,
                            subtype="launch_action",
                            page=i,
                            bbox=None,
                            evidence="Launch action annotation detected on page",
                            detector="static:launch_action",
                            confidence=0.99,
                            severity=Severity.CRITICAL,
                            visibility=VisibilityType.NORMAL,
                            recommended_action=FindingDecision.REDACT,
                        ))
                except Exception:
                    pass
        except Exception:
            pass
    return findings


def _check_embedded_files(pdf: pikepdf.Pdf) -> List[Finding]:
    findings = []
    try:
        names = pdf.Root.get("/Names", {})
        ef = names.get("/EmbeddedFiles")
        if ef:
            findings.append(Finding(
                category=FindingCategory.ACTIVE_CONTENT,
                subtype="embedded_file",
                page=1,
                bbox=None,
                evidence="Embedded files detected in PDF",
                detector="static:embedded_files",
                confidence=0.90,
                severity=Severity.HIGH,
                visibility=VisibilityType.NORMAL,
                recommended_action=FindingDecision.ESCALATE,
            ))
    except Exception:
        pass
    return findings


def _check_form_actions(pdf: pikepdf.Pdf) -> List[Finding]:
    findings = []
    try:
        acroform = pdf.Root.get("/AcroForm", {})
        fields = acroform.get("/Fields", [])
        for field in fields:
            try:
                a = field.get("/A", {})
                s = a.get("/S")
                if s in (pikepdf.Name("/SubmitForm"), pikepdf.Name("/ResetForm")):
                    findings.append(Finding(
                        category=FindingCategory.ACTIVE_CONTENT,
                        subtype="form_submit_action",
                        page=1,
                        bbox=None,
                        evidence=f"Form action '{s}' detected",
                        detector="static:form_action",
                        confidence=0.92,
                        severity=Severity.HIGH,
                        visibility=VisibilityType.NORMAL,
                        recommended_action=FindingDecision.REDACT,
                    ))
            except Exception:
                pass
    except Exception:
        pass
    return findings


def _check_urls(pdf: pikepdf.Pdf) -> List[Finding]:
    findings = []
    for i, page in enumerate(pdf.pages, start=1):
        try:
            annots = page.get("/Annots", [])
            for annot in annots:
                try:
                    a = annot.get("/A", {})
                    uri = a.get("/URI")
                    if uri:
                        url_str = str(uri)
                        severity = Severity.LOW
                        subtype = "external_link"
                        for domain in SUSPICIOUS_DOMAINS:
                            if domain in url_str:
                                severity = Severity.HIGH
                                subtype = "suspicious_shortlink"
                                break
                        findings.append(Finding(
                            category=FindingCategory.SUSPICIOUS_LINK,
                            subtype=subtype,
                            page=i,
                            bbox=None,
                            evidence=f"External URL: {url_str[:200]}",
                            detector="static:external_url",
                            confidence=0.85,
                            severity=severity,
                            visibility=VisibilityType.NORMAL,
                            recommended_action=FindingDecision.KEEP if severity == Severity.LOW else FindingDecision.ESCALATE,
                        ))
                except Exception:
                    pass
        except Exception:
            pass
    return findings


def _check_metadata(pdf: pikepdf.Pdf) -> List[Finding]:
    findings = []
    suspicious_keys = ["/Keywords", "/Subject", "/Author", "/Creator", "/Producer"]
    injection_hints = ["ignore", "system", "assistant", "prompt", "instruction"]
    try:
        meta = pdf.docinfo
        for key in suspicious_keys:
            try:
                val = str(meta.get(key, ""))
                if any(hint in val.lower() for hint in injection_hints):
                    findings.append(Finding(
                        category=FindingCategory.METADATA,
                        subtype="suspicious_metadata",
                        page=1,
                        bbox=None,
                        evidence=f"Metadata {key}: {val[:200]}",
                        detector="static:metadata_injection",
                        confidence=0.80,
                        severity=Severity.HIGH,
                        visibility=VisibilityType.NORMAL,
                        recommended_action=FindingDecision.REDACT,
                    ))
            except Exception:
                pass
    except Exception:
        pass
    return findings
