"""
Deterministic sensitive-data detector.
Validates candidates with checksums where applicable.
"""
from __future__ import annotations

import re
from typing import List, Set

from papershield.models.document import (
    DocumentElement, Finding, FindingCategory, FindingDecision,
    Severity, VisibilityType,
)

DETECTOR_VERSION = "rule:sensitive_v1"

ENABLED_CATEGORIES: Set[str] = {
    "email", "phone", "credit_card", "ssn", "ip_address",
    "api_key", "url", "iban", "date_of_birth",
}


# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b")
_CREDIT_CARD = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b")
_CREDIT_CARD_SPACED = re.compile(r"\b(\d{4}[\s\-]?){3}\d{4}\b")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b")
_IP_ADDRESS = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_API_KEY = re.compile(
    r"("
    r"sk-[A-Za-z0-9\-_]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{36}"
    r"|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"
    r")"
)
_URL = re.compile(r"https?://[^\s\"'<>{}\[\]\\^`|]{4,}", re.IGNORECASE)
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b")
_DOB = re.compile(
    r"\b(?:(?:0?[1-9]|[12]\d|3[01])[\-/.](?:0?[1-9]|1[0-2])[\-/.](?:19|20)\d{2}"
    r"|(?:19|20)\d{2}[\-/.](?:0?[1-9]|1[0-2])[\-/.](?:0?[1-9]|[12]\d|3[01]))\b"
)


def detect_sensitive_data(
    elements: List[DocumentElement],
    enabled_categories: Set[str] = ENABLED_CATEGORIES,
) -> List[Finding]:
    findings: List[Finding] = []
    seen: set = set()

    for element in elements:
        text = element.text

        if "email" in enabled_categories:
            for m in _EMAIL.finditer(text):
                _add(findings, seen, element, m.group(0), "email", "email_address", Severity.MEDIUM, 0.95)

        if "phone" in enabled_categories:
            for m in _PHONE.finditer(text):
                val = m.group(0).strip()
                if len(re.sub(r"\D", "", val)) >= 10:
                    _add(findings, seen, element, val, "phone", "phone_number", Severity.MEDIUM, 0.85)

        if "credit_card" in enabled_categories:
            for m in _CREDIT_CARD.finditer(text):
                digits = re.sub(r"\D", "", m.group(0))
                if _luhn(digits):
                    _add(findings, seen, element, m.group(0), "credit_card", "credit_card_number", Severity.CRITICAL, 0.98)
            for m in _CREDIT_CARD_SPACED.finditer(text):
                digits = re.sub(r"\D", "", m.group(0))
                if len(digits) in (15, 16) and _luhn(digits):
                    _add(findings, seen, element, m.group(0), "credit_card", "credit_card_number", Severity.CRITICAL, 0.97)

        if "ssn" in enabled_categories:
            for m in _SSN.finditer(text):
                _add(findings, seen, element, m.group(0), "ssn", "social_security_number", Severity.CRITICAL, 0.92)

        if "ip_address" in enabled_categories:
            for m in _IP_ADDRESS.finditer(text):
                ip = m.group(0)
                if not ip.startswith(("127.", "192.168.", "10.", "172.")):
                    _add(findings, seen, element, ip, "ip_address", "public_ip_address", Severity.LOW, 0.80)

        if "api_key" in enabled_categories:
            for m in _API_KEY.finditer(text):
                _add(findings, seen, element, m.group(0)[:40] + "…", "api_key", "api_key_or_token", Severity.CRITICAL, 0.88)

        if "url" in enabled_categories:
            for m in _URL.finditer(text):
                url = m.group(0)
                if len(url) > 8:
                    severity = Severity.LOW
                    if any(d in url for d in ["internal", "intranet", "private", "admin", "localhost"]):
                        severity = Severity.HIGH
                    _add(findings, seen, element, url[:100], "url", "external_url", severity, 0.75)

        if "iban" in enabled_categories:
            for m in _IBAN.finditer(text):
                val = m.group(0)
                if len(val) >= 15:
                    _add(findings, seen, element, val, "iban", "iban_number", Severity.HIGH, 0.85)

        if "date_of_birth" in enabled_categories:
            for m in _DOB.finditer(text):
                _add(findings, seen, element, m.group(0), "date_of_birth", "date_of_birth", Severity.MEDIUM, 0.70)

    return findings


def _add(
    findings: List[Finding],
    seen: set,
    element: DocumentElement,
    evidence: str,
    category_key: str,
    subtype: str,
    severity: Severity,
    confidence: float,
) -> None:
    key = (element.page, category_key, evidence[:40])
    if key in seen:
        return
    seen.add(key)
    findings.append(Finding(
        category=FindingCategory.SENSITIVE_DATA,
        subtype=subtype,
        page=element.page,
        bbox=element.bbox.as_list() if element.bbox else None,
        evidence=_mask(evidence, category_key),
        detector=f"{DETECTOR_VERSION}/{category_key}",
        confidence=confidence,
        severity=severity,
        visibility=VisibilityType.NORMAL,
        recommended_action=FindingDecision.REDACT,
    ))


def _mask(value: str, category: str) -> str:
    """Return a masked version for evidence display — never log raw secrets."""
    if category == "credit_card":
        digits = re.sub(r"\D", "", value)
        return "•" * (len(digits) - 4) + digits[-4:]
    if category == "ssn":
        return "•••-••-" + re.sub(r"\D", "", value)[-4:]
    if category == "api_key":
        return value[:6] + "•" * 20 + "…"
    if category == "iban":
        return value[:4] + "•" * (len(value) - 8) + value[-4:]
    return value


def _luhn(digits: str) -> bool:
    """Validate credit card number with Luhn algorithm."""
    if not digits.isdigit() or len(digits) < 13:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0
