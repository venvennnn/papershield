"""
Deterministic prompt-injection detector.

Runs entirely without an LLM. Patterns cover instruction overrides,
assistant-directed commands, secret exfiltration requests, tool invocations,
trust claims, and encoded markers.
"""
from __future__ import annotations

import base64
import re
from typing import List, Tuple, Optional

from papershield.models.document import (
    DocumentElement, Finding, FindingCategory, FindingDecision,
    Severity, VisibilityType,
)

DETECTOR_VERSION = "rule:injection_v2"

# ---------------------------------------------------------------------------
# Rule definitions: (rule_id, pattern, subtype, severity, description)
# ---------------------------------------------------------------------------

_RULES: List[Tuple[str, re.Pattern, str, Severity, str]] = []


def _add(rule_id: str, pattern: str, subtype: str, severity: Severity, desc: str) -> None:
    _RULES.append((rule_id, re.compile(pattern, re.IGNORECASE | re.DOTALL), subtype, severity, desc))


# Instruction overrides
_add("override_v1", r"ignore\s+(all\s+)?(previous|prior|earlier|above|preceding)\s+(instructions?|prompts?|context|directives?|rules?)", "instruction_override", Severity.CRITICAL, "Ignore-prior-instructions pattern")
_add("override_v2", r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", "instruction_override", Severity.CRITICAL, "Disregard-prior pattern")
_add("override_v3", r"forget\s+(everything|all|what)\s+(you.ve|you\s+have|i.ve|previously)", "instruction_override", Severity.CRITICAL, "Forget-everything pattern")
_add("override_v4", r"(new|updated|revised|superseding)\s+instructions?\s*(follow|are|below|:)", "instruction_override", Severity.HIGH, "New-instructions claim")
_add("override_v5", r"you\s+are\s+now\s+(operating|running|in)\s+(as|under|with)", "instruction_override", Severity.HIGH, "Persona-override pattern")
_add("override_v6", r"your\s+(new\s+)?(role|mission|task|job|purpose)\s+is\s+to", "instruction_override", Severity.HIGH, "Role-redefinition pattern")
_add("override_v7", r"end\s+of\s+(system\s+)?prompt[.\s]", "instruction_override", Severity.CRITICAL, "End-of-prompt injection marker")
_add("override_v8", r"</?(system|instructions?|context|prompt)>", "instruction_override", Severity.CRITICAL, "Fake XML instruction tag")

# Directed commands
_add("cmd_v1", r"(as\s+an?\s+)?(ai|llm|model|assistant|chatbot|agent|gpt|claude|copilot|gemini)[,\s]+\s*(you\s+)?(must|should|shall|will|need\s+to|are\s+required\s+to)\s+(now\s+)?", "directed_command", Severity.HIGH, "Direct AI command")
_add("cmd_v2", r"(tell|ask|instruct|command|order)\s+(the\s+)?(ai|llm|model|assistant|agent)\s+to\s+", "directed_command", Severity.HIGH, "Indirect AI command")
_add("cmd_v3", r"when\s+(processing|reading|ingesting|analyzing)\s+this\s+(document|file|pdf|text)", "directed_command", Severity.HIGH, "Processing-hook command")
_add("cmd_v4", r"(execute|run|perform|carry\s+out)\s+(the\s+following\s+)?(command|instruction|action|task|step)", "directed_command", Severity.HIGH, "Execute-command pattern")

# Secrets and exfiltration
_add("secret_v1", r"(reveal|show|output|print|return|send|expose|disclose|leak)\s+(the\s+)?(system\s+prompt|hidden\s+(prompt|instruction)|api\s+key|secret|password|credential|token|private\s+(key|data|info))", "secret_exfiltration", Severity.CRITICAL, "Secret/credential exfiltration")
_add("secret_v2", r"(what\s+(is|are)|tell\s+me)\s+(your\s+)?(system\s+prompt|hidden\s+instruction|api\s+key|secret|initial\s+prompt)", "secret_exfiltration", Severity.CRITICAL, "Secret-inquiry pattern")
_add("secret_v3", r"(repeat|echo|print|output)\s+(back\s+)?(every|all|your|the)\s+(instruction|prompt|system\s+message|context)", "secret_exfiltration", Severity.HIGH, "Context-echo exfiltration")

# Tool / data exfiltration
_add("tool_v1", r"(call|invoke|use|trigger)\s+(the\s+)?(tool|function|api|endpoint|webhook|plugin)\s+", "tool_invocation", Severity.CRITICAL, "Tool-invocation command")
_add("tool_v2", r"(send|upload|post|submit|forward)\s+(the\s+)?(data|file|document|information|context)\s+(to|at)\s+https?://", "data_exfiltration", Severity.CRITICAL, "Data-exfiltration URL")
_add("tool_v3", r"(fetch|retrieve|download|get)\s+(from\s+)?(https?://|ftp://)", "tool_invocation", Severity.HIGH, "Remote-fetch command")
_add("tool_v4", r"make\s+a\s+(get|post|put|delete|patch)\s+request\s+to", "tool_invocation", Severity.CRITICAL, "HTTP-method invocation")

# Trust claims
_add("trust_v1", r"(this\s+(content|document|text|instruction)\s+is\s+(trusted|authorized|verified|approved|safe|legitimate|from\s+admin))", "trust_claim", Severity.HIGH, "Trust-claim assertion")
_add("trust_v2", r"(higher|elevated|override|admin|root)\s+(priority|permission|access|trust|level)", "trust_claim", Severity.HIGH, "Elevated-privilege claim")
_add("trust_v3", r"(admin|administrator|system|root)\s+(override|command|instruction|approval)", "trust_claim", Severity.CRITICAL, "Admin-override claim")

# Policy modification
_add("policy_v1", r"(disable|bypass|skip|ignore|turn\s+off|deactivate)\s+(the\s+)?(safety|filter|moderation|guardrail|restriction|policy|rule|limit)", "policy_modification", Severity.CRITICAL, "Safety-bypass attempt")
_add("policy_v2", r"(you\s+)?(are\s+)?(no\s+longer\s+)?(bound\s+by|restricted\s+by|limited\s+to|subject\s+to)\s+(any\s+)?(policy|rule|guideline|restriction|filter)", "policy_modification", Severity.CRITICAL, "Policy-removal claim")

# Internal disclosure
_add("disclose_v1", r"(include|append|prepend|add)\s+(internal|private|confidential|classified|proprietary)\s+(information|data|document|content|details?)", "internal_disclosure", Severity.HIGH, "Internal-data inclusion request")
_add("disclose_v2", r"(summarize|describe|list|output)\s+(all\s+)?(internal|private|confidential)\s+(documents?|files?|data|emails?)", "internal_disclosure", Severity.HIGH, "Internal-document disclosure")

# Steganographic/encoded hints (simple safe decoding only)
_add("encode_v1", r"base64\s*[:\-]\s*[A-Za-z0-9+/]{10,}={0,2}", "encoded_instruction", Severity.HIGH, "Base64-encoded content")
_add("encode_v2", r"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){4,}", "encoded_instruction", Severity.MEDIUM, "Hex-encoded bytes")
_add("encode_v3", r"ROT\d{1,2}|caesar\s+cipher|hex\s+encoded", "encoded_instruction", Severity.MEDIUM, "Encoding reference")


def detect_injections(elements: List[DocumentElement], hidden_elements: Optional[List[DocumentElement]] = None) -> List[Finding]:
    """
    Run all deterministic injection rules against extracted document elements.
    Hidden elements (text-layer-only) receive severity bumping.
    """
    findings: List[Finding] = []
    all_elements = [(e, VisibilityType.NORMAL) for e in elements]
    if hidden_elements:
        all_elements += [(e, VisibilityType.TEXT_LAYER_ONLY) for e in hidden_elements]

    seen_spans: set = set()

    for element, visibility in all_elements:
        text = element.text
        for rule_id, pattern, subtype, base_severity, desc in _RULES:
            for match in pattern.finditer(text):
                span = match.group(0).strip()
                dedup_key = (element.page, rule_id, span[:80])
                if dedup_key in seen_spans:
                    continue
                seen_spans.add(dedup_key)

                severity = base_severity
                # Bump severity for hidden text
                if visibility == VisibilityType.TEXT_LAYER_ONLY:
                    severity = _bump_severity(severity)

                confidence = _rule_confidence(rule_id, visibility)
                evidence = _extract_context(text, match.start(), match.end())

                findings.append(Finding(
                    category=FindingCategory.PROMPT_INJECTION,
                    subtype=subtype,
                    page=element.page,
                    bbox=element.bbox.as_list() if element.bbox else None,
                    evidence=evidence,
                    detector=f"{DETECTOR_VERSION}/{rule_id}",
                    confidence=confidence,
                    severity=severity,
                    visibility=visibility,
                    recommended_action=FindingDecision.REDACT,
                ))

        # Check for embedded base64 with decoded injection
        findings.extend(_check_base64_decoded(element, visibility))

    return findings


def _bump_severity(s: Severity) -> Severity:
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = order.index(s)
    return order[min(idx + 1, len(order) - 1)]


def _rule_confidence(rule_id: str, visibility: VisibilityType) -> float:
    base = {
        "override": 0.97, "cmd": 0.90, "secret": 0.95,
        "tool": 0.93, "trust": 0.85, "policy": 0.96,
        "disclose": 0.82, "encode": 0.75,
    }
    prefix = rule_id.split("_")[0]
    conf = base.get(prefix, 0.80)
    if visibility == VisibilityType.TEXT_LAYER_ONLY:
        conf = min(conf + 0.03, 1.0)
    return round(conf, 2)


def _extract_context(text: str, start: int, end: int, window: int = 60) -> str:
    """Return a context snippet centered on the match."""
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    snippet = text[ctx_start:ctx_end].replace("\n", " ").strip()
    if ctx_start > 0:
        snippet = "…" + snippet
    if ctx_end < len(text):
        snippet = snippet + "…"
    return snippet[:300]


def _check_base64_decoded(element: DocumentElement, visibility: VisibilityType) -> List[Finding]:
    """Safely decode base64 blobs and check decoded content for injections."""
    findings = []
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    for match in b64_pattern.finditer(element.text):
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob + "==").decode("utf-8", errors="replace")
        except Exception:
            continue
        sub_findings = detect_injections([
            DocumentElement(
                page=element.page,
                text=decoded,
                bbox=element.bbox,
                source=element.source,
            )
        ])
        for f in sub_findings:
            f.evidence = f"[base64-decoded] {f.evidence}"
            f.detector = f"rule:injection_v2/base64_decoded"
            f.visibility = VisibilityType.TEXT_LAYER_ONLY
            f.severity = _bump_severity(f.severity)
            findings.append(f)
    return findings
