from __future__ import annotations
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid


class FindingCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    SENSITIVE_DATA = "sensitive_data"
    SUSPICIOUS_LINK = "suspicious_link"
    ACTIVE_CONTENT = "active_content"
    VISIBILITY_DISCREPANCY = "visibility_discrepancy"
    METADATA = "metadata"


class FindingDecision(str, Enum):
    REDACT = "Redact"
    KEEP = "Keep"
    ESCALATE = "Escalate"
    PENDING = "Pending"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class VisibilityType(str, Enum):
    NORMAL = "normal"
    TEXT_LAYER_ONLY = "text_layer_only"
    RENDERED_ONLY = "rendered_only"
    LOW_CONTRAST = "low_contrast"


class WorkflowStatus(str, Enum):
    UNINSPECTED = "Uninspected"
    NEEDS_REVIEW = "Needs review"
    BLOCKED = "Blocked"
    SANITIZATION_PENDING = "Sanitization pending"
    SANITIZED = "Sanitized and rechecked"
    REVIEW_INCOMPLETE = "Review incomplete"


class ProcessingStage(str, Enum):
    HASHING = "Hashing file"
    RENDERING = "Rendering pages"
    EXTRACTING = "Extracting machine-readable content"
    OCR_COMPARE = "Running OCR comparison"
    SENSITIVE_DATA = "Checking sensitive data"
    INJECTION = "Analyzing suspicious instructions"
    STATIC = "Running static PDF checks"
    BUILDING_QUEUE = "Building review queue"
    COMPLETE = "Complete"


class BoundingBox(BaseModel):
    x1: float
    y1: float
    x2: float
    y2: float

    def as_list(self) -> List[float]:
        return [self.x1, self.y1, self.x2, self.y2]


class DocumentElement(BaseModel):
    element_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    page: int
    text: str
    bbox: Optional[BoundingBox] = None
    confidence: Optional[float] = None
    source: str = "digital"  # "digital" | "ocr"
    reading_order: Optional[int] = None


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"f_{uuid.uuid4().hex[:6]}")
    category: FindingCategory
    subtype: str
    page: int
    bbox: Optional[List[float]] = None
    evidence: str
    detector: str
    confidence: float
    severity: Severity
    visibility: VisibilityType = VisibilityType.NORMAL
    recommended_action: FindingDecision
    review_decision: Optional[FindingDecision] = None
    review_reason: Optional[str] = None
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None


class RiskComponents(BaseModel):
    injection: float = 0.0      # I
    sensitive: float = 0.0      # S
    hidden: float = 0.0         # H
    active: float = 0.0         # A

    def score(self) -> int:
        raw = 0.40 * self.injection + 0.25 * self.sensitive + 0.20 * self.hidden + 0.15 * self.active
        # Clamp to [0,1] before multiplying
        raw = max(0.0, min(1.0, raw))
        return round(100 * raw)


class RiskScore(BaseModel):
    components: RiskComponents
    score: int
    label: str
    forced_minimum: bool = False

    @classmethod
    def from_components(cls, components: RiskComponents, has_confirmed_critical: bool = False) -> "RiskScore":
        score = components.score()
        if has_confirmed_critical and score < 80:
            score = 80
            forced_minimum = True
        else:
            forced_minimum = False

        if score >= 80:
            label = "Critical"
        elif score >= 60:
            label = "High"
        elif score >= 30:
            label = "Medium"
        else:
            label = "Low"

        return cls(components=components, score=score, label=label, forced_minimum=forced_minimum)


class RedactionResult(BaseModel):
    finding_id: str
    success: bool
    verified_absent: bool = False
    error: Optional[str] = None


class AuditRecord(BaseModel):
    session_id: str
    reviewer_name: str
    original_filename: str
    original_sha256: str
    sanitized_sha256: Optional[str] = None
    processing_started_at: str
    processing_completed_at: Optional[str] = None
    provider_mode: str
    extraction_version: str
    detectors: List[Dict[str, str]]
    findings: List[Dict[str, Any]]
    redaction_results: List[Dict[str, Any]] = []
    verification_passed: bool = False
    verification_details: Dict[str, Any] = {}
    unresolved_critical_count: int = 0
    workflow_status: WorkflowStatus = WorkflowStatus.UNINSPECTED
    page_count: int = 0
    sanitized_page_count: Optional[int] = None
