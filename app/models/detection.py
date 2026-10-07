"""
Detection and Incident models.
HARD RULE: A Stage with no evidence cannot exist — enforced by Pydantic validator.
"""
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional
from datetime import datetime
from enum import Enum
import uuid


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Detection(BaseModel):
    """
    A single detection event from a stage detector.
    This is the raw output before correlation.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    stage: str  # Kill-chain stage (e.g., "initial_access")
    mitre_tactic: str  # MITRE tactic ID (e.g., "TA0001")
    mitre_technique: str  # MITRE technique ID (e.g., "T1110")
    technique_name: str = ""
    evidence: list[str]  # Log event IDs — MUST NOT be empty
    reason: str  # Human-readable reason
    entities: dict = Field(default_factory=dict)  # {type: [ids]}
    anomaly_score: float = 0.0
    confidence: float = 0.5
    rule_name: str = ""
    feature_contributions: dict = Field(default_factory=dict)
    suppressed: bool = False
    suppression_reason: Optional[str] = None

    @field_validator("evidence")
    @classmethod
    def evidence_must_not_be_empty(cls, v):
        """HARD RULE: Every detection must have at least one evidence log ID."""
        if not v or len(v) == 0:
            raise ValueError("Detection evidence must contain at least one log ID. "
                             "A detection without evidence is invalid.")
        return v


class Stage(BaseModel):
    """
    A stage in an attack incident's kill chain.
    HARD RULE: evidence list must have min_length=1, enforced by validator.
    """
    stage: str  # Kill-chain stage name
    mitre_tactic: str
    mitre_technique: str
    technique_name: str = ""
    time: datetime  # When this stage was detected
    evidence: list[str] = Field(..., min_length=1)
    reason: str
    entities: dict = Field(default_factory=dict)
    anomaly_score: float = 0.0

    @field_validator("evidence")
    @classmethod
    def evidence_not_empty(cls, v):
        """Enforced: stage with no evidence must never exist."""
        if not v or len(v) == 0:
            raise ValueError("Stage evidence must contain at least one log event ID. "
                             "A stage with no evidence is invalid and must not be created.")
        return v


class Recommendation(BaseModel):
    """A recommended response action for an incident."""
    action: str  # e.g., "isolate_host", "disable_user"
    target: str  # e.g., "WKS-042", "jsmith"
    target_type: str  # "host", "user", "ip"
    priority: str = "medium"  # low/medium/high/critical
    description: str = ""
    automated: bool = False  # Whether this can be auto-executed


class Incident(BaseModel):
    """
    A correlated attack incident composed of multiple kill-chain stages.
    This is the primary output of the detection pipeline.
    """
    id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    title: str
    risk_score: int = Field(ge=0, le=100)
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0)
    status: IncidentStatus = IncidentStatus.OPEN
    first_seen: datetime
    last_seen: datetime
    entities: dict = Field(default_factory=dict)  # {type: [ids]}
    stages: list[Stage] = Field(..., min_length=1)
    timeline: list[dict] = Field(default_factory=list)
    explanation: str = ""  # "Why flagged" narrative
    recommendations: list[Recommendation] = Field(default_factory=list)
    mitre_mapping: list[dict] = Field(default_factory=list)
    attack_scenario: Optional[str] = None  # For evaluation matching
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @model_validator(mode="after")
    def validate_stages_have_evidence(self):
        """Double-check: every stage must have evidence."""
        for stage in self.stages:
            if not stage.evidence:
                raise ValueError(f"Stage '{stage.stage}' has no evidence. This is a hard rule violation.")
        return self

    @model_validator(mode="after")
    def build_timeline(self):
        """Auto-build timeline from stages if not provided."""
        if not self.timeline:
            self.timeline = [
                {
                    "time": s.time.isoformat(),
                    "stage": s.stage,
                    "reason": s.reason,
                    "evidence_count": len(s.evidence),
                }
                for s in sorted(self.stages, key=lambda x: x.time)
            ]
        return self

    @model_validator(mode="after")
    def build_mitre_mapping(self):
        """Auto-build MITRE mapping from stages."""
        if not self.mitre_mapping:
            self.mitre_mapping = [
                {
                    "tactic": s.mitre_tactic,
                    "technique": s.mitre_technique,
                    "technique_name": s.technique_name,
                    "stage": s.stage,
                }
                for s in self.stages
            ]
        return self


class IncidentSummary(BaseModel):
    """Lightweight incident summary for list endpoints."""
    id: str
    title: str
    risk_score: int
    severity: SeverityLevel
    confidence: float
    status: IncidentStatus
    first_seen: datetime
    last_seen: datetime
    stage_count: int
    entity_count: int
    created_at: datetime


class Observation(BaseModel):
    """
    A low-level anomaly that did not meet the incident threshold.
    Kept for visibility but does not trigger alerts.
    """
    id: str = Field(default_factory=lambda: f"OBS-{uuid.uuid4().hex[:8].upper()}")
    timestamp: datetime
    stage: str
    reason: str
    evidence: list[str] = Field(default_factory=list)
    entities: dict = Field(default_factory=dict)
    anomaly_score: float = 0.0
    why_not_incident: str = ""  # Explanation of why it stayed an observation
