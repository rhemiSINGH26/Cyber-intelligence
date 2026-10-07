"""Metrics and evaluation models."""
from pydantic import BaseModel, Field
from typing import Optional


class EvaluationMetrics(BaseModel):
    """Evaluation results comparing detected vs ground truth."""
    total_ground_truth: int = 0
    total_detected: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    fp_rate: float = 0.0
    clean_run_alerts: int = 0  # Alerts on benign_only dataset
    per_attack_detection: dict = Field(default_factory=dict)
    timeline_accuracy: float = 0.0
    stage_accuracy: float = 0.0
    mean_time_to_detect_seconds: float = 0.0


class DashboardMetrics(BaseModel):
    """Aggregated metrics for the dashboard endpoint."""
    total_logs: int = 0
    total_incidents: int = 0
    total_observations: int = 0
    severity_distribution: dict = Field(default_factory=dict)
    status_distribution: dict = Field(default_factory=dict)
    top_entities: list[dict] = Field(default_factory=list)
    recent_alerts: list[dict] = Field(default_factory=list)
    alerts_over_time: list[dict] = Field(default_factory=list)
    risk_distribution: dict = Field(default_factory=dict)
    mitre_coverage: list[dict] = Field(default_factory=list)
    detection_rate: float = 0.0


class StreamStatus(BaseModel):
    """Status of the log replay stream."""
    running: bool = False
    speed: float = 60.0
    logs_processed: int = 0
    total_logs: int = 0
    progress_pct: float = 0.0
    current_time: Optional[str] = None
    incidents_found: int = 0
    elapsed_seconds: float = 0.0
