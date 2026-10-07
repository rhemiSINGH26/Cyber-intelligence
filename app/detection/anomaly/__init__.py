"""ML and Statistical Anomaly Detection package."""
from app.detection.anomaly.isolation_forest import IsolationForestDetector
from app.detection.anomaly.statistical import StatisticalDetector

__all__ = ["IsolationForestDetector", "StatisticalDetector"]
