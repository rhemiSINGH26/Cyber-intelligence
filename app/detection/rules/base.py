"""
Base class for all rule-based stage detectors.
Each detector analyzes a window of events and produces Detection objects.
"""
from abc import ABC, abstractmethod
from app.models.detection import Detection
from app.detection.baseline import BaselineBuilder


class BaseDetector(ABC):
    """Abstract base for kill-chain stage detectors."""

    def __init__(self, baseline: BaselineBuilder):
        self.baseline = baseline

    @abstractmethod
    def detect(self, events: list[dict], all_events: list[dict] = None) -> list[Detection]:
        """
        Analyze events and return any detections.

        Args:
            events: Current window of events to analyze
            all_events: Full event history (for context)

        Returns:
            List of Detection objects (may be empty)
        """
        pass

    def _parse_ts(self, ts_str: str):
        """Parse timestamp string to datetime."""
        from datetime import datetime
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, AttributeError):
            return None

    def _get_entities(self, events: list[dict]) -> dict:
        """Extract entities from a list of events."""
        entities = {"users": set(), "hosts": set(), "ips": set(), "apps": set(), "files": set(), "devices": set()}
        for e in events:
            if e.get("user"):
                entities["users"].add(e["user"])
            if e.get("host"):
                entities["hosts"].add(e["host"])
            if e.get("src_ip"):
                entities["ips"].add(e["src_ip"])
            if e.get("dst_ip"):
                entities["ips"].add(e["dst_ip"])
            if e.get("app"):
                entities["apps"].add(e["app"])
            if e.get("file_path"):
                entities["files"].add(e["file_path"])
            if e.get("device_id"):
                entities["devices"].add(e["device_id"])
        return {k: list(v) for k, v in entities.items() if v}
