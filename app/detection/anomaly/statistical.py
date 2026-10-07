"""
Statistical Anomaly Detector: Z-Score, EWMA, and Cumulative Anomaly Tracking.
Evaluates daily entity metrics post-baseline and tracks cumulative deviations.
"""
from datetime import datetime
from collections import defaultdict
import numpy as np
from app.config import settings
from app.models.detection import Detection


class StatisticalDetector:
    """Detects daily statistical deviations and maintains cumulative scores across days."""

    def __init__(self):
        self.cumulative_scores: dict[str, float] = defaultdict(float)
        self.accumulated_evidence: dict[str, list[str]] = defaultdict(list)
        self.ewma_values: dict[str, float] = defaultdict(float)

    def update_and_detect(self, events: list[dict], baseline) -> list[Detection]:
        """
        Group events by (user, date) and check for post-baseline deviations.
        """
        detections = []
        # user -> day -> stats
        daily_stats = defaultdict(lambda: defaultdict(lambda: {"events": 0, "failures": 0, "bytes": 0, "evidence": []}))

        for e in events:
            user = e.get("user")
            ts_str = e.get("timestamp")
            if not user or not ts_str:
                continue

            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                continue

            # Skip events within the baseline training window
            if baseline.is_in_training_window(dt):
                continue

            day_str = dt.strftime("%Y-%m-%d")
            daily_stats[user][day_str]["events"] += 1
            if e.get("event_type") == "login_failure":
                daily_stats[user][day_str]["failures"] += 1
            b = e.get("bytes_transferred", 0) or e.get("bytes", 0)
            daily_stats[user][day_str]["bytes"] += b
            if e.get("id"):
                daily_stats[user][day_str]["evidence"].append(e["id"])

        for user, days in daily_stats.items():
            profile = baseline.get_profile("user", user)
            if profile.total_events < settings.MIN_OBSERVATIONS_FOR_BASELINE:
                continue

            for day_str, day_data in sorted(days.items()):
                # Calculate daily Z-scores
                day_anomaly = 0.0

                # 1. Login failures deviation
                if day_data["failures"] >= 2:
                    day_anomaly += day_data["failures"] * 2.0

                # 2. Daily events count deviation
                if profile.daily_event_count_std > 0 and day_data["events"] > 0:
                    z_ev = (day_data["events"] - profile.daily_event_count_mean) / profile.daily_event_count_std
                    if z_ev > 2.5:
                        day_anomaly += (z_ev - 2.5) * 1.5

                # 3. Daily bytes deviation
                if profile.daily_bytes_std > 0 and day_data["bytes"] > 0:
                    z_b = (day_data["bytes"] - profile.daily_bytes_mean) / profile.daily_bytes_std
                    if z_b > 2.5:
                        day_anomaly += (z_b - 2.5) * 1.5

                if day_anomaly > 0:
                    self.cumulative_scores[user] = (self.cumulative_scores[user] * 0.9) + day_anomaly
                    self.accumulated_evidence[user].extend(day_data["evidence"])
                else:
                    self.cumulative_scores[user] *= 0.85

                # Check if cumulative threshold breached
                if self.cumulative_scores[user] >= settings.CUMULATIVE_THRESHOLD:
                    evidence_sample = self.accumulated_evidence[user][-20:]
                    if not evidence_sample:
                        continue

                    try:
                        ts = datetime.fromisoformat(f"{day_str}T12:00:00")
                    except Exception:
                        ts = datetime.utcnow()

                    det = Detection(
                        timestamp=ts,
                        stage="collection",
                        mitre_tactic="TA0009",
                        mitre_technique="T1005",
                        technique_name="Low and Slow Cumulative Anomaly",
                        evidence=evidence_sample,
                        reason=(
                            f"Cumulative statistical score ({self.cumulative_scores[user]:.2f}) exceeded threshold "
                            f"for user '{user}' across sustained activity window"
                        ),
                        entities={"users": [user]},
                        anomaly_score=float(self.cumulative_scores[user]),
                        confidence=0.82,
                        rule_name="cumulative_statistical_tracker"
                    )
                    detections.append(det)
                    self.cumulative_scores[user] = settings.CUMULATIVE_THRESHOLD * 0.2
                    self.accumulated_evidence[user] = []

        return detections
