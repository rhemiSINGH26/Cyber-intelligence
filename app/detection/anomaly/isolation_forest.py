"""
Isolation Forest anomaly detection on entity behavioral features.
Extracts numerical feature vectors from event windows and detects multivariate anomalies.
"""
from datetime import datetime
from collections import defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest
from app.config import settings
from app.models.detection import Detection


class IsolationForestDetector:
    """Unsupervised multivariate anomaly detector using Isolation Forest."""

    def __init__(self):
        self.model = IsolationForest(
            contamination=settings.ISOLATION_FOREST_CONTAMINATION,
            n_estimators=settings.ISOLATION_FOREST_N_ESTIMATORS,
            random_state=settings.RANDOM_SEED
        )
        self.is_fitted = False
        self.feature_names = [
            "event_count",
            "failed_logins",
            "distinct_hosts",
            "distinct_files",
            "total_bytes",
            "off_hours_ratio",
        ]

    def _extract_features(self, entity_events: list[dict]) -> tuple[np.ndarray, list[str]]:
        """Extract feature vector and collect all evidence event IDs."""
        event_count = len(entity_events)
        failed_logins = sum(1 for e in entity_events if e.get("event_type") == "login_failure")
        distinct_hosts = len(set(e.get("host") for e in entity_events if e.get("host")))
        distinct_files = len(set(e.get("file_path") for e in entity_events if e.get("file_path")))
        total_bytes = sum(e.get("bytes_transferred", 0) or e.get("bytes", 0) for e in entity_events)

        off_hours = 0
        for e in entity_events:
            ts_str = e.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
                if dt.hour < settings.WORK_HOUR_START or dt.hour >= settings.WORK_HOUR_END:
                    off_hours += 1
            except Exception:
                pass
        off_hours_ratio = off_hours / max(event_count, 1)

        feature_vector = np.array([
            event_count,
            failed_logins,
            distinct_hosts,
            distinct_files,
            np.log1p(total_bytes),
            off_hours_ratio,
        ], dtype=float)

        evidence_ids = [e["id"] for e in entity_events if e.get("id")]
        return feature_vector, evidence_ids

    def train(self, events: list[dict]):
        """Fit Isolation Forest on training baseline events grouped by user."""
        users_events = defaultdict(list)
        for e in events:
            user = e.get("user")
            if user:
                users_events[user].append(e)

        vectors = []
        for user, evts in users_events.items():
            if len(evts) >= settings.MIN_OBSERVATIONS_FOR_BASELINE:
                vec, _ = self._extract_features(evts)
                vectors.append(vec)

        if len(vectors) >= 5:
            X = np.array(vectors)
            self.model.fit(X)
            self.is_fitted = True

    def detect(self, events: list[dict]) -> list[Detection]:
        """Score windows of events. Returns Detections for anomalous entities."""
        if not self.is_fitted:
            return []

        # Group by user
        users_events = defaultdict(list)
        for e in events:
            user = e.get("user")
            if user:
                users_events[user].append(e)

        detections = []
        for user, evts in users_events.items():
            if len(evts) < 3:
                continue

            vec, evidence_ids = self._extract_features(evts)
            score = self.model.decision_function([vec])[0]

            if score < settings.ANOMALY_SCORE_THRESHOLD:
                anomaly_val = float(abs(score))
                first_evt = evts[0]
                ts_str = first_evt.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    ts = datetime.utcnow()

                det = Detection(
                    timestamp=ts,
                    stage="execution",  # ML anomaly behavioral flag
                    mitre_tactic="TA0002",
                    mitre_technique="T1059",
                    technique_name="Multivariate Behavioral Anomaly",
                    evidence=evidence_ids[:10],  # Take first 10 evidence IDs
                    reason=f"Isolation Forest flagged entity '{user}' with anomaly score {anomaly_val:.2f}",
                    entities={"users": [user]},
                    anomaly_score=anomaly_val,
                    confidence=min(0.5 + anomaly_val * 0.2, 0.9),
                    rule_name="ml_isolation_forest",
                    feature_contributions=dict(zip(self.feature_names, vec.tolist()))
                )
                detections.append(det)

        return detections
