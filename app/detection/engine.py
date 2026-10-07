"""
Central Detection Engine.
Coordinates the entire threat intelligence pipeline:
Baseline -> Rule Detectors -> ML Anomaly Detectors -> Graph Construction ->
Attack Chain Correlation -> Risk Scoring -> Playbook Recommendation -> Incidents.
"""
from datetime import datetime
from typing import Optional
from app.config import settings
from app.db.store import store
from app.detection.baseline import BaselineBuilder
from app.detection.rules import (
    InitialAccessDetector,
    CredentialAccessDetector,
    ExecutionDetector,
    PersistenceDetector,
    PrivilegeEscalationDetector,
    DefenseEvasionDetector,
    LateralMovementDetector,
    CollectionDetector,
    ExfiltrationDetector,
)
from app.detection.anomaly import IsolationForestDetector, StatisticalDetector
from app.correlation import EntityGraph, AttackCorrelator
from app.scoring import RiskScorer
from app.models.detection import Incident, Observation, Detection


class DetectionEngine:
    """End-to-end Cyber Threat Intelligence Detection Pipeline."""

    def __init__(self):
        self.baseline = BaselineBuilder()
        self.graph = EntityGraph()
        self.correlator = AttackCorrelator(self.graph)
        self.scorer = RiskScorer()
        self.if_detector = IsolationForestDetector()
        self.stat_detector = StatisticalDetector()

        # Initialize all stage detectors
        self.detectors = [
            InitialAccessDetector(self.baseline),
            CredentialAccessDetector(self.baseline),
            ExecutionDetector(self.baseline),
            PersistenceDetector(self.baseline),
            PrivilegeEscalationDetector(self.baseline),
            DefenseEvasionDetector(self.baseline),
            LateralMovementDetector(self.baseline),
            CollectionDetector(self.baseline),
            ExfiltrationDetector(self.baseline),
        ]

    def build_baseline(self, events: list[dict], training_days: int = None):
        """Train baseline profiles from the first N days of events."""
        if not events:
            return

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))
        first_ts_str = sorted_events[0].get("timestamp", "")
        try:
            start_dt = datetime.fromisoformat(first_ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            start_dt = datetime.utcnow()

        self.baseline.set_training_window(start_dt, training_days)

        for e in sorted_events:
            self.baseline.add_event(e)

        profiles = self.baseline.build_profiles()
        for k, p in profiles.items():
            store.set_baseline(p.entity_type.value, p.entity_id, p)

        # Train Isolation Forest on training window
        self.if_detector.train(sorted_events)

    def process_events(self, events: list[dict], auto_baseline: bool = True) -> list[Incident]:
        """
        Process a batch or complete set of events through the entire detection pipeline.
        """
        if not events:
            return []

        # 1. Register events & entities in DataStore and EntityGraph
        for e in events:
            store.add_log(e)
            ts = None
            if e.get("timestamp"):
                try:
                    ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    pass
            if e.get("user"):
                store.register_entity("user", e["user"], ts)
            if e.get("host"):
                store.register_entity("host", e["host"], ts)
            if e.get("src_ip"):
                store.register_entity("ip", e["src_ip"], ts)

            self.graph.add_event(e)

        # 2. Build baseline if requested and not built yet
        if auto_baseline and not self.baseline.profiles:
            self.build_baseline(events)

        # 3. Execute Rule-based Detectors across stages
        all_detections: list[Detection] = []
        for detector in self.detectors:
            dets = detector.detect(events, all_events=events)
            all_detections.extend(dets)

        # 4. Execute ML & Statistical Anomaly Detectors
        ml_dets = self.if_detector.detect(events)
        all_detections.extend(ml_dets)

        stat_dets = self.stat_detector.update_and_detect(events, self.baseline)
        all_detections.extend(stat_dets)

        # Save raw detections to store
        for d in all_detections:
            store.add_detection(d)

        # 5. Correlate Detections into Multi-Stage Attack Chains
        incidents, observations = self.correlator.correlate(all_detections)

        # 6. Score and Generate Response Actions & Narratives
        final_incidents = []
        for inc in incidents:
            scored_inc = self.scorer.evaluate(inc)
            store.add_incident(scored_inc)
            final_incidents.append(scored_inc)

            # Mark graph nodes as suspicious for this incident
            for user in scored_inc.entities.get("users", []):
                self.graph.add_event({"user": user}, is_suspicious=True, incident_id=scored_inc.id)
            for host in scored_inc.entities.get("hosts", []):
                self.graph.add_event({"host": host}, is_suspicious=True, incident_id=scored_inc.id)

        # Store observations
        for obs in observations:
            store.add_observation(obs)

        return final_incidents


# Global detection engine singleton
engine = DetectionEngine()
