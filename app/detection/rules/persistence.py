"""
Persistence detector: scheduled tasks, new accounts, service installations.
MITRE: T1053 Scheduled Task, T1136 Create Account
"""
from collections import defaultdict
from app.detection.rules.base import BaseDetector
from app.models.detection import Detection
from app.config import settings, MITRE_TECHNIQUES


class PersistenceDetector(BaseDetector):
    """Detect persistence mechanisms like task scheduling and account creation."""

    def detect(self, events: list[dict], all_events: list[dict] = None) -> list[Detection]:
        detections = []
        for e in events:
            evt_type = e.get("event_type", "")
            app = (e.get("app") or "").lower()
            status = (e.get("status") or "").lower()
            details = (e.get("details") or "").lower()

            is_schtask = "schtasks" in app or "crontab" in app or "scheduled_task" in evt_type
            is_new_account = "create_account" in evt_type or "useradd" in app or "net user /add" in details

            if is_schtask or is_new_account:
                ts = self._parse_ts(e.get("timestamp", ""))
                if not ts:
                    continue

                if is_schtask:
                    tech = MITRE_TECHNIQUES.get("scheduled_task", {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "persistence"})
                    reason = f"Scheduled task persistence detected via '{app}' on host '{e.get('host', 'unknown')}'"
                    rule_name = "scheduled_task_creation"
                else:
                    tech = MITRE_TECHNIQUES.get("create_account", {"id": "T1136", "name": "Create Account", "tactic": "persistence"})
                    reason = f"Persistence account creation detected on host '{e.get('host', 'unknown')}'"
                    rule_name = "local_account_creation"

                det = Detection(
                    timestamp=ts,
                    stage="persistence",
                    mitre_tactic=tech["tactic"],
                    mitre_technique=tech["id"],
                    technique_name=tech["name"],
                    evidence=[e["id"]],
                    reason=reason,
                    entities=self._get_entities([e]),
                    anomaly_score=1.5,
                    confidence=0.70,
                    rule_name=rule_name
                )
                detections.append(det)

        return detections
