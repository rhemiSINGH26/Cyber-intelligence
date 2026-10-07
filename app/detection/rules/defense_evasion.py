"""
Defense Evasion detector: log clearing, security service tampering, artifact deletion.
MITRE: TA0005 Defense Evasion
"""
from app.detection.rules.base import BaseDetector
from app.models.detection import Detection
from app.config import settings, MITRE_TACTICS


class DefenseEvasionDetector(BaseDetector):
    """Detect defense evasion behaviors."""

    def detect(self, events: list[dict], all_events: list[dict] = None) -> list[Detection]:
        detections = []
        for e in events:
            app = (e.get("app") or "").lower()
            evt_type = (e.get("event_type") or "").lower()
            details = (e.get("details") or "").lower()
            file_path = (e.get("file_path") or "").lower()

            is_evasion = False
            reason = ""

            if "wevtutil" in app and "cl" in details:
                is_evasion = True
                reason = "Windows Event Log clearing attempt detected"
            elif "fltmc" in app or "sc stop" in details or "set-mppreference -disablerealtime" in details:
                is_evasion = True
                reason = "Security tool or antivirus disabling attempt detected"
            elif evt_type == "log_clear" or "clear-eventlog" in details:
                is_evasion = True
                reason = "Security audit log clearing activity detected"

            if is_evasion:
                ts = self._parse_ts(e.get("timestamp", ""))
                if not ts:
                    continue

                tactic = MITRE_TACTICS.get("defense_evasion", {"id": "TA0005", "name": "Defense Evasion"})
                det = Detection(
                    timestamp=ts,
                    stage="defense_evasion",
                    mitre_tactic=tactic["id"],
                    mitre_technique="T1070",
                    technique_name="Indicator Removal on Host",
                    evidence=[e["id"]],
                    reason=reason,
                    entities=self._get_entities([e]),
                    anomaly_score=2.0,
                    confidence=0.85,
                    rule_name="defense_evasion_activity"
                )
                detections.append(det)

        return detections
