"""
Privilege Escalation detector.
MITRE: T1548 Abuse Elevation Control, T1134 Access Token Manipulation
"""
from app.detection.rules.base import BaseDetector
from app.models.detection import Detection
from app.config import settings, MITRE_TECHNIQUES


class PrivilegeEscalationDetector(BaseDetector):
    """Detect suspicious privilege escalation events."""

    def detect(self, events: list[dict], all_events: list[dict] = None) -> list[Detection]:
        detections = []

        for e in events:
            if e.get("event_type") != "privilege_change":
                continue

            user = e.get("user", "")
            if not user:
                continue

            ts = self._parse_ts(e["timestamp"])
            if ts is None:
                continue

            profile = self.baseline.get_profile("user", user)
            anomaly_signals = []
            score = 0.0

            # Check 1: Non-admin user elevating
            known_admins = [u for u in (settings.ADMIN_USERS or []) if u]
            # Use baseline to determine if this user typically does priv changes
            priv_events_in_baseline = sum(1 for f in (all_events or [])
                                          if f.get("user") == user
                                          and f.get("event_type") == "privilege_change"
                                          and self.baseline.is_in_training_window(
                                              self._parse_ts(f.get("timestamp", "")) or ts))

            if priv_events_in_baseline == 0 and profile.total_events >= settings.MIN_OBSERVATIONS_FOR_BASELINE:
                anomaly_signals.append(f"user '{user}' has no prior privilege change history")
                score += 1.5

            # Check 2: Unusual hour
            if ts.hour < 6 or ts.hour > 22:
                anomaly_signals.append(f"privilege change at unusual hour {ts.hour}:00")
                score += 1.0

            # Check 3: Source IP is external
            src_ip = e.get("src_ip", "")
            if src_ip and not (src_ip.startswith("10.") or src_ip.startswith("172.") or src_ip.startswith("192.168.")):
                anomaly_signals.append(f"privilege change from external IP {src_ip}")
                score += 1.5

            # Check 4: From unusual host
            host = e.get("host", "")
            if host and self.baseline.is_host_anomalous(user, host):
                anomaly_signals.append(f"privilege change on unusual host '{host}'")
                score += 0.8

            if score >= 2.0:
                tech = MITRE_TECHNIQUES["abuse_elevation"]
                det = Detection(
                    timestamp=ts,
                    stage="privilege_escalation",
                    mitre_tactic="privilege_escalation",
                    mitre_technique=tech["id"],
                    technique_name=tech["name"],
                    evidence=[e["id"]],
                    reason=f"Suspicious privilege escalation for '{user}': " + "; ".join(anomaly_signals),
                    entities=self._get_entities([e]),
                    anomaly_score=score,
                    confidence=min(0.4 + score * 0.15, 0.9),
                    rule_name="suspicious_priv_esc",
                )
                detections.append(det)

        return detections
