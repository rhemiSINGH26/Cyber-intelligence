"""
Initial Access detector: anomalous logins (geo, time, new host).
MITRE: T1078 Valid Accounts, T1133 External Remote Services
"""
from collections import defaultdict
from app.detection.rules.base import BaseDetector
from app.models.detection import Detection
from app.config import settings, MITRE_TECHNIQUES


class InitialAccessDetector(BaseDetector):
    """Detect suspicious initial access events."""

    def detect(self, events: list[dict], all_events: list[dict] = None) -> list[Detection]:
        detections = []

        for e in events:
            if e.get("event_type") != "login_success":
                continue

            user = e.get("user", "")
            if not user:
                continue

            ts = self._parse_ts(e["timestamp"])
            if ts is None:
                continue

            profile = self.baseline.get_profile("user", user)

            # Skip if we don't have enough baseline data
            if profile.total_events < settings.MIN_OBSERVATIONS_FOR_BASELINE:
                continue

            anomaly_signals = []
            score = 0.0

            # Check 1: Anomalous geography
            geo = e.get("geo_country", "")
            if geo and self.baseline.is_geo_anomalous(user, geo):
                anomaly_signals.append(f"login from unusual country '{geo}' (known: {', '.join(profile.known_geos)})")
                score += 1.5

            # Check 2: Anomalous hour
            if self.baseline.is_hour_anomalous(user, ts.hour):
                anomaly_signals.append(f"login at unusual hour {ts.hour}:00 (low activity in baseline)")
                score += 1.0

            # Check 3: New host for this user
            host = e.get("host", "")
            if host and self.baseline.is_host_anomalous(user, host):
                anomaly_signals.append(f"login from new host '{host}' (known: {', '.join(list(profile.known_hosts)[:5])})")
                score += 0.8

            # Check 4: Source IP not in known set
            src_ip = e.get("src_ip", "")
            if src_ip and profile.known_ips and src_ip not in profile.known_ips:
                # Only flag if IP is external (not internal 10.x, 172.x, 192.168.x)
                if not (src_ip.startswith("10.") or src_ip.startswith("172.") or src_ip.startswith("192.168.")):
                    anomaly_signals.append(f"login from unknown external IP {src_ip}")
                    score += 1.0

            # Only fire if multiple signals or high score
            if score >= 2.0 and len(anomaly_signals) >= 2:
                tech = MITRE_TECHNIQUES["valid_accounts"]
                det = Detection(
                    timestamp=ts,
                    stage="initial_access",
                    mitre_tactic="initial_access",
                    mitre_technique=tech["id"],
                    technique_name=tech["name"],
                    evidence=[e["id"]],
                    reason=f"Suspicious login for '{user}': " + "; ".join(anomaly_signals),
                    entities=self._get_entities([e]),
                    anomaly_score=score,
                    confidence=min(0.4 + score * 0.15, 0.9),
                    rule_name="anomalous_login",
                )
                detections.append(det)

        # Check for service accounts on unusual hosts
        detections.extend(self._detect_service_account_anomaly(events))

        return detections

    def _detect_service_account_anomaly(self, events: list[dict]) -> list[Detection]:
        """Detect service accounts logging in from unusual hosts."""
        detections = []
        svc_accounts = set(settings.BACKUP_SERVICE_ACCOUNTS + ["svc_monitor", "svc_deploy"])

        for e in events:
            if e.get("event_type") != "login_success":
                continue
            user = e.get("user", "")
            if user not in svc_accounts:
                continue

            host = e.get("host", "")
            profile = self.baseline.get_profile("user", user)

            if profile.total_events < settings.MIN_OBSERVATIONS_FOR_BASELINE:
                continue

            # Service account on an unusual host
            if host and profile.known_hosts and host not in profile.known_hosts:
                ts = self._parse_ts(e["timestamp"])
                if ts is None:
                    continue

                tech = MITRE_TECHNIQUES["valid_accounts"]
                det = Detection(
                    timestamp=ts,
                    stage="initial_access",
                    mitre_tactic="initial_access",
                    mitre_technique=tech["id"],
                    technique_name=tech["name"],
                    evidence=[e["id"]],
                    reason=(
                        f"Service account '{user}' logged in from unusual host '{host}' "
                        f"(normally on: {', '.join(list(profile.known_hosts)[:5])})"
                    ),
                    entities=self._get_entities([e]),
                    anomaly_score=2.5,
                    confidence=0.7,
                    rule_name="service_account_anomaly",
                )
                detections.append(det)

        return detections
