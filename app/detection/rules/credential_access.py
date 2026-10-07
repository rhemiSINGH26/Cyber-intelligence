"""
Credential Access detector: brute-force login failures and low-and-slow credential testing.
MITRE: T1110 Brute Force
"""
from collections import defaultdict
from datetime import timedelta
from app.detection.rules.base import BaseDetector
from app.models.detection import Detection
from app.config import settings, MITRE_TECHNIQUES


class CredentialAccessDetector(BaseDetector):
    """Detect brute-force credential attacks and low-and-slow spraying."""

    def detect(self, events: list[dict], all_events: list[dict] = None) -> list[Detection]:
        detections = []

        # 1. Fast brute-force: Group by (user, src_ip) in short sliding window
        failures_by_key: dict[tuple, list[dict]] = defaultdict(list)
        # 2. Slow spraying: Group all failures by user
        failures_by_user: dict[str, list[dict]] = defaultdict(list)

        for e in events:
            if e.get("event_type") == "login_failure":
                user = e.get("user", "")
                src_ip = e.get("src_ip", "")
                if user:
                    failures_by_key[(user, src_ip)].append(e)
                    failures_by_user[user].append(e)

        handled_evidence = set()

        for (user, src_ip), failure_events in failures_by_key.items():
            if not user:
                continue

            failure_events.sort(key=lambda x: x.get("timestamp", ""))
            window_seconds = settings.BRUTE_FORCE_WINDOW_SECONDS
            threshold = settings.BRUTE_FORCE_THRESHOLD

            i = 0
            while i < len(failure_events):
                window = [failure_events[i]]
                ts_start = self._parse_ts(failure_events[i]["timestamp"])
                if ts_start is None:
                    i += 1
                    continue

                j = i + 1
                while j < len(failure_events):
                    ts_j = self._parse_ts(failure_events[j]["timestamp"])
                    if ts_j and (ts_j - ts_start).total_seconds() <= window_seconds:
                        window.append(failure_events[j])
                        j += 1
                    else:
                        break

                if len(window) >= threshold:
                    # Forgotten password check (few failures from known IP)
                    is_known_ip = not self.baseline.is_geo_anomalous(user, failure_events[0].get("geo_country", "US"))
                    if len(window) <= threshold + 1 and is_known_ip:
                        i = j
                        continue

                    evidence_ids = [e["id"] for e in window]
                    for eid in evidence_ids:
                        handled_evidence.add(eid)

                    tech = MITRE_TECHNIQUES["brute_force"]
                    det = Detection(
                        timestamp=ts_start,
                        stage="credential_access",
                        mitre_tactic=tech["tactic"],
                        mitre_technique=tech["id"],
                        technique_name=tech["name"],
                        evidence=evidence_ids,
                        reason=(
                            f"Brute-force detected: {len(window)} login failures for user '{user}' "
                            f"from IP {src_ip} within {window_seconds}s"
                        ),
                        entities=self._get_entities(window),
                        anomaly_score=min(len(window) / threshold, 3.0),
                        confidence=min(0.5 + (len(window) - threshold) * 0.1, 0.95),
                        rule_name="brute_force_login",
                    )
                    detections.append(det)
                    i = j
                else:
                    i += 1

        # 3. Detect low-and-slow credential testing (spread across multiple days from rare IPs)
        for user, user_failures in failures_by_user.items():
            profile = self.baseline.get_profile("user", user)
            unhandled = [f for f in user_failures if f["id"] not in handled_evidence]
            if len(unhandled) < 4:
                continue

            # Check if source IPs are external and not known
            external_failures = []
            for f in unhandled:
                ip = f.get("src_ip", "")
                if ip and not ip.startswith(("10.", "172.16.", "192.168.", "127.")):
                    if ip not in profile.known_ips:
                        external_failures.append(f)

            if len(external_failures) >= 4:
                evidence_ids = [e["id"] for e in external_failures]
                tech = MITRE_TECHNIQUES["brute_force"]
                first_ts = self._parse_ts(external_failures[0]["timestamp"]) or external_failures[0]["timestamp"]
                det = Detection(
                    timestamp=first_ts,
                    stage="credential_access",
                    mitre_tactic=tech["tactic"],
                    mitre_technique=tech["id"],
                    technique_name="Low-and-Slow Credential Testing",
                    evidence=evidence_ids,
                    reason=(
                        f"Low-and-slow credential attack: {len(external_failures)} login failures for user '{user}' "
                        f"from unfamiliar external IPs across multiple days"
                    ),
                    entities=self._get_entities(external_failures),
                    anomaly_score=2.0,
                    confidence=0.80,
                    rule_name="low_and_slow_credential_spray",
                )
                detections.append(det)

        return detections
