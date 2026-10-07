"""
Lateral Movement detector.
MITRE: T1021 Remote Services, T1570 Lateral Tool Transfer
"""
from collections import defaultdict
from datetime import timedelta
from app.detection.rules.base import BaseDetector
from app.models.detection import Detection
from app.config import settings, MITRE_TECHNIQUES


class LateralMovementDetector(BaseDetector):
    """Detect lateral movement across hosts."""

    def detect(self, events: list[dict], all_events: list[dict] = None) -> list[Detection]:
        detections = []

        # Group remote sessions and relevant network connections by user
        user_sessions: dict[str, list[dict]] = defaultdict(list)
        for e in events:
            if e.get("event_type") in ("remote_session", "network_conn"):
                app = e.get("app", "").lower()
                if e.get("event_type") == "remote_session" or app in settings.LATERAL_MOVEMENT_PROTOCOLS:
                    user = e.get("user", "")
                    if user:
                        user_sessions[user].append(e)

        for user, sessions in user_sessions.items():
            if not sessions:
                continue

            profile = self.baseline.get_profile("user", user)
            if profile.total_events < settings.MIN_OBSERVATIONS_FOR_BASELINE:
                continue

            # Sort by timestamp
            sessions.sort(key=lambda x: x.get("timestamp", ""))

            # Sliding window: count unique new hosts accessed
            window_seconds = settings.LATERAL_MOVEMENT_WINDOW_SECONDS
            threshold = settings.LATERAL_MOVEMENT_NEW_HOST_THRESHOLD

            for i in range(len(sessions)):
                ts_i = self._parse_ts(sessions[i]["timestamp"])
                if ts_i is None:
                    continue

                window_events = [sessions[i]]
                hosts_in_window = set()
                host_i = sessions[i].get("host", "")
                if host_i:
                    hosts_in_window.add(host_i)

                for j in range(i + 1, len(sessions)):
                    ts_j = self._parse_ts(sessions[j]["timestamp"])
                    if ts_j and (ts_j - ts_i).total_seconds() <= window_seconds:
                        window_events.append(sessions[j])
                        h = sessions[j].get("host", "")
                        if h:
                            hosts_in_window.add(h)
                    else:
                        break

                # Count how many hosts are NEW (not in baseline)
                new_hosts = [h for h in hosts_in_window if h not in profile.known_hosts]

                if len(new_hosts) >= threshold:
                    evidence_ids = [e["id"] for e in window_events]
                    tech = MITRE_TECHNIQUES["remote_services"]
                    det = Detection(
                        timestamp=ts_i,
                        stage="lateral_movement",
                        mitre_tactic="lateral_movement",
                        mitre_technique=tech["id"],
                        technique_name=tech["name"],
                        evidence=evidence_ids,
                        reason=(
                            f"Lateral movement: user '{user}' accessed {len(new_hosts)} new hosts "
                            f"({', '.join(new_hosts)}) within {window_seconds}s via "
                            f"{', '.join(set(e.get('app', '') for e in window_events))}"
                        ),
                        entities=self._get_entities(window_events),
                        anomaly_score=len(new_hosts) * 1.5,
                        confidence=min(0.5 + len(new_hosts) * 0.1, 0.9),
                        rule_name="lateral_movement_new_hosts",
                    )
                    detections.append(det)
                    break  # Avoid duplicate detections for same user

        return detections
