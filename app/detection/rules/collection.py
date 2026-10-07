"""
Collection detector: mass file access, data staging, and low-and-slow sensitive file harvesting.
MITRE: T1005 Data from Local System, T1074 Data Staged
"""
from collections import defaultdict
from datetime import timedelta
from app.detection.rules.base import BaseDetector
from app.models.detection import Detection
from app.config import settings, MITRE_TECHNIQUES


SENSITIVE_KEYWORDS = (
    "finance", "hr", "executive", "security", "proprietary", "personnel",
    "salary", "customer", "backup", "secret", "contract", "tax", "database"
)


class CollectionDetector(BaseDetector):
    """Detect suspicious data collection activities."""

    def detect(self, events: list[dict], all_events: list[dict] = None) -> list[Detection]:
        detections = []

        # Group file access events by user within time windows
        user_file_events: dict[str, list[dict]] = defaultdict(list)
        for e in events:
            if e.get("event_type") in ("file_access", "file_copy"):
                user = e.get("user", "")
                if user:
                    user_file_events[user].append(e)

        for user, file_events in user_file_events.items():
            if not file_events:
                continue

            profile = self.baseline.get_profile("user", user)

            # Skip service accounts and users without baseline
            if user in settings.BACKUP_SERVICE_ACCOUNTS:
                continue
            if profile.total_events < settings.MIN_OBSERVATIONS_FOR_BASELINE:
                continue

            # Sort by timestamp
            file_events.sort(key=lambda x: x.get("timestamp", ""))

            # Detect bursts of file access
            detections.extend(self._detect_file_burst(user, file_events, profile))

            # Detect access to novel sensitive files and staging
            detections.extend(self._detect_file_novelty(user, file_events, profile))

        return detections

    def _detect_file_burst(self, user: str, events: list[dict], profile) -> list[Detection]:
        """Detect bursts of file access in short windows."""
        detections = []
        window_seconds = settings.FILE_ACCESS_BURST_WINDOW_SECONDS
        threshold = settings.FILE_ACCESS_BURST_THRESHOLD

        i = 0
        while i < len(events):
            ts_i = self._parse_ts(events[i]["timestamp"])
            if ts_i is None:
                i += 1
                continue

            window = [events[i]]
            for j in range(i + 1, len(events)):
                ts_j = self._parse_ts(events[j]["timestamp"])
                if ts_j and (ts_j - ts_i).total_seconds() <= window_seconds:
                    window.append(events[j])
                else:
                    break

            if len(window) >= threshold:
                sensitive_count = sum(1 for e in window
                                      if any(k in (e.get("file_path", "") or "").lower() for k in SENSITIVE_KEYWORDS))

                novel_files = [e for e in window
                               if e.get("file_path") and e["file_path"] not in profile.known_files]
                novelty_ratio = len(novel_files) / len(window) if window else 0

                if novelty_ratio >= settings.FILE_NOVELTY_RATIO_THRESHOLD or sensitive_count >= 5:
                    evidence_ids = [e["id"] for e in window]
                    tech = MITRE_TECHNIQUES["data_from_local"]
                    det = Detection(
                        timestamp=ts_i,
                        stage="collection",
                        mitre_tactic="collection",
                        mitre_technique=tech["id"],
                        technique_name=tech["name"],
                        evidence=evidence_ids,
                        reason=(
                            f"Mass file access: user '{user}' accessed {len(window)} files "
                            f"in {window_seconds}s ({len(novel_files)} novel, {sensitive_count} sensitive)."
                        ),
                        entities=self._get_entities(window),
                        anomaly_score=len(window) / threshold * 2 + sensitive_count * 0.3,
                        confidence=min(0.5 + novelty_ratio * 0.3 + sensitive_count * 0.05, 0.95),
                        rule_name="mass_file_access",
                    )
                    detections.append(det)
                i += len(window)
            else:
                i += 1

        return detections

    def _detect_file_novelty(self, user: str, events: list[dict], profile) -> list[Detection]:
        """Detect access to novel sensitive files and data staging."""
        detections = []
        if not profile.known_files:
            return []

        # 1. Check for data staging
        staging_events = [e for e in events
                          if e.get("event_type") == "file_copy"
                          and e.get("file_path")
                          and ("temp" in e["file_path"].lower() or "staging" in e["file_path"].lower())]

        if len(staging_events) >= 10:
            evidence_ids = [e["id"] for e in staging_events]
            tech = MITRE_TECHNIQUES["data_staged"]
            det = Detection(
                timestamp=self._parse_ts(staging_events[0]["timestamp"]),
                stage="collection",
                mitre_tactic="collection",
                mitre_technique=tech["id"],
                technique_name=tech["name"],
                evidence=evidence_ids,
                reason=(
                    f"Data staging: user '{user}' copied {len(staging_events)} files "
                    f"to staging/temp directories"
                ),
                entities=self._get_entities(staging_events),
                anomaly_score=len(staging_events) * 0.5,
                confidence=0.7,
                rule_name="data_staging",
            )
            detections.append(det)

        # 2. Check for gradual low-and-slow sensitive file harvesting
        novel_sensitive = [e for e in events
                           if e.get("file_path")
                           and e["file_path"] not in profile.known_files
                           and any(k in (e.get("file_path", "") or "").lower() for k in SENSITIVE_KEYWORDS)]

        if len(novel_sensitive) >= 5:
            evidence_ids = [e["id"] for e in novel_sensitive]
            tech = MITRE_TECHNIQUES["data_from_local"]
            det = Detection(
                timestamp=self._parse_ts(novel_sensitive[0]["timestamp"]),
                stage="collection",
                mitre_tactic="collection",
                mitre_technique=tech["id"],
                technique_name="Sensitive Data Harvesting",
                evidence=evidence_ids,
                reason=(
                    f"Low-and-slow data harvesting: user '{user}' accessed {len(novel_sensitive)} "
                    f"never-before-seen sensitive corporate files"
                ),
                entities=self._get_entities(novel_sensitive),
                anomaly_score=2.2,
                confidence=0.82,
                rule_name="sensitive_file_harvesting",
            )
            detections.append(det)

        return detections
