"""
Exfiltration detector: large transfers, USB exfil, DNS tunnelling, and low-and-slow exfiltration.
MITRE: T1041, T1048, T1052, T1071.004
"""
from collections import defaultdict
from datetime import timedelta
import math
from app.detection.rules.base import BaseDetector
from app.models.detection import Detection
from app.config import settings, MITRE_TECHNIQUES


class ExfiltrationDetector(BaseDetector):
    """Detect data exfiltration attempts."""

    def detect(self, events: list[dict], all_events: list[dict] = None) -> list[Detection]:
        detections = []
        detections.extend(self._detect_large_transfer(events))
        detections.extend(self._detect_usb_exfil(events, all_events or events))
        detections.extend(self._detect_dns_tunnelling(events))
        detections.extend(self._detect_low_slow_transfer(events))
        return detections

    def _detect_large_transfer(self, events: list[dict]) -> list[Detection]:
        """Detect anomalously large outbound data transfers."""
        detections = []
        user_transfers: dict[str, list[dict]] = defaultdict(list)
        for e in events:
            if e.get("event_type") in ("network_conn", "data_upload"):
                user = e.get("user", "")
                bytes_val = e.get("bytes", 0) or e.get("bytes_transferred", 0) or 0
                if user and bytes_val > 0:
                    user_transfers[user].append(e)

        for user, transfers in user_transfers.items():
            if user in settings.BACKUP_SERVICE_ACCOUNTS:
                continue

            profile = self.baseline.get_profile("user", user)
            if profile.total_events < settings.MIN_OBSERVATIONS_FOR_BASELINE:
                continue

            daily_bytes: dict[str, int] = defaultdict(int)
            daily_events: dict[str, list[dict]] = defaultdict(list)
            for t in transfers:
                ts = self._parse_ts(t["timestamp"])
                if ts:
                    day_key = ts.strftime("%Y-%m-%d")
                    bytes_val = t.get("bytes", 0) or t.get("bytes_transferred", 0) or 0
                    daily_bytes[day_key] += bytes_val
                    daily_events[day_key].append(t)

            for day, total_bytes in daily_bytes.items():
                is_anomalous, z_score = self.baseline.is_bytes_anomalous("user", user, total_bytes)
                if is_anomalous and total_bytes >= settings.EXFIL_MIN_BYTES:
                    day_evts = daily_events[day]
                    dst_ips = set(e.get("dst_ip", "") for e in day_evts if e.get("dst_ip"))
                    rare_ips = [ip for ip in dst_ips
                                if ip and not ip.startswith(("10.", "172.16.", "192.168.", "127."))
                                and ip not in profile.known_ips]

                    if rare_ips:
                        evidence_ids = [e["id"] for e in day_evts]
                        tech = MITRE_TECHNIQUES["exfil_over_web"]
                        det = Detection(
                            timestamp=self._parse_ts(day_evts[0]["timestamp"]),
                            stage="exfiltration",
                            mitre_tactic="exfiltration",
                            mitre_technique=tech["id"],
                            technique_name=tech["name"],
                            evidence=evidence_ids,
                            reason=(
                                f"Large data transfer: user '{user}' sent {total_bytes / 1e6:.1f} MB "
                                f"on {day} (z-score: {z_score:.1f}). Rare destination IPs: {', '.join(rare_ips)}"
                            ),
                            entities=self._get_entities(day_evts),
                            anomaly_score=z_score,
                            confidence=min(0.5 + z_score * 0.1, 0.9),
                            rule_name="large_outbound_transfer",
                        )
                        detections.append(det)

        return detections

    def _detect_low_slow_transfer(self, events: list[dict]) -> list[Detection]:
        """Detect repetitive transfers to rare external IPs over multiple days."""
        detections = []
        user_transfers = defaultdict(list)
        for e in events:
            if e.get("event_type") == "network_conn":
                user = e.get("user")
                if user:
                    user_transfers[user].append(e)

        for user, transfers in user_transfers.items():
            if user in settings.BACKUP_SERVICE_ACCOUNTS:
                continue
            profile = self.baseline.get_profile("user", user)

            rare_transfers = []
            for t in transfers:
                dst = t.get("dst_ip", "")
                bytes_val = t.get("bytes_transferred", 0) or t.get("bytes", 0)
                if dst and not dst.startswith(("10.", "172.16.", "192.168.", "127.")) and dst not in profile.known_ips:
                    if bytes_val >= 4_000_000:  # 4 MB or more to rare IP
                        rare_transfers.append(t)

            if len(rare_transfers) >= 3:
                evidence_ids = [e["id"] for e in rare_transfers]
                tech = MITRE_TECHNIQUES["exfil_over_web"]
                det = Detection(
                    timestamp=self._parse_ts(rare_transfers[0]["timestamp"]),
                    stage="exfiltration",
                    mitre_tactic="exfiltration",
                    mitre_technique=tech["id"],
                    technique_name="Low-and-Slow Exfiltration",
                    evidence=evidence_ids,
                    reason=f"Repeated data transfers ({len(rare_transfers)} times) to rare external IPs by user '{user}'",
                    entities=self._get_entities(rare_transfers),
                    anomaly_score=2.0,
                    confidence=0.80,
                    rule_name="low_and_slow_exfil"
                )
                detections.append(det)

        return detections

    def _detect_usb_exfil(self, events: list[dict], all_events: list[dict]) -> list[Detection]:
        """Detect file copies to USB devices, especially after bulk file access."""
        detections = []
        user_usb_copies: dict[str, list[dict]] = defaultdict(list)
        user_usb_inserts: dict[str, list[dict]] = defaultdict(list)

        for e in events:
            user = e.get("user", "")
            if not user:
                continue
            if e.get("event_type") == "file_copy" and e.get("device_id"):
                user_usb_copies[user].append(e)
            elif e.get("event_type") == "usb_insert":
                user_usb_inserts[user].append(e)

        for user, copies in user_usb_copies.items():
            if not copies:
                continue

            copy_count = len(copies)
            devices = list(set(c["device_id"] for c in copies if c.get("device_id")))

            if copy_count >= 10 or devices:
                evidence_ids = [c["id"] for c in copies]
                inserts = user_usb_inserts.get(user, [])
                evidence_ids.extend([i["id"] for i in inserts if i["id"] not in evidence_ids])

                tech = MITRE_TECHNIQUES["removable_media_exfil"]
                det = Detection(
                    timestamp=self._parse_ts(copies[0]["timestamp"]),
                    stage="exfiltration",
                    mitre_tactic="exfiltration",
                    mitre_technique=tech["id"],
                    technique_name=tech["name"],
                    evidence=evidence_ids,
                    reason=(
                        f"USB data exfiltration: user '{user}' copied {copy_count} files "
                        f"to removable media ({', '.join(devices)})"
                    ),
                    entities=self._get_entities(copies + inserts),
                    anomaly_score=copy_count * 0.2,
                    confidence=0.85,
                    rule_name="usb_exfiltration",
                )
                detections.append(det)

        return detections

    def _detect_dns_tunnelling(self, events: list[dict]) -> list[Detection]:
        """Detect DNS queries with long/high-entropy subdomains indicative of C2 or data staging."""
        detections = []
        user_dns: dict[str, list[dict]] = defaultdict(list)
        for e in events:
            if e.get("event_type") == "dns_query":
                user = e.get("user", "")
                if user:
                    user_dns[user].append(e)

        for user, dns_events in user_dns.items():
            suspicious = []
            for e in dns_events:
                domain = e.get("file_path", "")
                if not domain:
                    continue
                parts = domain.split(".")
                if len(parts) < 3:
                    continue
                subdomain = ".".join(parts[:-2])

                # Check length (>= 14) and entropy (>= 3.2)
                if len(subdomain) >= 14:
                    entropy = self._shannon_entropy(subdomain)
                    if entropy >= 3.2:
                        suspicious.append(e)

            if len(suspicious) >= 5:
                evidence_ids = [e["id"] for e in suspicious]
                tech = MITRE_TECHNIQUES["dns_tunneling"]
                det = Detection(
                    timestamp=self._parse_ts(suspicious[0]["timestamp"]),
                    stage="exfiltration",
                    mitre_tactic="exfiltration",
                    mitre_technique=tech["id"],
                    technique_name=tech["name"],
                    evidence=evidence_ids,
                    reason=(
                        f"DNS tunnelling detected: user '{user}' made {len(suspicious)} DNS queries "
                        f"with high-entropy, encoded subdomains"
                    ),
                    entities=self._get_entities(suspicious),
                    anomaly_score=len(suspicious) * 0.2,
                    confidence=0.85,
                    rule_name="dns_tunnelling",
                )
                detections.append(det)

        return detections

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        length = len(s)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
