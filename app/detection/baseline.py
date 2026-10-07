"""
Per-entity behavioural baselines.
Computes typical patterns from the training window (first N days).
"""
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np
from app.config import settings
from app.models.entity import BaselineProfile, EntityType


class BaselineBuilder:
    """Builds behavioural baselines for users and hosts from training data."""

    def __init__(self):
        self.profiles: dict[str, BaselineProfile] = {}
        # Accumulation structures
        self._hourly_counts: dict[str, list[int]] = defaultdict(lambda: [0] * 24)
        self._weekday_counts: dict[str, list[int]] = defaultdict(lambda: [0] * 7)
        self._geos: dict[str, set] = defaultdict(set)
        self._hosts: dict[str, set] = defaultdict(set)
        self._ips: dict[str, set] = defaultdict(set)
        self._apps: dict[str, set] = defaultdict(set)
        self._files: dict[str, set] = defaultdict(set)
        self._devices: dict[str, set] = defaultdict(set)
        self._daily_bytes: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._daily_events: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._total_events: dict[str, int] = defaultdict(int)
        self._training_start: datetime = None
        self._training_end: datetime = None

    def set_training_window(self, start: datetime, days: int = None):
        """Set the training window for baseline computation."""
        if days is None:
            days = settings.BASELINE_TRAINING_DAYS
        self._training_start = start
        self._training_end = start + timedelta(days=days)

    def is_in_training_window(self, timestamp: datetime) -> bool:
        """Check if a timestamp falls within the training window."""
        if self._training_start is None:
            return False
        return self._training_start <= timestamp < self._training_end

    def add_event(self, event: dict):
        """Add an event to the baseline accumulator (only during training window)."""
        ts_str = event.get("timestamp", "")
        try:
            if isinstance(ts_str, str):
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
            else:
                ts = ts_str
        except (ValueError, AttributeError):
            return

        if not self.is_in_training_window(ts):
            return

        user = event.get("user", "")
        host = event.get("host", "")

        # Build keys for user and host
        for entity_type, entity_id in [("user", user), ("host", host)]:
            if not entity_id:
                continue
            key = f"{entity_type}:{entity_id}"

            self._hourly_counts[key][ts.hour] += 1
            self._weekday_counts[key][ts.weekday()] += 1
            self._total_events[key] += 1

            day_key = ts.strftime("%Y-%m-%d")
            self._daily_events[key][day_key] += 1

            if event.get("geo_country"):
                self._geos[key].add(event["geo_country"])
            if event.get("host") and entity_type == "user":
                self._hosts[key].add(event["host"])
            if event.get("src_ip"):
                self._ips[key].add(event["src_ip"])
            if event.get("dst_ip"):
                self._ips[key].add(event["dst_ip"])
            if event.get("app"):
                self._apps[key].add(event["app"])
            if event.get("file_path"):
                self._files[key].add(event["file_path"])
            if event.get("device_id"):
                self._devices[key].add(event["device_id"])

            bytes_val = event.get("bytes", 0) or event.get("bytes_transferred", 0) or 0
            if bytes_val:
                self._daily_bytes[key][day_key] += bytes_val

    def build_profiles(self) -> dict[str, BaselineProfile]:
        """Finalize all baseline profiles from accumulated data."""
        for key in self._total_events:
            entity_type, entity_id = key.split(":", 1)

            # Normalize hourly histogram
            hourly = self._hourly_counts[key]
            total_h = sum(hourly) or 1
            hourly_norm = [h / total_h for h in hourly]

            weekday = self._weekday_counts[key]
            total_w = sum(weekday) or 1
            weekday_norm = [w / total_w for w in weekday]

            # Daily stats
            daily_b = list(self._daily_bytes[key].values()) or [0]
            daily_e = list(self._daily_events[key].values()) or [0]

            profile = BaselineProfile(
                entity_type=EntityType(entity_type),
                entity_id=entity_id,
                hourly_histogram=hourly_norm,
                weekday_histogram=weekday_norm,
                known_geos=self._geos.get(key, set()),
                known_hosts=self._hosts.get(key, set()),
                known_ips=self._ips.get(key, set()),
                known_apps=self._apps.get(key, set()),
                known_files=self._files.get(key, set()),
                known_devices=self._devices.get(key, set()),
                daily_bytes_mean=float(np.mean(daily_b)),
                daily_bytes_std=float(np.std(daily_b)) if len(daily_b) > 1 else float(np.mean(daily_b)) * 0.5,
                daily_event_count_mean=float(np.mean(daily_e)),
                daily_event_count_std=float(np.std(daily_e)) if len(daily_e) > 1 else float(np.mean(daily_e)) * 0.5,
                total_events=self._total_events[key],
                training_days=settings.BASELINE_TRAINING_DAYS,
            )
            self.profiles[key] = profile

        # Build peer groups (same entity type, similar event counts)
        self._build_peer_groups()

        return self.profiles

    def _build_peer_groups(self):
        """Assign peer groups based on entity type and activity level."""
        by_type: dict[str, list[tuple[str, BaselineProfile]]] = defaultdict(list)
        for key, profile in self.profiles.items():
            by_type[profile.entity_type.value].append((key, profile))

        for entity_type, profiles in by_type.items():
            # Sort by daily event count
            profiles.sort(key=lambda x: x[1].daily_event_count_mean)

            for i, (key, profile) in enumerate(profiles):
                # Peers are the N nearest by activity level
                start = max(0, i - settings.PEER_GROUP_SIZE // 2)
                end = min(len(profiles), start + settings.PEER_GROUP_SIZE)
                peers = [p[1] for j, p in enumerate(profiles[start:end]) if profiles[start + j][0] != key]

                profile.peer_group = [p.entity_id for p in peers]
                if peers:
                    profile.peer_daily_bytes_mean = float(np.mean([p.daily_bytes_mean for p in peers]))
                    profile.peer_daily_event_mean = float(np.mean([p.daily_event_count_mean for p in peers]))

    def get_profile(self, entity_type: str, entity_id: str) -> BaselineProfile:
        """Get baseline profile for an entity. Returns empty profile if not found."""
        key = f"{entity_type}:{entity_id}"
        if key in self.profiles:
            return self.profiles[key]
        # Return an empty profile (new entity, no baseline)
        return BaselineProfile(entity_type=EntityType(entity_type), entity_id=entity_id)

    def is_geo_anomalous(self, user: str, geo: str) -> bool:
        """Check if a geo is anomalous for a user."""
        profile = self.get_profile("user", user)
        if not profile.known_geos or profile.total_events < settings.MIN_OBSERVATIONS_FOR_BASELINE:
            return False
        return geo not in profile.known_geos

    def is_hour_anomalous(self, user: str, hour: int) -> bool:
        """Check if an hour is anomalous for a user (z-score based)."""
        profile = self.get_profile("user", user)
        if profile.total_events < settings.MIN_OBSERVATIONS_FOR_BASELINE:
            return False
        hist = profile.hourly_histogram
        mean_h = np.mean(hist)
        std_h = np.std(hist)
        if std_h == 0:
            return hist[hour] == 0
        z = (hist[hour] - mean_h) / std_h
        return z < -settings.LOGIN_TIME_ANOMALY_ZSCORE

    def is_host_anomalous(self, user: str, host: str) -> bool:
        """Check if a host is new for a user."""
        profile = self.get_profile("user", user)
        if profile.total_events < settings.MIN_OBSERVATIONS_FOR_BASELINE:
            return False
        return host not in profile.known_hosts and len(profile.known_hosts) > 0

    def is_bytes_anomalous(self, entity_type: str, entity_id: str, daily_bytes: float) -> tuple[bool, float]:
        """Check if daily bytes are anomalous. Returns (is_anomalous, z_score)."""
        profile = self.get_profile(entity_type, entity_id)
        if profile.total_events < settings.MIN_OBSERVATIONS_FOR_BASELINE:
            return False, 0.0
        if profile.daily_bytes_std == 0:
            return daily_bytes > profile.daily_bytes_mean * 3, 3.0 if daily_bytes > profile.daily_bytes_mean * 3 else 0.0
        z = (daily_bytes - profile.daily_bytes_mean) / profile.daily_bytes_std
        return z > settings.EXFIL_BYTES_ZSCORE, z
