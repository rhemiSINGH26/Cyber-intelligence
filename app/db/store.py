"""
In-memory data store for the CTI system.
Uses dictionaries and lists for fast access during detection.
SQLite is used for persistence across restarts.
"""
from typing import Optional
from datetime import datetime
from app.models.log import LogEvent
from app.models.detection import Incident, Detection, Observation
from app.models.entity import Entity, BaselineProfile, EntityType
from app.models.metrics import StreamStatus
import threading
import json


class DataStore:
    """
    Central in-memory data store. Thread-safe for concurrent access.
    All detection operates on this store; persistence to SQLite is async.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        """Clear all data. Used for dataset switching."""
        with self._lock if hasattr(self, '_lock') else threading.Lock():
            # Log events indexed by ID
            self.logs: dict[str, dict] = {}
            # Ordered log list for timeline queries
            self.log_list: list[dict] = []
            # Incidents
            self.incidents: dict[str, Incident] = {}
            # Observations (low-level anomalies)
            self.observations: list[Observation] = []
            # Detections (raw, before correlation)
            self.detections: list[Detection] = []
            # Entity registry
            self.entities: dict[str, Entity] = {}
            # Baseline profiles
            self.baselines: dict[str, BaselineProfile] = {}
            # Ground truth (only for evaluation)
            self.ground_truth: list[dict] = []
            # Audit log for actions
            self.audit_log: list[dict] = []
            # Stream status
            self.stream_status = StreamStatus()
            # Labels mapping (log_id -> label, only for evaluation)
            self.labels: dict[str, str] = {}
            # Log-to-incident mapping
            self.log_incident_map: dict[str, str] = {}
            self.log_stage_map: dict[str, str] = {}
            # Dataset name currently loaded
            self.current_dataset: Optional[str] = None
            # Ingestion counter
            self.total_ingested: int = 0

    def add_log(self, log: dict) -> str:
        """Add a log event to the store. Returns the log ID."""
        log_id = log.get("id", str(self.total_ingested))
        # Store label separately (never visible to detector)
        if "label" in log:
            if log["label"]:
                self.labels[log_id] = log["label"]
            # Remove label from the working copy
            log = {k: v for k, v in log.items() if k != "label"}
        self.logs[log_id] = log
        self.log_list.append(log)
        self.total_ingested += 1
        return log_id

    def add_logs_batch(self, logs: list[dict]) -> int:
        """Add multiple logs. Returns count added."""
        count = 0
        for log in logs:
            self.add_log(log)
            count += 1
        return count

    def get_log(self, log_id: str) -> Optional[dict]:
        """Get a single log by ID."""
        return self.logs.get(log_id)

    def get_logs(
        self,
        user: Optional[str] = None,
        host: Optional[str] = None,
        ip: Optional[str] = None,
        event_type: Optional[str] = None,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
        query: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[dict], int]:
        """Query logs with filters. Returns (items, total)."""
        results = self.log_list

        if user:
            results = [l for l in results if l.get("user") == user]
        if host:
            results = [l for l in results if l.get("host") == host]
        if ip:
            results = [l for l in results if l.get("src_ip") == ip or l.get("dst_ip") == ip]
        if event_type:
            results = [l for l in results if l.get("event_type") == event_type]
        if from_time:
            from_str = from_time.isoformat() if isinstance(from_time, datetime) else str(from_time)
            results = [l for l in results if l.get("timestamp", "") >= from_str]
        if to_time:
            to_str = to_time.isoformat() if isinstance(to_time, datetime) else str(to_time)
            results = [l for l in results if l.get("timestamp", "") <= to_str]
        if query:
            q_lower = query.lower()
            results = [l for l in results if q_lower in json.dumps(l).lower()]

        total = len(results)
        # Enrich with incident info
        for log in results:
            log_id = log.get("id", "")
            if log_id in self.log_incident_map:
                log["incident_id"] = self.log_incident_map[log_id]
                log["stage"] = self.log_stage_map.get(log_id, "")

        start = (page - 1) * page_size
        end = start + page_size
        return results[start:end], total

    def add_incident(self, incident: Incident):
        """Store an incident and update log-incident mappings."""
        self.incidents[incident.id] = incident
        for stage in incident.stages:
            for log_id in stage.evidence:
                self.log_incident_map[log_id] = incident.id
                self.log_stage_map[log_id] = stage.stage

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def get_incidents(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        sort: str = "-risk_score",
    ) -> list[Incident]:
        """Get filtered and sorted incidents."""
        results = list(self.incidents.values())
        if severity:
            results = [i for i in results if i.severity.value == severity]
        if status:
            results = [i for i in results if i.status.value == status]

        reverse = sort.startswith("-")
        sort_key = sort.lstrip("-")
        if sort_key == "risk_score":
            results.sort(key=lambda i: i.risk_score, reverse=reverse)
        elif sort_key == "first_seen":
            results.sort(key=lambda i: i.first_seen, reverse=reverse)
        elif sort_key == "last_seen":
            results.sort(key=lambda i: i.last_seen, reverse=reverse)
        elif sort_key == "confidence":
            results.sort(key=lambda i: i.confidence, reverse=reverse)
        return results

    def add_observation(self, obs: Observation):
        self.observations.append(obs)

    def add_detection(self, det: Detection):
        self.detections.append(det)

    def register_entity(self, entity_type: str, entity_id: str, timestamp: Optional[datetime] = None):
        """Register or update an entity."""
        key = f"{entity_type}:{entity_id}"
        if key not in self.entities:
            self.entities[key] = Entity(
                entity_type=EntityType(entity_type),
                entity_id=entity_id,
                first_seen=timestamp,
                last_seen=timestamp,
                event_count=1,
            )
        else:
            ent = self.entities[key]
            ent.event_count += 1
            if timestamp:
                if ent.first_seen is None or timestamp < ent.first_seen:
                    ent.first_seen = timestamp
                if ent.last_seen is None or timestamp > ent.last_seen:
                    ent.last_seen = timestamp

    def add_audit_entry(self, entry: dict):
        self.audit_log.append(entry)

    def set_baseline(self, entity_type: str, entity_id: str, profile: BaselineProfile):
        key = f"{entity_type}:{entity_id}"
        self.baselines[key] = profile

    def get_baseline(self, entity_type: str, entity_id: str) -> Optional[BaselineProfile]:
        return self.baselines.get(f"{entity_type}:{entity_id}")


# Global singleton
store = DataStore()
