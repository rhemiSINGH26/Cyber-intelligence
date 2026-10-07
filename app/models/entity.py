"""
Entity models for the CTI system.
Entities are the core nodes in the threat graph: users, hosts, IPs, apps, files, devices.
"""
from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum
from datetime import datetime


class EntityType(str, Enum):
    USER = "user"
    HOST = "host"
    IP = "ip"
    APP = "app"
    FILE = "file"
    DEVICE = "device"


class Entity(BaseModel):
    """An entity node in the threat intelligence graph."""
    entity_type: EntityType
    entity_id: str  # Canonical identifier
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    event_count: int = 0
    anomaly_score: float = 0.0
    risk_level: str = "low"
    related_incidents: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class BaselineProfile(BaseModel):
    """Per-entity behavioural baseline, computed from the training window."""
    entity_type: EntityType
    entity_id: str
    # Time patterns
    hourly_histogram: list[float] = Field(default_factory=lambda: [0.0] * 24)
    weekday_histogram: list[float] = Field(default_factory=lambda: [0.0] * 7)
    # Known sets
    known_geos: set[str] = Field(default_factory=set)
    known_hosts: set[str] = Field(default_factory=set)
    known_ips: set[str] = Field(default_factory=set)
    known_apps: set[str] = Field(default_factory=set)
    known_files: set[str] = Field(default_factory=set)
    known_devices: set[str] = Field(default_factory=set)
    # Volume statistics
    daily_bytes_mean: float = 0.0
    daily_bytes_std: float = 0.0
    daily_event_count_mean: float = 0.0
    daily_event_count_std: float = 0.0
    # Peer group
    peer_group: list[str] = Field(default_factory=list)
    peer_daily_bytes_mean: float = 0.0
    peer_daily_event_mean: float = 0.0
    # Observation count
    total_events: int = 0
    training_days: int = 0

    model_config = {"arbitrary_types_allowed": True}


class EntityDetail(BaseModel):
    """Detailed entity information for API response."""
    entity: Entity
    baseline: Optional[BaselineProfile] = None
    anomaly_timeline: list[dict] = Field(default_factory=list)
    related_incidents: list[dict] = Field(default_factory=list)
    recent_events: list[dict] = Field(default_factory=list)
