"""
Unified log event schema.
Every log — regardless of source — is normalized to this model before storage.
"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime
from enum import Enum
import uuid


class EventType(str, Enum):
    """All recognized event types in the unified schema."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    FILE_ACCESS = "file_access"
    FILE_COPY = "file_copy"
    FILE_DELETE = "file_delete"
    FILE_MODIFY = "file_modify"
    USB_INSERT = "usb_insert"
    USB_EJECT = "usb_eject"
    PROCESS_START = "process_start"
    PROCESS_STOP = "process_stop"
    PRIVILEGE_CHANGE = "privilege_change"
    NETWORK_CONN = "network_conn"
    DNS_QUERY = "dns_query"
    EMAIL_SEND = "email_send"
    EMAIL_RECEIVE = "email_receive"
    ACCOUNT_CHANGE = "account_change"
    ACCOUNT_CREATE = "account_create"
    REGISTRY_CHANGE = "registry_change"
    SERVICE_START = "service_start"
    SERVICE_STOP = "service_stop"
    LOGOFF = "logoff"
    REMOTE_SESSION = "remote_session"
    DATA_UPLOAD = "data_upload"
    SCHEDULED_TASK = "scheduled_task"
    UNKNOWN = "unknown"


class LogEvent(BaseModel):
    """Unified log event schema. All fields are optional except id and timestamp."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    event_type: EventType = EventType.UNKNOWN
    user: Optional[str] = None
    host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    app: Optional[str] = None
    file_path: Optional[str] = None
    bytes_transferred: Optional[int] = Field(default=None, alias="bytes")
    geo_country: Optional[str] = None
    device_id: Optional[str] = None
    status: Optional[str] = None
    raw: Optional[str] = None
    label: Optional[str] = Field(default=None, exclude=True)  # Ground truth, hidden from detector
    # Enrichment fields (added during processing)
    incident_id: Optional[str] = None
    stage: Optional[str] = None

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "example": {
                "id": "evt-001",
                "timestamp": "2025-01-15T09:30:00Z",
                "event_type": "login_success",
                "user": "jsmith",
                "host": "WKS-042",
                "src_ip": "10.0.1.50",
                "geo_country": "US",
            }
        }
    }

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v):
        """Accept various timestamp formats."""
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            # Try ISO format first
            for fmt in [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
            ]:
                try:
                    return datetime.strptime(v, fmt)
                except ValueError:
                    continue
            # Fallback: fromisoformat
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        raise ValueError(f"Cannot parse timestamp: {v}")


class LogEventCreate(BaseModel):
    """Schema for creating a log event via API (without auto-generated fields)."""
    timestamp: datetime
    event_type: str = "unknown"
    user: Optional[str] = None
    host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    app: Optional[str] = None
    file_path: Optional[str] = None
    bytes_transferred: Optional[int] = Field(default=None, alias="bytes")
    geo_country: Optional[str] = None
    device_id: Optional[str] = None
    status: Optional[str] = None
    raw: Optional[str] = None

    model_config = {"populate_by_name": True}
