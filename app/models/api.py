"""API request/response wrapper models."""
from pydantic import BaseModel, Field
from typing import Optional, Any


class PaginatedResponse(BaseModel):
    """Generic paginated response wrapper."""
    items: list[Any] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 50
    total_pages: int = 1


class ActionRequest(BaseModel):
    """Request to execute a SOAR-like action on an incident."""
    action: str  # isolate_host, block_ip, disable_user, rotate_credentials, revoke_usb
    target: str  # Entity identifier
    target_type: str  # host, ip, user, device
    notes: Optional[str] = None


class ActionResponse(BaseModel):
    """Response after executing an action."""
    success: bool
    action: str
    target: str
    message: str
    audit_id: str
    timestamp: str


class UploadResponse(BaseModel):
    """Response after file upload."""
    filename: str
    logs_ingested: int
    errors: int = 0
    message: str = ""


class DatasetLoadResponse(BaseModel):
    """Response after loading a dataset."""
    dataset: str
    logs_loaded: int
    message: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str = "1.0.0"
    logs_in_store: int = 0
    incidents_count: int = 0
    database: str = "connected"


class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str
    error_code: Optional[str] = None
