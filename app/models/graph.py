"""Graph models for threat intelligence visualization."""
from pydantic import BaseModel, Field
from typing import Optional


class GraphNode(BaseModel):
    """A node in the threat graph."""
    id: str
    label: str
    node_type: str  # user, host, ip, app, file, device
    risk_score: float = 0.0
    is_suspicious: bool = False
    incident_ids: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """An edge in the threat graph."""
    source: str
    target: str
    edge_type: str  # event_type or relationship type
    weight: float = 1.0
    timestamp: Optional[str] = None
    is_suspicious: bool = False
    event_ids: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class GraphResponse(BaseModel):
    """Full graph data for API response."""
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    attack_path: list[str] = Field(default_factory=list)  # Ordered node IDs
    metadata: dict = Field(default_factory=dict)
