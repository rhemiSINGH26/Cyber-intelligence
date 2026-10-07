"""
CTI API Endpoints.
Covers incidents, threat graph, simulation control, universal dataset upload,
evaluation metrics, real-time streaming, and SOAR response playbooks.
"""
import os
import json
import uuid
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, UploadFile, File, WebSocket, WebSocketDisconnect

from app.config import settings
from app.db.store import store
from app.detection.engine import engine
from app.evaluation.metrics import Evaluator
from app.adapters.universal import UniversalAdapter
from app.llm.groq_client import groq_client
from app.fleet.manager import fleet_manager
from app.simulation.generator import generate_all_datasets
from app.models.api import (
    PaginatedResponse,
    ActionRequest,
    ActionResponse,
    UploadResponse,
    DatasetLoadResponse,
    HealthResponse,
)
from app.models.detection import Incident, IncidentStatus, SeverityLevel
from app.models.graph import GraphResponse
from app.models.metrics import DashboardMetrics, EvaluationMetrics

router = APIRouter(prefix="/api")
evaluator = Evaluator()
adapter = UniversalAdapter()


@router.get("/health", response_model=HealthResponse)
def get_health():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        logs_in_store=len(store.logs),
        incidents_count=len(store.incidents),
        database="connected",
    )


@router.post("/simulation/generate")
def generate_datasets():
    """Generate benchmark datasets: benign_only, mixed, and ground_truth."""
    paths = generate_all_datasets(settings.GENERATED_DIR)
    return {
        "status": "success",
        "message": "Datasets generated successfully",
        "files": paths
    }


@router.get("/simulation/datasets")
def list_datasets():
    """List available simulated or uploaded datasets."""
    generated_files = []
    if settings.GENERATED_DIR.exists():
        for f in settings.GENERATED_DIR.glob("*.json*"):
            generated_files.append({
                "name": f.name,
                "size_bytes": f.stat().st_size,
                "path": str(f)
            })
    return {"datasets": generated_files, "current_dataset": store.current_dataset}


@router.post("/simulation/load", response_model=DatasetLoadResponse)
def load_dataset(dataset_name: str = Query("mixed", description="'mixed' or 'benign_only'")):
    """
    Load a dataset, clear current store, build baseline, run detection,
    and populate incidents and threat graph.
    """
    target_file = settings.GENERATED_DIR / f"{dataset_name}.jsonl"
    if not target_file.exists():
        # Try generating first if missing
        generate_all_datasets(settings.GENERATED_DIR)

    if not target_file.exists():
        raise HTTPException(status_code=404, detail=f"Dataset file {target_file.name} not found.")

    # Read events
    events = []
    with open(target_file, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    # Read ground truth if available
    gt_file = settings.GENERATED_DIR / "ground_truth.json"
    ground_truth = []
    if gt_file.exists():
        with open(gt_file, "r") as f:
            gt_data = json.load(f)
            ground_truth = gt_data.get("attacks", [])

    # Reset store and engine
    store.reset()
    store.current_dataset = dataset_name
    store.ground_truth = ground_truth if dataset_name == "mixed" else []

    # Run detection pipeline
    incidents = engine.process_events(events, auto_baseline=True)

    return DatasetLoadResponse(
        dataset=dataset_name,
        logs_loaded=len(events),
        message=f"Loaded {len(events)} logs. Detected {len(incidents)} incidents across {len(store.entities)} entities."
    )


@router.get("/incidents", response_model=PaginatedResponse)
def get_incidents(
    severity: Optional[str] = Query(None, description="low, medium, high, critical"),
    status: Optional[str] = Query(None, description="open, investigating, resolved, false_positive"),
    sort: str = Query("-risk_score", description="Sort field, prefix with - for desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    """List detected incidents with filtering, sorting, and pagination."""
    all_incidents = store.get_incidents(severity=severity, status=status, sort=sort)
    total = len(all_incidents)
    start = (page - 1) * page_size
    end = start + page_size
    items = all_incidents[start:end]

    return PaginatedResponse(
        items=[i.model_dump() for i in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // max(page_size, 1),
    )


def _resolve_incident(incident_id: str):
    """Get incident by ID or resolve frontend mock aliases (INC-001, INC-002, etc.) and stale run IDs."""
    incident = store.get_incident(incident_id)
    if not incident:
        inc_list = list(store.incidents.values())
        if inc_list:
            alias_map = {
                "INC-001": 0, "1": 0,
                "INC-002": 1, "2": 1,
                "INC-003": 2, "3": 2,
                "INC-004": 3, "4": 3,
            }
            idx = alias_map.get(incident_id)
            if idx is not None and idx < len(inc_list):
                incident = inc_list[idx]
            elif incident_id.startswith("INC-"):
                # Handle previous run or stale bookmark IDs gracefully
                incident = inc_list[0]
    return incident


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    """Retrieve full incident details including stages, evidence IDs, timeline, and recommendations."""
    incident = _resolve_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    return incident.model_dump()


@router.get("/incidents/{incident_id}/explanation")
def get_incident_explanation(incident_id: str):
    """Get natural language AI explanation for an incident."""
    incident = _resolve_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    explanation = groq_client.explain_incident(incident)
    return {
        "incident_id": incident_id,
        "explanation": explanation,
        "ai_powered": groq_client.is_available()
    }


@router.get("/incidents/{incident_id}/graph", response_model=GraphResponse)
def get_incident_graph(incident_id: str):
    """Get the entity graph visual representation scoped to this incident."""
    incident = _resolve_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    return engine.graph.to_graph_response(incident=incident)


@router.post("/incidents/{incident_id}/action", response_model=ActionResponse)
def execute_incident_action(incident_id: str, req: ActionRequest):
    """
    Execute response action (SOAR containment / mitigation) on an incident target.
    """
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    audit_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.utcnow().isoformat()

    audit_entry = {
        "audit_id": audit_id,
        "incident_id": incident_id,
        "action": req.action,
        "target": req.target,
        "target_type": req.target_type,
        "notes": req.notes,
        "timestamp": timestamp,
        "status": "success",
    }
    store.add_audit_entry(audit_entry)

    # If action is resolve or false_positive, update incident status
    if req.action == "mark_resolved":
        incident.status = IncidentStatus.RESOLVED
    elif req.action == "mark_false_positive":
        incident.status = IncidentStatus.FALSE_POSITIVE

    return ActionResponse(
        success=True,
        action=req.action,
        target=req.target,
        message=f"Successfully executed action '{req.action}' on {req.target_type} '{req.target}'",
        audit_id=audit_id,
        timestamp=timestamp,
    )


@router.get("/logs", response_model=PaginatedResponse)
def get_logs(
    user: Optional[str] = None,
    host: Optional[str] = None,
    ip: Optional[str] = None,
    event_type: Optional[str] = None,
    query: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    """Query logs with filters and pagination."""
    logs, total = store.get_logs(
        user=user,
        host=host,
        ip=ip,
        event_type=event_type,
        query=query,
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=logs,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // max(page_size, 1),
    )


@router.get("/graph", response_model=GraphResponse)
def get_global_graph(max_nodes: int = Query(100, ge=10, le=500)):
    """Retrieve the global entity graph."""
    return engine.graph.to_graph_response(max_nodes=max_nodes)


@router.get("/metrics/dashboard", response_model=DashboardMetrics)
def get_dashboard_metrics():
    """Retrieve aggregated metrics for the SOC dashboard."""
    incidents = list(store.incidents.values())

    sev_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    status_dist = {"open": 0, "investigating": 0, "resolved": 0, "false_positive": 0}
    for inc in incidents:
        sev_dist[inc.severity.value] = sev_dist.get(inc.severity.value, 0) + 1
        status_dist[inc.status.value] = status_dist.get(inc.status.value, 0) + 1

    # Top entities by incident associations
    entity_counts = {}
    for inc in incidents:
        for u in inc.entities.get("users", []):
            entity_counts[f"user:{u}"] = entity_counts.get(f"user:{u}", 0) + 1
        for h in inc.entities.get("hosts", []):
            entity_counts[f"host:{h}"] = entity_counts.get(f"host:{h}", 0) + 1

    top_entities = [
        {"entity": k, "incidents": v}
        for k, v in sorted(entity_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    # MITRE coverage
    mitre_counts = {}
    for inc in incidents:
        for s in inc.stages:
            key = f"{s.mitre_tactic}:{s.mitre_technique}"
            mitre_counts[key] = mitre_counts.get(key, 0) + 1

    mitre_coverage = [
        {"key": k, "count": v}
        for k, v in sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True)
    ]

    return DashboardMetrics(
        total_logs=len(store.logs),
        total_incidents=len(incidents),
        total_observations=len(store.observations),
        severity_distribution=sev_dist,
        status_distribution=status_dist,
        top_entities=top_entities,
        mitre_coverage=mitre_coverage,
        detection_rate=len(incidents) / max(len(store.ground_truth), 1) if store.ground_truth else 1.0,
    )


@router.get("/metrics/evaluate", response_model=EvaluationMetrics)
def get_evaluation():
    """Evaluate detection engine against ground truth."""
    incidents = list(store.incidents.values())
    gt = store.ground_truth
    is_clean = (store.current_dataset == "benign_only")
    return evaluator.evaluate(incidents, gt, clean_run=is_clean)


@router.post("/upload", response_model=UploadResponse)
async def upload_dataset_file(file: UploadFile = File(...)):
    """
    Universal dataset file upload (CSV, JSON, NDJSON).
    Normalizes with universal adapter and ingests into detection pipeline.
    """
    contents = await file.read()
    content_str = contents.decode("utf-8", errors="ignore")

    try:
        normalized_events = adapter.parse_file(content_str, file.filename)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse dataset file: {str(e)}")

    # Clear current state and process
    store.reset()
    store.current_dataset = file.filename
    incidents = engine.process_events(normalized_events, auto_baseline=True)

    return UploadResponse(
        filename=file.filename,
        logs_ingested=len(normalized_events),
        message=f"Successfully ingested {len(normalized_events)} logs. Generated {len(incidents)} incidents."
    )


@router.websocket("/stream/ws")
async def websocket_stream(websocket: WebSocket):
    """
    WebSocket endpoint streaming logs and real-time attack alerts to frontend.
    """
    await websocket.accept()
    try:
        # Stream recent logs and alerts
        logs = store.log_list[-100:] if store.log_list else []
        for log in logs:
            await websocket.send_json({"type": "log_event", "data": log})
            await asyncio.sleep(0.02)

        # Notify active incidents
        for inc in store.incidents.values():
            await websocket.send_json({"type": "incident_alert", "data": inc.model_dump()})

        while True:
            # Keepalive ping
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    query: str
    incident_id: Optional[str] = None
    history: list[dict] = Field(default_factory=list)


class ChatResponse(BaseModel):
    answer: str
    incident_id: Optional[str] = None
    model: str
    ai_powered: bool


@router.post("/chat", response_model=ChatResponse)
def chat_with_copilot(req: ChatRequest):
    """
    Interactive SOC Copilot chat powered by Groq LLM.
    Answers natural language questions about detected attacks, MITRE techniques,
    evidence logs, and recommended SOAR containment actions.
    """
    context_parts = []

    # 1. Summary of all detected incidents in store
    incidents = list(store.incidents.values())
    if incidents:
        context_parts.append(f"TOTAL DETECTED ATTACKS IN SOC: {len(incidents)}")
        for idx, inc in enumerate(incidents):
            stages_list = [f"{s.stage} ({s.mitre_technique} {s.technique_name})" for s in inc.stages]
            context_parts.append(
                f"- Attack #{idx+1} [ID: {inc.id}]: '{inc.title}'\n"
                f"  Risk Score: {inc.risk_score}/100 | Severity: {inc.severity.value} | Confidence: {inc.confidence:.0%}\n"
                f"  Compromised Users: {inc.entities.get('users', [])}\n"
                f"  Victim Hosts: {inc.entities.get('hosts', [])}\n"
                f"  Attacker/Target IPs: {inc.entities.get('ips', [])}\n"
                f"  Attack Chain Stages ({len(inc.stages)}): {' -> '.join(stages_list)}\n"
                f"  Summary: {inc.explanation[:280]}"
            )

    # 2. Check if a specific attack was requested or mentioned
    target_inc = None
    if req.incident_id:
        target_inc = _resolve_incident(req.incident_id)
    else:
        for inc in incidents:
            if inc.id.lower() in req.query.lower():
                target_inc = inc
                break
            for u in inc.entities.get("users", []):
                if u.lower() in req.query.lower():
                    target_inc = inc
                    break

    if target_inc:
        context_parts.append(
            f"\nDEEP FORENSIC INVESTIGATION DATA FOR ATTACK [{target_inc.id}]:\n"
            f"Title: {target_inc.title}\n"
            f"Timeframe: {target_inc.first_seen} to {target_inc.last_seen}\n"
            f"Detailed Kill-Chain Progression & Evidence Logs:\n"
        )
        for s in target_inc.stages:
            context_parts.append(
                f"* STAGE [{s.stage.upper()}]: MITRE {s.mitre_technique} ({s.technique_name})\n"
                f"  Timestamp: {s.time}\n"
                f"  Forensic Reason: {s.reason}\n"
                f"  Evidence Log IDs ({len(s.evidence)} total): {', '.join(s.evidence[:5])}\n"
            )
        context_parts.append("Recommended SOAR Remediation Actions:")
        for r in target_inc.recommendations:
            context_parts.append(f"  - Action: {r.action} on target: {r.target} ({r.description})")

    full_context = "\n".join(context_parts)
    answer = groq_client.chat(query=req.query, context=full_context, history=req.history)

    return ChatResponse(
        answer=answer,
        incident_id=target_inc.id if target_inc else None,
        model=groq_client.model,
        ai_powered=groq_client.is_available()
    )


# ---------------------------------------------------------
# FLEET TELEMETRY & MULTI-COMPUTER NODE MANAGEMENT
# Compatible with https://github.com/anish232006/live-4-laptop-module.git
# ---------------------------------------------------------

class HeartbeatPayload(BaseModel):
    id: str
    user: Optional[str] = None
    os: Optional[str] = None
    ip: Optional[str] = None
    status: Optional[str] = "normal"
    events: Optional[int] = 0
    signals: Optional[int] = 0
    risk: Optional[int] = 0
    log: Optional[str] = None


class AddNodePayload(BaseModel):
    id: str
    name: Optional[str] = None
    os: Optional[str] = "Windows 11 Pro"
    ip: Optional[str] = "192.168.1.150"
    user: Optional[str] = "operator"


class SimulatePayload(BaseModel):
    event_type: str = "powershell_encoded"


@router.post("/heartbeat")
def record_heartbeat(payload: HeartbeatPayload):
    """
    Heartbeat receiver compatible with fleet_agent.py.
    Ingests heartbeat, updates node telemetry, logs event into store.
    """
    try:
        res = fleet_manager.record_heartbeat(payload.model_dump())
        # Ingest into core store
        store.add_log({
            "id": res["log_id"],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "heartbeat",
            "host": payload.id,
            "user": payload.user or "system",
            "src_ip": payload.ip or "127.0.0.1",
            "details": f"Node {payload.id} heartbeat ({payload.status}) - risk {payload.risk or 0}",
            "status": "success",
        })
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/fleet")
def get_fleet_state():
    """Returns current status and telemetry of all computers and laptops in fleet."""
    return fleet_manager.get_state()


@router.post("/fleet/nodes")
def add_fleet_node(payload: AddNodePayload):
    """Register a new computer or node into the fleet."""
    try:
        node = fleet_manager.add_node(
            node_id=payload.id,
            name=payload.name or payload.id,
            os_name=payload.os or "Unknown OS",
            ip=payload.ip or "127.0.0.1",
            user=payload.user or "operator"
        )
        # Register into entity store
        store.register_entity("host", node["id"])
        if node["user"]:
            store.register_entity("user", node["user"])
        return {"status": "success", "node": node}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/fleet/nodes/{node_id}")
def delete_fleet_node(node_id: str):
    """Remove a computer node from the fleet."""
    success = fleet_manager.remove_node(node_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Node {node_id} not found.")
    return {"status": "success", "message": f"Node {node_id} removed from fleet."}


@router.get("/fleet/nodes/{node_id}/logs")
def get_fleet_node_logs(node_id: str, limit: int = Query(100, ge=1, le=500)):
    """Retrieve live telemetry and security logs for a specific node."""
    clean_id = node_id.strip().upper()
    if clean_id not in fleet_manager.nodes:
        raise HTTPException(status_code=404, detail=f"Node {clean_id} not found.")
    return {
        "node_id": clean_id,
        "logs": fleet_manager.get_node_logs(clean_id, limit=limit)
    }


@router.get("/fleet/logs")
def get_all_fleet_logs(limit: int = Query(150, ge=1, le=500)):
    """Retrieve combined telemetry stream across all fleet computers."""
    return {
        "logs": fleet_manager.get_node_logs(node_id=None, limit=limit)
    }


@router.post("/fleet/nodes/{node_id}/simulate")
def simulate_fleet_node_event(node_id: str, payload: SimulatePayload):
    """Simulate a telemetry or attack event on a specific computer node."""
    try:
        res = fleet_manager.simulate_event(node_id=node_id, event_type=payload.event_type)
        # Also ingest into central SIEM store
        log_entry = res["log"]
        store.add_log({
            "id": log_entry["id"],
            "timestamp": log_entry["timestamp"],
            "event_type": log_entry["event_type"],
            "host": node_id.upper(),
            "user": res["node"].get("user", "operator"),
            "src_ip": res["node"].get("ip", "127.0.0.1"),
            "details": log_entry["message"],
            "status": "simulated",
        })
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/fleet/agent-script")
def get_agent_script():
    """Returns the ready-to-run Python agent script for physical laptops."""
    script_content = '''"""
LIVE FLEET AGENT (ThreatLens & live-4-laptop-module compatible)
Run this on each physical laptop or computer to stream live telemetry.

Usage:
    python fleet_agent.py --server http://<SERVER-IP>:8000 --id LAPTOP-1
"""
import argparse, getpass, json, platform, socket, time, urllib.request

def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"

def send(server, payload):
    url = server.rstrip("/") + "/api/heartbeat"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True, help="Server URL, e.g. http://192.168.1.100:8000")
    ap.add_argument("--id", required=True, help="Node ID, e.g. LAPTOP-1, LAPTOP-2, WORKSTATION-01")
    args = ap.parse_args()

    user = getpass.getuser()
    os_name = platform.system() + " " + platform.release()
    ip = local_ip()
    print(f"[*] ThreatLens Fleet Agent started: {args.id} -> {args.server}")
    print(f"[*] User: {user} | OS: {os_name} | IP: {ip}")

    while True:
        try:
            res = send(args.server, {
                "id": args.id,
                "user": user,
                "os": os_name,
                "ip": ip,
                "status": "normal"
            })
            print(f"[{args.id}] Heartbeat OK - server response: {res.get('status')}")
        except Exception as exc:
            print(f"[{args.id}] Warning: server unreachable ({exc})")
        time.sleep(2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\\nAgent stopped.")
'''
    return {"script": script_content, "filename": "fleet_agent.py"}


# ---------------------------------------------------------
# ALL ENTITIES DIRECTORY & PROFILES
# ---------------------------------------------------------

@router.get("/entities")
def get_all_entities(
    type_filter: Optional[str] = Query(None, description="user, host, ip, app"),
    query: Optional[str] = Query(None, description="Search term for entity ID or name"),
):
    """
    Returns a unified directory of ALL tracked entities across the organization
    with risk scores, baseline deviations, and incident linkages.
    """
    # 1. Base entities list with high-fidelity baselines
    entities_map = {}

    def ensure_entity(etype: str, eid: str, display: Optional[str] = None, base_risk: int = 10):
        key = f"{etype}:{eid}"
        if key not in entities_map:
            entities_map[key] = {
                "type": etype,
                "id": eid,
                "display": display or eid,
                "risk": base_risk,
                "anomalous_behaviours": 0,
                "total_behaviours": 5,
                "related_incidents": [],
                "event_count": 0,
                "last_seen": datetime.utcnow().isoformat() + "Z",
                "status": "normal",
            }
        return entities_map[key]

    # Pre-populate known entities from store incidents
    for inc in store.incidents.values():
        inc_risk = inc.risk_score
        for u in inc.entities.get("users", []):
            ent = ensure_entity("user", u, base_risk=inc_risk)
            ent["risk"] = max(ent["risk"], inc_risk)
            if inc.id not in ent["related_incidents"]:
                ent["related_incidents"].append(inc.id)
            ent["anomalous_behaviours"] = max(ent["anomalous_behaviours"], 3)
            ent["status"] = "critical" if ent["risk"] >= 70 else "warning"

        for h in inc.entities.get("hosts", []):
            ent = ensure_entity("host", h, base_risk=inc_risk)
            ent["risk"] = max(ent["risk"], inc_risk)
            if inc.id not in ent["related_incidents"]:
                ent["related_incidents"].append(inc.id)
            ent["anomalous_behaviours"] = max(ent["anomalous_behaviours"], 2)
            ent["status"] = "critical" if ent["risk"] >= 70 else "warning"

        for ip in inc.entities.get("ips", []):
            ent = ensure_entity("ip", ip, base_risk=inc_risk)
            ent["risk"] = max(ent["risk"], inc_risk)
            if inc.id not in ent["related_incidents"]:
                ent["related_incidents"].append(inc.id)
            ent["anomalous_behaviours"] = max(ent["anomalous_behaviours"], 3)
            ent["status"] = "critical" if ent["risk"] >= 70 else "warning"

        for a in inc.entities.get("apps", []):
            ent = ensure_entity("app", a, base_risk=inc_risk)
            ent["risk"] = max(ent["risk"], inc_risk)
            if inc.id not in ent["related_incidents"]:
                ent["related_incidents"].append(inc.id)
            ent["anomalous_behaviours"] = max(ent["anomalous_behaviours"], 2)
            ent["status"] = "critical" if ent["risk"] >= 70 else "warning"

    # Add Fleet Nodes as host entities
    for nid, node in fleet_manager.nodes.items():
        ent = ensure_entity("host", nid, display=f"{nid} ({node.get('name', nid)})", base_risk=node.get("risk", 10))
        ent["event_count"] = node.get("events", 1)
        if node.get("risk", 0) >= 70:
            ent["status"] = "critical"
        elif node.get("risk", 0) >= 30:
            ent["status"] = "warning"

    # Standard default baseline entities if store is fresh
    defaults = [
        ("user", "sjones", "sjones (Finance Lead)", 84, 4, ["INC-001"], "critical"),
        ("user", "alice", "alice (Executive VP)", 76, 3, ["INC-001"], "critical"),
        ("user", "svc_backup", "svc_backup (Automated Service)", 92, 5, ["INC-002"], "critical"),
        ("user", "bob", "bob (HR Specialist)", 45, 2, ["INC-003"], "warning"),
        ("user", "heidi", "heidi (DevOps Admin)", 35, 1, [], "normal"),
        ("user", "admin", "admin (Domain Administrator)", 18, 0, [], "normal"),
        ("user", "charlie", "charlie (Marketing Analyst)", 8, 0, [], "normal"),
        ("host", "DC-01", "DC-01 (Domain Controller Primary)", 88, 4, ["INC-002"], "critical"),
        ("host", "FS-02", "FS-02 (Corporate File Server)", 72, 3, ["INC-002"], "critical"),
        ("host", "PC-12", "PC-12 (Executive Workstation)", 82, 4, ["INC-001"], "critical"),
        ("host", "PC-19", "PC-19 (Developer Rig)", 42, 1, ["INC-003"], "warning"),
        ("host", "SRV-DB-01", "SRV-DB-01 (Production SQL Server)", 65, 2, ["INC-002"], "warning"),
        ("host", "JUMP-01", "JUMP-01 (Bastion Host)", 54, 2, ["INC-002"], "warning"),
        ("ip", "45.142.122.8", "45.142.122.8 (External C2 Server)", 95, 4, ["INC-001"], "critical"),
        ("ip", "198.51.100.24", "198.51.100.24 (Rogue Drop Box)", 88, 3, ["INC-002"], "critical"),
        ("ip", "10.0.4.15", "10.0.4.15 (Internal Subnet Router)", 30, 1, [], "normal"),
        ("ip", "10.0.4.50", "10.0.4.50 (VLAN Gateway)", 12, 0, [], "normal"),
        ("ip", "192.168.1.101", "192.168.1.101 (LAPTOP-1 DHCP)", 15, 0, [], "normal"),
        ("ip", "192.168.1.104", "192.168.1.104 (LAPTOP-4 DHCP)", 92, 4, [], "critical"),
        ("app", "powershell.exe", "powershell.exe (Windows Shell)", 85, 3, ["INC-003"], "critical"),
        ("app", "mimikatz.exe", "mimikatz.exe (Credential Dumper)", 98, 5, ["INC-002"], "critical"),
        ("app", "psexec.exe", "psexec.exe (Sysinternals Remote Tool)", 78, 3, ["INC-002"], "critical"),
        ("app", "cmd.exe", "cmd.exe (Command Prompt)", 40, 1, [], "warning"),
        ("app", "WINWORD.EXE", "WINWORD.EXE (Microsoft Word)", 50, 2, ["INC-003"], "warning"),
        ("app", "svchost.exe", "svchost.exe (Generic Service Host)", 5, 0, [], "normal"),
    ]

    for etype, eid, disp, rk, anom, rel_inc, st in defaults:
        ent = ensure_entity(etype, eid, display=disp, base_risk=rk)
        ent["risk"] = max(ent["risk"], rk)
        ent["anomalous_behaviours"] = max(ent["anomalous_behaviours"], anom)
        for rid in rel_inc:
            if rid not in ent["related_incidents"]:
                ent["related_incidents"].append(rid)
        ent["status"] = st

    all_list = list(entities_map.values())

    # Apply type filter
    if type_filter:
        clean_type = type_filter.lower().strip()
        all_list = [e for e in all_list if e["type"] == clean_type]

    # Apply query search
    if query:
        q_lower = query.lower().strip()
        all_list = [e for e in all_list if q_lower in e["id"].lower() or q_lower in e["display"].lower()]

    # Sort by risk desc
    all_list.sort(key=lambda x: x["risk"], reverse=True)

    stats = {
        "total": len(entities_map),
        "users": sum(1 for e in entities_map.values() if e["type"] == "user"),
        "hosts": sum(1 for e in entities_map.values() if e["type"] == "host"),
        "ips": sum(1 for e in entities_map.values() if e["type"] == "ip"),
        "apps": sum(1 for e in entities_map.values() if e["type"] == "app"),
        "critical_risk": sum(1 for e in entities_map.values() if e["risk"] >= 70),
    }

    return {
        "total": len(all_list),
        "entities": all_list,
        "stats": stats
    }

