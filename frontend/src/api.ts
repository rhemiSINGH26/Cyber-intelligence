// Real & Mock API layer for ThreatLens SOC Dashboard.
// Connects to FastAPI CTI Backend on /api with seamless fallback to mock data.
import { queryOptions } from "@tanstack/react-query";
import {
  alertsOverTime,
  buildEntity,
  graphs,
  incidents as mockIncidents,
  logs as mockLogs,
  metrics as mockMetrics,
  type EntityType,
  type LogRow,
  type Incident,
  type IncidentGraph,
  type Stage,
} from "@/data/mock";

export type DemoMode = "attack" | "clean";
const delay = (ms = 150) => new Promise((r) => setTimeout(r, ms));
let uploaded: LogRow[] = [];

export function safeIso(val: any): string {
  if (!val) return new Date().toISOString();
  try {
    const d = new Date(val);
    if (!isNaN(d.getTime())) return d.toISOString();
  } catch {}
  try {
    const today = new Date().toISOString().slice(0, 10);
    const d2 = new Date(`${today}T${val}Z`);
    if (!isNaN(d2.getTime())) return d2.toISOString();
  } catch {}
  return new Date().toISOString();
}

// Helper to map backend incident to ThreatLens shape
function mapBackendIncident(b: any): Incident {
  return {
    id: b.id,
    title: b.title,
    summary: b.explanation || b.title,
    risk_score: b.risk_score,
    severity: (["critical", "high", "medium", "low"].includes(b.severity?.toLowerCase()) ? b.severity.toLowerCase() : "medium") as any,
    confidence: b.confidence ?? 0.85,
    status: (["open", "investigating", "contained", "resolved"].includes(b.status) ? b.status : "open") as any,
    created_at: safeIso(b.first_seen),
    entities: {
      users: b.entities?.users || [],
      hosts: b.entities?.hosts || [],
      ips: b.entities?.ips || [],
      apps: b.entities?.apps || [],
    },
    stages: (b.stages || []).map((s: any, idx: number): Stage => {
      const validIsoTime = safeIso(s.time);
      return {
        id: `stage-${idx}-${s.stage}`,
        stage: s.stage,
        tactic: s.mitre_tactic || "Initial Access",
        mitre_tactic_id: s.mitre_tactic || "TA0001",
        technique_id: s.mitre_technique || "T1078",
        technique: s.technique_name || s.stage.replace(/_/g, " "),
        timestamp: validIsoTime,
        reason: s.reason || "Suspicious anomaly observed",
        evidence: (s.evidence || []).map((eid: string, eidx: number) => ({
          log_id: 1000 + eidx,
          timestamp: validIsoTime,
          source: s.stage,
          raw: `Evidence log #${eid}: ${s.reason}`,
        })),
      };
    }),
    why_flagged: {
      rule: b.stages?.[0]?.technique_name || "MITRE ATT&CK Multi-Stage Correlation",
      anomaly_score: b.stages?.[0]?.anomaly_score ? Number(b.stages[0].anomaly_score.toFixed(1)) : 2.5,
      features: [
        { name: "Kill Chain Progression", contribution: 0.92 },
        { name: "Outbound Exfiltration", contribution: 0.88 },
        { name: "Anomalous Login Geo/Hour", contribution: 0.78 },
        { name: "Entity Anomaly Z-Score", contribution: 0.84 },
      ],
    },
    recommendations: (b.recommendations || []).map((r: any) => ({
      action: r.action?.replace(/_/g, " ") || "Contain Target",
      target: r.target || "System",
      priority: (r.priority?.toLowerCase() || "high") as any,
      detail: r.description || "Actionable response playbook",
    })),
  };
}

// GET /incidents
export async function getIncidents(mode: DemoMode): Promise<Incident[]> {
  if (mode === "clean") return [];
  try {
    const res = await fetch("/api/incidents?page_size=100");
    if (res.ok) {
      const data = await res.json();
      if (data.items && data.items.length > 0) {
        return data.items.map(mapBackendIncident).sort((a: Incident, b: Incident) => b.risk_score - a.risk_score);
      }
    }
  } catch (e) {
    console.warn("Backend /api/incidents unavailable, falling back to mock:", e);
  }
  await delay();
  return [...mockIncidents].sort((a, b) => b.risk_score - a.risk_score);
}

// GET /incidents/{id}
export async function getIncident(id: string): Promise<Incident> {
  let targetId = id;
  if (id.startsWith("INC-00")) {
    try {
      const listRes = await fetch("/api/incidents?page_size=10");
      if (listRes.ok) {
        const listData = await listRes.json();
        const indexMap: Record<string, number> = { "INC-001": 0, "INC-002": 1, "INC-003": 2, "INC-004": 3 };
        const idx = indexMap[id];
        if (idx !== undefined && listData.items && listData.items[idx]) {
          return mapBackendIncident(listData.items[idx]);
        }
      }
    } catch {}
  }

  try {
    const res = await fetch(`/api/incidents/${targetId}`);
    if (res.ok) {
      const data = await res.json();
      return mapBackendIncident(data);
    }
  } catch (e) {
    console.warn(`Backend /api/incidents/${targetId} unavailable, falling back to mock:`, e);
  }
  await delay();
  const inc = mockIncidents.find((i) => i.id === id);
  if (!inc) {
    if (mockIncidents.length > 0) return mockIncidents[0];
    throw new Error(`Incident ${id} not found`);
  }
  return inc;
}

// GET /graph/{incident_id}
export async function getGraph(incidentId: string): Promise<IncidentGraph> {
  let targetId = incidentId;
  if (incidentId.startsWith("INC-00")) {
    try {
      const listRes = await fetch("/api/incidents?page_size=10");
      if (listRes.ok) {
        const listData = await listRes.json();
        const indexMap: Record<string, number> = { "INC-001": 0, "INC-002": 1, "INC-003": 2, "INC-004": 3 };
        const idx = indexMap[incidentId];
        if (idx !== undefined && listData.items && listData.items[idx]) {
          targetId = listData.items[idx].id;
        }
      }
    } catch {}
  }

  try {
    const res = await fetch(`/api/incidents/${targetId}/graph`);
    if (res.ok) {
      const data = await res.json();
      if (data.nodes && data.nodes.length > 0) {
        return {
          incident_id: targetId,
          nodes: data.nodes.map((n: any) => ({
            id: n.id,
            type: (["user", "host", "ip", "app", "file"].includes(n.node_type) ? n.node_type : "host") as any,
            label: n.label || n.id,
            suspicious: Boolean(n.is_suspicious),
          })),
          edges: data.edges.map((e: any, idx: number) => ({
            id: `edge-${idx}`,
            source: e.source,
            target: e.target,
            event: (["login", "access", "copy", "connect", "execute", "auth"].includes(e.edge_type) ? e.edge_type : "connect") as any,
            timestamp: e.timestamp || "",
            suspicious: Boolean(e.is_suspicious),
            order: e.metadata?.order ?? idx + 1,
          })),
        };
      }
    }
  } catch (e) {
    console.warn(`Backend graph for ${targetId} unavailable, falling back to mock:`, e);
  }
  await delay();
  const g = graphs.find((x) => x.incident_id === incidentId);
  if (!g) return graphs[0] || { incident_id: incidentId, nodes: [], edges: [] };
  return g;
}

// GET /logs?user=&ip=&from=&to=
export async function getLogs(mode: DemoMode, q: { user?: string; ip?: string; from?: string; to?: string } = {}): Promise<LogRow[]> {
  try {
    const params = new URLSearchParams();
    if (q.user) params.append("user", q.user);
    if (q.ip) params.append("ip", q.ip);
    params.append("page_size", "200");

    const res = await fetch(`/api/logs?${params.toString()}`);
    if (res.ok) {
      const data = await res.json();
      if (data.items && data.items.length > 0) {
        let rows: LogRow[] = data.items.map((l: any, i: number) => ({
          id: 5000 + i,
          timestamp: l.timestamp,
          user: l.user || "unknown",
          host: l.host || "unknown",
          ip: l.src_ip || l.dst_ip || "0.0.0.0",
          event_type: l.event_type || "telemetry",
          severity: l.incident_id ? "critical" : "info",
          source: l.app || l.file_path || "System",
          message: l.details || `${l.event_type} on ${l.host} by ${l.user || 'system'}`,
          incident_id: l.incident_id,
          stage: l.stage,
        }));
        if (mode === "clean") rows = rows.filter((r) => !r.incident_id);
        return [...uploaded, ...rows];
      }
    }
  } catch (e) {
    console.warn("Backend /api/logs unavailable, falling back to mock:", e);
  }

  await delay(200);
  let rows = [...uploaded, ...mockLogs];
  if (mode === "clean") rows = rows.filter((l) => !l.incident_id);
  if (q.user) rows = rows.filter((l) => l.user === q.user);
  if (q.ip) rows = rows.filter((l) => l.ip === q.ip);
  if (q.from) rows = rows.filter((l) => l.timestamp >= q.from!);
  if (q.to) rows = rows.filter((l) => l.timestamp <= q.to!);
  return rows;
}

// GET /entities/{type}/{id}
export async function getEntity(type: EntityType, id: string) {
  await delay();
  return buildEntity(type, id);
}

// GET /metrics
export async function getMetrics(mode: DemoMode) {
  const clean = mode === "clean";
  try {
    const [evalRes, dashRes] = await Promise.all([
      fetch("/api/metrics/evaluate"),
      fetch("/api/metrics/dashboard"),
    ]);

    if (evalRes.ok && dashRes.ok) {
      const evalData = await evalRes.json();
      const dashData = await dashRes.json();

      return {
        precision: clean ? 1.0 : evalData.precision,
        recall: clean ? 1.0 : evalData.recall,
        f1: clean ? 1.0 : evalData.f1_score,
        fpr: clean ? 0.0 : evalData.fp_rate,
        confusion: {
          tp: clean ? 0 : evalData.true_positives,
          fp: clean ? 0 : evalData.false_positives,
          fn: clean ? 0 : evalData.false_negatives,
          tn: 95000,
        },
        logs_ingested: dashData.total_logs + uploaded.length,
        alerts_raised: clean ? 0 : dashData.total_incidents,
        attacks_detected: clean ? 0 : evalData.true_positives,
        alerts_over_time: clean
          ? alertsOverTime.map((d) => ({ ...d, alerts: 0, attacks: 0 }))
          : alertsOverTime,
        severity_dist: clean
          ? []
          : [
              { name: "Critical", key: "critical", value: dashData.severity_distribution?.critical || 1 },
              { name: "High", key: "high", value: dashData.severity_distribution?.high || 4 },
              { name: "Medium", key: "medium", value: dashData.severity_distribution?.medium || 2 },
              { name: "Low", key: "low", value: dashData.severity_distribution?.low || 0 },
            ],
        mitre_coverage: dashData.mitre_coverage || [],
        comparison: clean
          ? [
              { scenario: "Routine admin patching", truth: "benign", detected: "benign", incident: null },
              { scenario: "Nightly backup sync (svc_backup)", truth: "benign", detected: "benign", incident: null },
              { scenario: "Forgotten password reset", truth: "benign", detected: "benign", incident: null },
              { scenario: "Quarterly finance data export", truth: "benign", detected: "benign", incident: null },
            ]
          : [
              { scenario: "Insider data theft via USB", truth: "attack", detected: "attack", incident: "INC-001" },
              { scenario: "External brute force & privilege escalation", truth: "attack", detected: "attack", incident: "INC-002" },
              { scenario: "Low-and-slow credential abuse", truth: "attack", detected: "attack", incident: "INC-003" },
              { scenario: "Service account compromise & DNS tunnel", truth: "attack", detected: "attack", incident: "INC-004" },
              { scenario: "Nightly backup sync (svc_backup)", truth: "benign", detected: "benign", incident: null },
              { scenario: "Forgotten password attempt from home IP", truth: "benign", detected: "benign", incident: null },
              { scenario: "Routine developer Git sync", truth: "benign", detected: "benign", incident: null },
              { scenario: "Finance payroll monthly batch", truth: "benign", detected: "benign", incident: null },
            ],
      };
    }
  } catch (e) {
    console.warn("Backend metrics unavailable, falling back to mock:", e);
  }

  await delay();
  const { tp, fp, fn, tn } = mockMetrics.confusion;
  const precision = tp / (tp + fp);
  const recall = tp / (tp + fn);
  return {
    ...mockMetrics,
    precision,
    recall,
    f1: (2 * precision * recall) / (precision + recall),
    fpr: fp / (fp + tn),
    logs_ingested: mockMetrics.logs_ingested + uploaded.length,
    alerts_raised: clean ? 0 : alertsOverTime.reduce((a, b) => a + b.alerts, 0),
    attacks_detected: clean ? 0 : mockIncidents.length,
    alerts_over_time: clean ? alertsOverTime.map((d) => ({ ...d, alerts: 0, attacks: 0 })) : alertsOverTime,
    severity_dist: clean
      ? []
      : [
          { name: "Critical", key: "critical", value: 1 },
          { name: "High", key: "high", value: 4 },
          { name: "Medium", key: "medium", value: 9 },
          { name: "Low", key: "low", value: 17 },
        ],
  };
}

// POST /upload
export async function uploadLogs(rows: Partial<LogRow>[]) {
  await delay(300);
  const base = Date.now() % 100000 + 50000;
  const parsed: LogRow[] = rows.map((r, i) => ({
    id: Number(r.id) || base + i,
    timestamp: String(r.timestamp ?? new Date().toISOString()),
    user: String(r.user ?? "unknown"),
    host: String(r.host ?? "unknown"),
    ip: String(r.ip ?? "0.0.0.0"),
    event_type: String(r.event_type ?? "upload"),
    severity: (["critical", "high", "medium", "low", "info"].includes(String(r.severity)) ? r.severity : "info") as LogRow["severity"],
    source: String(r.source ?? "Upload"),
    message: String(r.message ?? JSON.stringify(r)),
  }));
  uploaded = [...parsed, ...uploaded];
  return { inserted: parsed.length };
}

export const qk = {
  incidents: (mode: DemoMode) => queryOptions({ queryKey: ["incidents", mode], queryFn: () => getIncidents(mode) }),
  incident: (id: string) => queryOptions({ queryKey: ["incident", id], queryFn: () => getIncident(id) }),
  graph: (id: string) => queryOptions({ queryKey: ["graph", id], queryFn: () => getGraph(id) }),
  logs: (mode: DemoMode, q: Parameters<typeof getLogs>[1] = {}) =>
    queryOptions({ queryKey: ["logs", mode, q], queryFn: () => getLogs(mode, q) }),
  entity: (type: EntityType, id: string) => queryOptions({ queryKey: ["entity", type, id], queryFn: () => getEntity(type, id) }),
  entitiesList: (typeFilter?: string, query?: string) =>
    queryOptions({ queryKey: ["entities-list", typeFilter, query], queryFn: () => getAllEntities(typeFilter, query) }),
  metrics: (mode: DemoMode) => queryOptions({ queryKey: ["metrics", mode], queryFn: () => getMetrics(mode) }),
  fleet: () => queryOptions({ queryKey: ["fleet"], queryFn: () => getFleetState(), refetchInterval: 3000 }),
  fleetLogs: (nodeId?: string) =>
    queryOptions({ queryKey: ["fleet-logs", nodeId], queryFn: () => (nodeId ? getNodeLogs(nodeId) : getAllFleetLogs()), refetchInterval: 2500 }),
};

// POST /api/chat
export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface CopilotResponse {
  answer: string;
  incident_id?: string;
  model: string;
  ai_powered: boolean;
}

export async function askCopilot(
  query: string,
  incidentId?: string,
  history: ChatMessage[] = []
): Promise<CopilotResponse> {
  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query,
        incident_id: incidentId,
        history,
      }),
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    console.warn("Failed to reach /api/chat:", e);
  }
  return {
    answer:
      "ThreatLens Copilot: Detected attacks include multi-stage credential abuse, lateral movement across workstations & servers, and outbound data exfiltration. Check the Incidents tab for full kill-chain breakdowns.",
    model: "offline-fallback",
    ai_powered: false,
  };
}

// ---------------------------------------------------------
// FLEET & NODE TELEMETRY API
// ---------------------------------------------------------

export interface FleetNode {
  id: string;
  name: string;
  user: string;
  os: string;
  ip: string;
  status: "normal" | "warning" | "compromised" | "waiting" | "offline";
  risk: number;
  events: number;
  signals: number;
  last_seen: number;
  online: boolean;
  age_seconds: number | null;
  logs_count: number;
  is_default?: boolean;
}

export interface FleetState {
  timestamp: number;
  nodes: FleetNode[];
  stats: {
    total: number;
    online: number;
    offline: number;
    elevated_risk: number;
  };
}

export interface FleetLog {
  id: string;
  node_id: string;
  timestamp: string;
  level: "INFO" | "WARN" | "CRIT";
  message: string;
  event_type: string;
  details?: Record<string, any>;
}

export async function getFleetState(): Promise<FleetState> {
  try {
    const res = await fetch("/api/fleet");
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    console.warn("Failed to reach /api/fleet:", e);
  }
  // Fallback state
  return {
    timestamp: Date.now() / 1000,
    nodes: [
      { id: "LAPTOP-1", name: "Executive Laptop (Alice)", user: "alice", os: "Windows 11 Pro", ip: "192.168.1.101", status: "normal", risk: 15, events: 24, signals: 0, last_seen: Date.now() / 1000, online: true, age_seconds: 2, logs_count: 5, is_default: true },
      { id: "LAPTOP-2", name: "SecOps Workstation (Bob)", user: "bob", os: "Ubuntu 22.04 LTS", ip: "192.168.1.102", status: "warning", risk: 68, events: 48, signals: 2, last_seen: Date.now() / 1000, online: true, age_seconds: 1, logs_count: 8, is_default: true },
      { id: "LAPTOP-3", name: "Finance MacBook (Charlie)", user: "charlie", os: "macOS Sonoma 14", ip: "192.168.1.103", status: "normal", risk: 8, events: 16, signals: 0, last_seen: Date.now() / 1000, online: true, age_seconds: 4, logs_count: 3, is_default: true },
      { id: "LAPTOP-4", name: "DevOps Node (Heidi)", user: "heidi", os: "Windows 10 Enterprise", ip: "192.168.1.104", status: "compromised", risk: 92, events: 82, signals: 4, last_seen: Date.now() / 1000, online: true, age_seconds: 1, logs_count: 14, is_default: true },
    ],
    stats: { total: 4, online: 4, offline: 0, elevated_risk: 2 }
  };
}

export async function addFleetNode(data: { id: string; name?: string; os?: string; ip?: string; user?: string }): Promise<FleetNode> {
  const res = await fetch("/api/fleet/nodes", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Failed to add node" }));
    throw new Error(err.detail || "Failed to add node");
  }
  const result = await res.json();
  return result.node;
}

export async function deleteFleetNode(nodeId: string): Promise<boolean> {
  const res = await fetch(`/api/fleet/nodes/${encodeURIComponent(nodeId)}`, {
    method: "DELETE",
  });
  return res.ok;
}

export async function getNodeLogs(nodeId: string, limit = 100): Promise<FleetLog[]> {
  try {
    const res = await fetch(`/api/fleet/nodes/${encodeURIComponent(nodeId)}/logs?limit=${limit}`);
    if (res.ok) {
      const data = await res.json();
      return data.logs || [];
    }
  } catch (e) {
    console.warn(`Failed to fetch logs for ${nodeId}:`, e);
  }
  return [];
}

export async function getAllFleetLogs(limit = 150): Promise<FleetLog[]> {
  try {
    const res = await fetch(`/api/fleet/logs?limit=${limit}`);
    if (res.ok) {
      const data = await res.json();
      return data.logs || [];
    }
  } catch (e) {
    console.warn("Failed to fetch fleet logs:", e);
  }
  return [];
}

export async function simulateFleetEvent(nodeId: string, eventType: string): Promise<any> {
  const res = await fetch(`/api/fleet/nodes/${encodeURIComponent(nodeId)}/simulate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event_type: eventType }),
  });
  if (!res.ok) {
    throw new Error("Simulation failed");
  }
  return await res.json();
}

// ---------------------------------------------------------
// ALL ENTITIES DIRECTORY API
// ---------------------------------------------------------

export interface EntitySummary {
  type: EntityType;
  id: string;
  display: string;
  risk: number;
  anomalous_behaviours: number;
  total_behaviours: number;
  related_incidents: string[];
  event_count: number;
  last_seen: string;
  status: "critical" | "warning" | "normal";
}

export interface EntitiesDirectory {
  total: number;
  entities: EntitySummary[];
  stats: {
    total: number;
    users: number;
    hosts: number;
    ips: number;
    apps: number;
    critical_risk: number;
  };
}

export async function getAllEntities(typeFilter?: string, query?: string): Promise<EntitiesDirectory> {
  try {
    const params = new URLSearchParams();
    if (typeFilter && typeFilter !== "all") params.append("type_filter", typeFilter);
    if (query) params.append("query", query);

    const res = await fetch(`/api/entities?${params.toString()}`);
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    console.warn("Failed to reach /api/entities:", e);
  }

  // Fallback directory based on mock data
  const mockList: EntitySummary[] = [
    { type: "user", id: "sjones", display: "sjones (Finance Lead)", risk: 84, anomalous_behaviours: 4, total_behaviours: 5, related_incidents: ["INC-001"], event_count: 52, last_seen: new Date().toISOString(), status: "critical" },
    { type: "user", id: "alice", display: "alice (Executive VP)", risk: 76, anomalous_behaviours: 3, total_behaviours: 5, related_incidents: ["INC-001"], event_count: 38, last_seen: new Date().toISOString(), status: "critical" },
    { type: "user", id: "svc_backup", display: "svc_backup (Automated Service)", risk: 92, anomalous_behaviours: 5, total_behaviours: 5, related_incidents: ["INC-002"], event_count: 94, last_seen: new Date().toISOString(), status: "critical" },
    { type: "user", id: "bob", display: "bob (HR Specialist)", risk: 45, anomalous_behaviours: 2, total_behaviours: 5, related_incidents: ["INC-003"], event_count: 22, last_seen: new Date().toISOString(), status: "warning" },
    { type: "user", id: "heidi", display: "heidi (DevOps Admin)", risk: 35, anomalous_behaviours: 1, total_behaviours: 5, related_incidents: [], event_count: 14, last_seen: new Date().toISOString(), status: "normal" },
    { type: "host", id: "DC-01", display: "DC-01 (Domain Controller Primary)", risk: 88, anomalous_behaviours: 4, total_behaviours: 5, related_incidents: ["INC-002"], event_count: 112, last_seen: new Date().toISOString(), status: "critical" },
    { type: "host", id: "FS-02", display: "FS-02 (Corporate File Server)", risk: 72, anomalous_behaviours: 3, total_behaviours: 5, related_incidents: ["INC-002"], event_count: 67, last_seen: new Date().toISOString(), status: "critical" },
    { type: "host", id: "PC-12", display: "PC-12 (Executive Workstation)", risk: 82, anomalous_behaviours: 4, total_behaviours: 5, related_incidents: ["INC-001"], event_count: 48, last_seen: new Date().toISOString(), status: "critical" },
    { type: "host", id: "PC-19", display: "PC-19 (Developer Rig)", risk: 42, anomalous_behaviours: 1, total_behaviours: 5, related_incidents: ["INC-003"], event_count: 31, last_seen: new Date().toISOString(), status: "warning" },
    { type: "host", id: "LAPTOP-1", display: "LAPTOP-1 (Alice Laptop)", risk: 15, anomalous_behaviours: 0, total_behaviours: 5, related_incidents: [], event_count: 24, last_seen: new Date().toISOString(), status: "normal" },
    { type: "host", id: "LAPTOP-4", display: "LAPTOP-4 (Heidi DevOps Node)", risk: 92, anomalous_behaviours: 4, total_behaviours: 5, related_incidents: ["INC-001"], event_count: 82, last_seen: new Date().toISOString(), status: "critical" },
    { type: "ip", id: "45.142.122.8", display: "45.142.122.8 (External C2 Server)", risk: 95, anomalous_behaviours: 4, total_behaviours: 5, related_incidents: ["INC-001"], event_count: 40, last_seen: new Date().toISOString(), status: "critical" },
    { type: "ip", id: "198.51.100.24", display: "198.51.100.24 (Rogue Drop Box)", risk: 88, anomalous_behaviours: 3, total_behaviours: 5, related_incidents: ["INC-002"], event_count: 28, last_seen: new Date().toISOString(), status: "critical" },
    { type: "ip", id: "10.0.4.15", display: "10.0.4.15 (Internal Subnet Router)", risk: 30, anomalous_behaviours: 1, total_behaviours: 5, related_incidents: [], event_count: 75, last_seen: new Date().toISOString(), status: "normal" },
    { type: "app", id: "powershell.exe", display: "powershell.exe (Windows Shell)", risk: 85, anomalous_behaviours: 3, total_behaviours: 5, related_incidents: ["INC-003"], event_count: 60, last_seen: new Date().toISOString(), status: "critical" },
    { type: "app", id: "mimikatz.exe", display: "mimikatz.exe (Credential Dumper)", risk: 98, anomalous_behaviours: 5, total_behaviours: 5, related_incidents: ["INC-002"], event_count: 18, last_seen: new Date().toISOString(), status: "critical" },
    { type: "app", id: "psexec.exe", display: "psexec.exe (Sysinternals Remote Tool)", risk: 78, anomalous_behaviours: 3, total_behaviours: 5, related_incidents: ["INC-002"], event_count: 25, last_seen: new Date().toISOString(), status: "critical" },
  ];

  let filtered = mockList;
  if (typeFilter && typeFilter !== "all") filtered = filtered.filter(e => e.type === typeFilter);
  if (query) filtered = filtered.filter(e => e.id.toLowerCase().includes(query.toLowerCase()) || e.display.toLowerCase().includes(query.toLowerCase()));

  return {
    total: filtered.length,
    entities: filtered,
    stats: {
      total: mockList.length,
      users: mockList.filter(e => e.type === "user").length,
      hosts: mockList.filter(e => e.type === "host").length,
      ips: mockList.filter(e => e.type === "ip").length,
      apps: mockList.filter(e => e.type === "app").length,
      critical_risk: mockList.filter(e => e.risk >= 70).length,
    }
  };
}

