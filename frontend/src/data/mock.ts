// Mock data shaped like the ThreatLens REST API. Swap for real endpoints in src/api.ts.

export type Severity = "critical" | "high" | "medium" | "low";
export type LogSeverity = Severity | "info";
export type EntityType = "user" | "host" | "ip" | "app";
export type KillChainKey =
  | "initial_access"
  | "execution"
  | "privilege_escalation"
  | "lateral_movement"
  | "collection"
  | "exfiltration";

export const KILL_CHAIN: { key: KillChainKey; label: string; mitre: string }[] = [
  { key: "initial_access", label: "Initial Access", mitre: "TA0001" },
  { key: "execution", label: "Execution", mitre: "TA0002" },
  { key: "privilege_escalation", label: "Privilege Escalation", mitre: "TA0004" },
  { key: "lateral_movement", label: "Lateral Movement", mitre: "TA0008" },
  { key: "collection", label: "Collection", mitre: "TA0009" },
  { key: "exfiltration", label: "Exfiltration", mitre: "TA0010" },
];

export interface Evidence {
  log_id: number;
  timestamp: string;
  source: string;
  raw: string;
}

export interface Stage {
  id: string;
  stage: KillChainKey;
  tactic: string;
  mitre_tactic_id: string;
  technique_id: string;
  technique: string;
  timestamp: string;
  reason: string;
  evidence: Evidence[];
}

export interface Incident {
  id: string;
  title: string;
  summary: string;
  risk_score: number;
  severity: Severity;
  confidence: number;
  status: "open" | "investigating" | "contained" | "resolved";
  created_at: string;
  entities: { users: string[]; hosts: string[]; ips: string[]; apps: string[] };
  stages: Stage[];
  why_flagged: {
    rule: string;
    anomaly_score: number;
    features: { name: string; contribution: number }[];
  };
  recommendations: { action: string; target: string; priority: Severity; detail: string }[];
}

export interface LogRow {
  id: number;
  timestamp: string;
  user: string;
  host: string;
  ip: string;
  event_type: string;
  severity: LogSeverity;
  source: string;
  message: string;
  incident_id?: string;
  stage?: KillChainKey;
}

export type GraphNodeType = "user" | "host" | "ip" | "app" | "file";
export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  suspicious: boolean;
}
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  event: "login" | "access" | "copy" | "connect" | "execute" | "auth";
  timestamp: string;
  suspicious: boolean;
  order?: number;
}
export interface IncidentGraph {
  incident_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// ---------- Incidents ----------

export const incidents: Incident[] = [
  {
    id: "INC-001",
    title: "Data exfiltration via USB after foreign login",
    summary:
      "alice authenticated from a Tor exit node in a never-seen country, bulk-read 40 unseen files on PC-12 and copied them to a USB mass-storage device within 26 minutes.",
    risk_score: 92,
    severity: "critical",
    confidence: 0.94,
    status: "open",
    created_at: "2026-10-06T02:40:51Z",
    entities: { users: ["alice"], hosts: ["PC-12"], ips: ["185.220.101.45"], apps: ["explorer.exe", "VPN Gateway"] },
    stages: [
      {
        id: "INC-001-S1",
        stage: "initial_access",
        tactic: "Initial Access",
        mitre_tactic_id: "TA0001",
        technique_id: "T1078",
        technique: "Valid Accounts",
        timestamp: "2026-10-06T02:14:07Z",
        reason: "Login from new country (RO) — user baseline is IN only; source IP is a known Tor exit node.",
        evidence: [
          {
            log_id: 1021,
            timestamp: "2026-10-06T02:14:07Z",
            source: "VPN Gateway",
            raw: 'auth success user=alice src=185.220.101.45 geo=RO asn=AS208294 mfa=push_approved device=unknown',
          },
        ],
      },
      {
        id: "INC-001-S2",
        stage: "collection",
        tactic: "Collection",
        mitre_tactic_id: "TA0009",
        technique_id: "T1005",
        technique: "Data from Local System",
        timestamp: "2026-10-06T02:31:44Z",
        reason: "Accessed 40 unseen files in 6 min (baseline: 3 new files/day) across Finance and HR shares.",
        evidence: [
          {
            log_id: 1088,
            timestamp: "2026-10-06T02:31:44Z",
            source: "Sysmon/PC-12",
            raw: 'EventID=11 user=alice host=PC-12 path="\\\\fs01\\finance\\Q3\\*" files_read=40 first_seen=40 bytes=812MB',
          },
        ],
      },
      {
        id: "INC-001-S3",
        stage: "exfiltration",
        tactic: "Exfiltration",
        mitre_tactic_id: "TA0010",
        technique_id: "T1052.001",
        technique: "Exfiltration over USB",
        timestamp: "2026-10-06T02:40:12Z",
        reason: "USB device copy of 812MB to a mass-storage device never seen on PC-12.",
        evidence: [
          {
            log_id: 1102,
            timestamp: "2026-10-06T02:40:12Z",
            source: "EDR/PC-12",
            raw: 'usb_write user=alice host=PC-12 vid=0781 pid=5583 serial=4C530001 bytes=812MB files=40 device_first_seen=true',
          },
        ],
      },
    ],
    why_flagged: {
      rule: "TL-EXFIL-004: Off-hours foreign login followed by bulk read + removable media write within 60m",
      anomaly_score: 0.97,
      features: [
        { name: "New login country", contribution: 0.31 },
        { name: "Files accessed vs baseline", contribution: 0.24 },
        { name: "USB write volume", contribution: 0.21 },
        { name: "Off-hours activity (02:00)", contribution: 0.13 },
        { name: "Tor exit node IP", contribution: 0.08 },
        { name: "Unknown device", contribution: 0.03 },
      ],
    },
    recommendations: [
      { action: "Disable account", target: "alice", priority: "critical", detail: "Revoke sessions and force password + MFA reset." },
      { action: "Isolate host", target: "PC-12", priority: "critical", detail: "Network-isolate via EDR and preserve memory image." },
      { action: "Block IP", target: "185.220.101.45", priority: "high", detail: "Add to perimeter and VPN deny lists." },
    ],
  },
  {
    id: "INC-002",
    title: "Low-and-slow credential abuse with lateral movement",
    summary:
      "svc_backup credentials were sprayed at a rate below lockout thresholds over 3 days, then used to escalate on JUMP-01 and move laterally to SRV-DB-01 and FS-02.",
    risk_score: 78,
    severity: "high",
    confidence: 0.81,
    status: "investigating",
    created_at: "2026-10-04T22:09:30Z",
    entities: { users: ["svc_backup"], hosts: ["JUMP-01", "SRV-DB-01", "FS-02"], ips: ["45.153.160.2", "10.0.4.21"], apps: ["RDP", "PsExec"] },
    stages: [
      {
        id: "INC-002-S1",
        stage: "initial_access",
        tactic: "Initial Access",
        mitre_tactic_id: "TA0001",
        technique_id: "T1110.003",
        technique: "Password Spraying",
        timestamp: "2026-10-02T03:02:11Z",
        reason: "1 failed auth every ~47 min for 3 days (below lockout of 5/15m) from a single external ASN, then success.",
        evidence: [
          { log_id: 1005, timestamp: "2026-10-02T03:02:11Z", source: "AD/DC-01", raw: "EventID=4625 user=svc_backup src=45.153.160.2 logon_type=10 status=0xC000006A" },
          { log_id: 1131, timestamp: "2026-10-04T21:48:02Z", source: "AD/DC-01", raw: "EventID=4624 user=svc_backup src=45.153.160.2 logon_type=10 host=JUMP-01" },
        ],
      },
      {
        id: "INC-002-S2",
        stage: "privilege_escalation",
        tactic: "Privilege Escalation",
        mitre_tactic_id: "TA0004",
        technique_id: "T1078.002",
        technique: "Domain Accounts",
        timestamp: "2026-10-04T21:55:40Z",
        reason: "Service account used interactively and added itself to local Administrators — never seen in 180-day baseline.",
        evidence: [
          { log_id: 1140, timestamp: "2026-10-04T21:55:40Z", source: "Windows/JUMP-01", raw: "EventID=4732 member=svc_backup group=Administrators host=JUMP-01 caller=svc_backup" },
        ],
      },
      {
        id: "INC-002-S3",
        stage: "lateral_movement",
        tactic: "Lateral Movement",
        mitre_tactic_id: "TA0008",
        technique_id: "T1021.002",
        technique: "SMB/Admin Shares (PsExec)",
        timestamp: "2026-10-04T22:09:30Z",
        reason: "PsExec service created on 2 servers from JUMP-01 within 4 min; svc_backup normally only talks to BACKUP-01.",
        evidence: [
          { log_id: 1177, timestamp: "2026-10-04T22:07:12Z", source: "Windows/SRV-DB-01", raw: "EventID=7045 service=PSEXESVC user=svc_backup src=10.0.4.21 host=SRV-DB-01" },
          { log_id: 1178, timestamp: "2026-10-04T22:09:30Z", source: "Windows/FS-02", raw: "EventID=7045 service=PSEXESVC user=svc_backup src=10.0.4.21 host=FS-02" },
        ],
      },
    ],
    why_flagged: {
      rule: "TL-CRED-011: Sub-threshold auth failures (>40 / 72h) followed by success + new admin group membership",
      anomaly_score: 0.84,
      features: [
        { name: "Failed-auth cadence (72h)", contribution: 0.29 },
        { name: "Service acct interactive logon", contribution: 0.23 },
        { name: "New admin group membership", contribution: 0.19 },
        { name: "New host fan-out", contribution: 0.17 },
        { name: "External ASN reputation", contribution: 0.12 },
      ],
    },
    recommendations: [
      { action: "Disable account", target: "svc_backup", priority: "critical", detail: "Rotate credentials; move to gMSA." },
      { action: "Isolate host", target: "JUMP-01", priority: "high", detail: "Contain pivot host and review RDP sessions." },
      { action: "Block IP", target: "45.153.160.2", priority: "high", detail: "Block at firewall; hunt for same ASN." },
      { action: "Review", target: "SRV-DB-01, FS-02", priority: "medium", detail: "Remove PSEXESVC and audit data access." },
    ],
  },
  {
    id: "INC-003",
    title: "Phishing macro spawned encoded PowerShell",
    summary:
      "bob opened a macro-enabled invoice from email; WINWORD spawned an encoded PowerShell beacon to a newly registered domain. Blocked at proxy before payload download.",
    risk_score: 56,
    severity: "medium",
    confidence: 0.67,
    status: "contained",
    created_at: "2026-10-05T10:22:18Z",
    entities: { users: ["bob"], hosts: ["LAPTOP-07"], ips: ["91.92.240.77"], apps: ["WINWORD.EXE", "powershell.exe", "Outlook"] },
    stages: [
      {
        id: "INC-003-S1",
        stage: "initial_access",
        tactic: "Initial Access",
        mitre_tactic_id: "TA0001",
        technique_id: "T1566.001",
        technique: "Spearphishing Attachment",
        timestamp: "2026-10-05T10:19:03Z",
        reason: "Macro-enabled .docm from first-time external sender opened within 2 min of delivery.",
        evidence: [
          { log_id: 1201, timestamp: "2026-10-05T10:19:03Z", source: "M365/Defender", raw: 'mail_attachment_open user=bob file="Invoice_8812.docm" sender=billing@inv0ice-hub.top first_contact=true' },
        ],
      },
      {
        id: "INC-003-S2",
        stage: "execution",
        tactic: "Execution",
        mitre_tactic_id: "TA0002",
        technique_id: "T1059.001",
        technique: "PowerShell",
        timestamp: "2026-10-05T10:22:18Z",
        reason: "WINWORD.EXE spawned powershell -enc with outbound connection to a domain registered 2 days ago.",
        evidence: [
          { log_id: 1205, timestamp: "2026-10-05T10:22:18Z", source: "Sysmon/LAPTOP-07", raw: "EventID=1 parent=WINWORD.EXE image=powershell.exe cmd=\"-nop -w hidden -enc SQBFAFgA...\" user=bob" },
          { log_id: 1206, timestamp: "2026-10-05T10:22:20Z", source: "Proxy", raw: "BLOCKED dst=91.92.240.77 host=cdn-upd8.top category=newly_registered user=bob" },
        ],
      },
    ],
    why_flagged: {
      rule: "TL-EXEC-002: Office process spawning script interpreter with encoded command",
      anomaly_score: 0.71,
      features: [
        { name: "Office → PowerShell parent chain", contribution: 0.38 },
        { name: "Encoded command line", contribution: 0.24 },
        { name: "Newly registered domain", contribution: 0.2 },
        { name: "First-contact sender", contribution: 0.18 },
      ],
    },
    recommendations: [
      { action: "Isolate host", target: "LAPTOP-07", priority: "medium", detail: "Run full EDR scan before release." },
      { action: "Block IP", target: "91.92.240.77", priority: "medium", detail: "Block domain cdn-upd8.top and sender domain." },
      { action: "Reset password", target: "bob", priority: "low", detail: "Precautionary reset + phishing awareness." },
    ],
  },
];

// ---------- Graphs ----------

export const graphs: IncidentGraph[] = [
  {
    incident_id: "INC-001",
    nodes: [
      { id: "ip:185.220.101.45", type: "ip", label: "185.220.101.45", suspicious: true },
      { id: "app:VPN Gateway", type: "app", label: "VPN Gateway", suspicious: false },
      { id: "user:alice", type: "user", label: "alice", suspicious: true },
      { id: "host:PC-12", type: "host", label: "PC-12", suspicious: true },
      { id: "file:finance", type: "file", label: "\\\\fs01\\finance\\Q3 (40 files)", suspicious: true },
      { id: "file:usb", type: "file", label: "USB 4C530001", suspicious: true },
      { id: "host:fs01", type: "host", label: "fs01", suspicious: false },
      { id: "app:outlook", type: "app", label: "Outlook", suspicious: false },
    ],
    edges: [
      { id: "e1", source: "ip:185.220.101.45", target: "app:VPN Gateway", event: "connect", timestamp: "2026-10-06T02:13:58Z", suspicious: true, order: 1 },
      { id: "e2", source: "app:VPN Gateway", target: "user:alice", event: "login", timestamp: "2026-10-06T02:14:07Z", suspicious: true, order: 2 },
      { id: "e3", source: "user:alice", target: "host:PC-12", event: "login", timestamp: "2026-10-06T02:16:30Z", suspicious: true, order: 3 },
      { id: "e4", source: "host:PC-12", target: "file:finance", event: "access", timestamp: "2026-10-06T02:31:44Z", suspicious: true, order: 4 },
      { id: "e5", source: "file:finance", target: "file:usb", event: "copy", timestamp: "2026-10-06T02:40:12Z", suspicious: true, order: 5 },
      { id: "e6", source: "host:fs01", target: "file:finance", event: "access", timestamp: "2026-10-05T14:02:00Z", suspicious: false },
      { id: "e7", source: "user:alice", target: "app:outlook", event: "login", timestamp: "2026-10-05T09:01:00Z", suspicious: false },
    ],
  },
  {
    incident_id: "INC-002",
    nodes: [
      { id: "ip:45.153.160.2", type: "ip", label: "45.153.160.2", suspicious: true },
      { id: "user:svc_backup", type: "user", label: "svc_backup", suspicious: true },
      { id: "host:DC-01", type: "host", label: "DC-01", suspicious: false },
      { id: "host:JUMP-01", type: "host", label: "JUMP-01", suspicious: true },
      { id: "app:PsExec", type: "app", label: "PsExec", suspicious: true },
      { id: "host:SRV-DB-01", type: "host", label: "SRV-DB-01", suspicious: true },
      { id: "host:FS-02", type: "host", label: "FS-02", suspicious: true },
      { id: "host:BACKUP-01", type: "host", label: "BACKUP-01", suspicious: false },
    ],
    edges: [
      { id: "e1", source: "ip:45.153.160.2", target: "host:DC-01", event: "auth", timestamp: "2026-10-02T03:02:11Z", suspicious: true, order: 1 },
      { id: "e2", source: "host:DC-01", target: "user:svc_backup", event: "login", timestamp: "2026-10-04T21:48:02Z", suspicious: true, order: 2 },
      { id: "e3", source: "user:svc_backup", target: "host:JUMP-01", event: "login", timestamp: "2026-10-04T21:48:09Z", suspicious: true, order: 3 },
      { id: "e4", source: "host:JUMP-01", target: "app:PsExec", event: "execute", timestamp: "2026-10-04T22:06:55Z", suspicious: true, order: 4 },
      { id: "e5", source: "app:PsExec", target: "host:SRV-DB-01", event: "connect", timestamp: "2026-10-04T22:07:12Z", suspicious: true, order: 5 },
      { id: "e6", source: "app:PsExec", target: "host:FS-02", event: "connect", timestamp: "2026-10-04T22:09:30Z", suspicious: true, order: 6 },
      { id: "e7", source: "user:svc_backup", target: "host:BACKUP-01", event: "login", timestamp: "2026-10-03T01:00:00Z", suspicious: false },
    ],
  },
  {
    incident_id: "INC-003",
    nodes: [
      { id: "app:Outlook", type: "app", label: "Outlook", suspicious: false },
      { id: "user:bob", type: "user", label: "bob", suspicious: true },
      { id: "file:docm", type: "file", label: "Invoice_8812.docm", suspicious: true },
      { id: "app:WINWORD.EXE", type: "app", label: "WINWORD.EXE", suspicious: true },
      { id: "app:powershell.exe", type: "app", label: "powershell.exe", suspicious: true },
      { id: "host:LAPTOP-07", type: "host", label: "LAPTOP-07", suspicious: true },
      { id: "ip:91.92.240.77", type: "ip", label: "91.92.240.77", suspicious: true },
    ],
    edges: [
      { id: "e1", source: "app:Outlook", target: "file:docm", event: "access", timestamp: "2026-10-05T10:17:40Z", suspicious: true, order: 1 },
      { id: "e2", source: "user:bob", target: "file:docm", event: "access", timestamp: "2026-10-05T10:19:03Z", suspicious: true, order: 2 },
      { id: "e3", source: "file:docm", target: "app:WINWORD.EXE", event: "execute", timestamp: "2026-10-05T10:19:05Z", suspicious: true, order: 3 },
      { id: "e4", source: "app:WINWORD.EXE", target: "app:powershell.exe", event: "execute", timestamp: "2026-10-05T10:22:18Z", suspicious: true, order: 4 },
      { id: "e5", source: "app:powershell.exe", target: "ip:91.92.240.77", event: "connect", timestamp: "2026-10-05T10:22:20Z", suspicious: true, order: 5 },
      { id: "e6", source: "user:bob", target: "host:LAPTOP-07", event: "login", timestamp: "2026-10-05T08:58:00Z", suspicious: false },
    ],
  },
];

// ---------- Logs ----------

function rng(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const USERS: { user: string; host: string; ip: string }[] = [
  { user: "alice", host: "PC-12", ip: "10.0.1.12" },
  { user: "bob", host: "LAPTOP-07", ip: "10.0.1.37" },
  { user: "carol", host: "PC-03", ip: "10.0.1.3" },
  { user: "dave", host: "PC-19", ip: "10.0.1.19" },
  { user: "erin", host: "MAC-02", ip: "10.0.2.2" },
  { user: "frank", host: "PC-22", ip: "10.0.1.22" },
  { user: "grace", host: "LAPTOP-11", ip: "10.0.2.11" },
  { user: "heidi", host: "PC-08", ip: "10.0.1.8" },
  { user: "svc_backup", host: "BACKUP-01", ip: "10.0.4.5" },
  { user: "ivan", host: "SRV-DB-01", ip: "10.0.4.30" },
];
const BENIGN: { type: string; source: string; msg: (u: string, h: string) => string; sev: LogSeverity }[] = [
  { type: "login", source: "AD/DC-01", msg: (u, h) => `EventID=4624 user=${u} host=${h} logon_type=2 status=success`, sev: "info" },
  { type: "logout", source: "AD/DC-01", msg: (u, h) => `EventID=4634 user=${u} host=${h}`, sev: "info" },
  { type: "file_access", source: "FileServer/fs01", msg: (u) => `read user=${u} path="\\\\fs01\\shared\\team\\notes.docx"`, sev: "info" },
  { type: "process_start", source: "Sysmon", msg: (u, h) => `EventID=1 image=chrome.exe user=${u} host=${h}`, sev: "info" },
  { type: "network_connect", source: "Firewall", msg: (u) => `allow tcp/443 user=${u} dst=outlook.office365.com`, sev: "info" },
  { type: "dns_query", source: "DNS", msg: (_u, h) => `query host=${h} name=teams.microsoft.com A`, sev: "info" },
  { type: "auth_failure", source: "AD/DC-01", msg: (u, h) => `EventID=4625 user=${u} host=${h} reason=bad_password`, sev: "low" },
  { type: "privilege_use", source: "Windows", msg: (u, h) => `EventID=4673 user=${u} host=${h} privilege=SeBackupPrivilege`, sev: "low" },
  { type: "usb_insert", source: "EDR", msg: (u, h) => `usb_mount user=${u} host=${h} device=corp_issued_kb`, sev: "info" },
];

function incidentLogs(): LogRow[] {
  const out: LogRow[] = [];
  for (const inc of incidents) {
    for (const s of inc.stages) {
      for (const e of s.evidence) {
        const user = inc.entities.users[0] ?? "";
        const host = e.raw.match(/host=([\w-]+)/)?.[1] ?? inc.entities.hosts[0] ?? "";
        const ip = e.raw.match(/(?:src|dst)=([\d.]+)/)?.[1] ?? inc.entities.ips[0] ?? "";
        out.push({
          id: e.log_id,
          timestamp: e.timestamp,
          user,
          host,
          ip,
          event_type: s.stage === "exfiltration" ? "usb_write" : s.stage === "collection" ? "file_access" : s.stage === "lateral_movement" ? "service_install" : s.stage === "execution" ? "process_start" : "login",
          severity: inc.severity,
          source: e.source,
          message: e.raw,
          incident_id: inc.id,
          stage: s.stage,
        });
      }
    }
  }
  return out;
}

function buildLogs(): LogRow[] {
  const r = rng(42);
  const attack = incidentLogs();
  const used = new Set(attack.map((l) => l.id));
  const rows: LogRow[] = [...attack];
  const start = Date.parse("2026-10-01T00:00:00Z");
  let id = 1000;
  while (rows.length < 300) {
    id++;
    if (used.has(id)) continue;
    const u = USERS[Math.floor(r() * USERS.length)]!;
    const b = BENIGN[Math.floor(r() * BENIGN.length)]!;
    const day = Math.floor(r() * 7);
    const hour = 8 + Math.floor(r() * 10);
    const ts = start + day * 864e5 + hour * 36e5 + Math.floor(r() * 36e5);
    rows.push({
      id,
      timestamp: new Date(ts).toISOString().replace(/\.\d+Z$/, "Z"),
      user: u.user,
      host: u.host,
      ip: u.ip,
      event_type: b.type,
      severity: b.sev,
      source: b.source,
      message: b.msg(u.user, u.host),
    });
  }
  return rows.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

export const logs: LogRow[] = buildLogs();

// ---------- Dashboard stats ----------

export const alertsOverTime = Array.from({ length: 14 }, (_, i) => {
  const r = rng(100 + i);
  const d = new Date(Date.parse("2026-09-24T00:00:00Z") + i * 864e5);
  const base = Math.floor(r() * 4);
  const spike = i === 10 ? 6 : i === 11 ? 4 : i === 12 ? 9 : 0;
  return { date: d.toISOString().slice(5, 10), alerts: base + spike, attacks: spike ? Math.ceil(spike / 3) : 0 };
});

// ---------- Entities ----------

export interface EntityProfile {
  type: EntityType;
  id: string;
  display: string;
  risk: number;
  baseline: { label: string; usual: string; observed: string; anomalous: boolean }[];
  anomaly_series: { date: string; score: number }[];
  related_incidents: string[];
}

const BASELINES: Record<string, EntityProfile["baseline"]> = {
  "user:alice": [
    { label: "Login hours", usual: "08:30 – 18:30 IST", observed: "02:14 IST", anomalous: true },
    { label: "Login countries", usual: "IN", observed: "IN, RO", anomalous: true },
    { label: "New files / day", usual: "≈ 3", observed: "40 in 6 min", anomalous: true },
    { label: "Removable media", usual: "Never", observed: "812 MB written", anomalous: true },
    { label: "Primary device", usual: "PC-12", observed: "PC-12", anomalous: false },
  ],
  "user:svc_backup": [
    { label: "Logon type", usual: "Service (5)", observed: "RemoteInteractive (10)", anomalous: true },
    { label: "Hosts contacted", usual: "BACKUP-01", observed: "JUMP-01, SRV-DB-01, FS-02", anomalous: true },
    { label: "Failed auth / 72h", usual: "0", observed: "92", anomalous: true },
    { label: "Group changes", usual: "None", observed: "+ Administrators", anomalous: true },
    { label: "Active hours", usual: "01:00 – 02:00", observed: "21:48 – 22:10", anomalous: true },
  ],
  "user:bob": [
    { label: "Office child processes", usual: "None", observed: "powershell.exe", anomalous: true },
    { label: "Login hours", usual: "09:00 – 18:00", observed: "08:58 – 18:10", anomalous: false },
    { label: "External senders opened", usual: "Known contacts", observed: "First-contact .top domain", anomalous: true },
    { label: "Countries", usual: "IN", observed: "IN", anomalous: false },
  ],
};

function genericBaseline(type: EntityType, id: string): EntityProfile["baseline"] {
  if (type === "ip")
    return [
      { label: "Reputation", usual: "Unknown / internal", observed: id.startsWith("10.") ? "Internal" : "Malicious (threat feed)", anomalous: !id.startsWith("10.") },
      { label: "Seen in org", usual: "Daily", observed: id.startsWith("10.") ? "Daily" : "First seen", anomalous: !id.startsWith("10.") },
      { label: "Ports", usual: "443", observed: id.startsWith("10.") ? "443, 445" : "443, 3389", anomalous: !id.startsWith("10.") },
    ];
  if (type === "host")
    return [
      { label: "Logged-in users", usual: "1 primary", observed: "1 primary", anomalous: false },
      { label: "New services", usual: "0 / week", observed: ["SRV-DB-01", "FS-02", "JUMP-01"].includes(id) ? "PSEXESVC" : "0", anomalous: ["SRV-DB-01", "FS-02", "JUMP-01"].includes(id) },
      { label: "Outbound volume", usual: "≈ 200 MB/day", observed: id === "PC-12" ? "812 MB to USB" : "≈ 210 MB/day", anomalous: id === "PC-12" },
    ];
  return [
    { label: "Executions / day", usual: "Normal", observed: "Normal", anomalous: false },
    { label: "Parent processes", usual: "explorer.exe", observed: id === "powershell.exe" ? "WINWORD.EXE" : "explorer.exe", anomalous: id === "powershell.exe" },
  ];
}

export function buildEntity(type: EntityType, id: string): EntityProfile {
  const key = `${type}:${id}`;
  const related = incidents
    .filter((i) => {
      const list = type === "user" ? i.entities.users : type === "host" ? i.entities.hosts : type === "ip" ? i.entities.ips : i.entities.apps;
      return list.includes(id);
    })
    .map((i) => i.id);
  const seed = [...key].reduce((a, c) => a + c.charCodeAt(0), 0);
  const r = rng(seed);
  const series = Array.from({ length: 14 }, (_, i) => {
    const d = new Date(Date.parse("2026-09-24T00:00:00Z") + i * 864e5).toISOString().slice(5, 10);
    let s = 0.05 + r() * 0.15;
    if (related.length && i >= 10) s = Math.min(0.99, s + (i - 9) * 0.2);
    return { date: d, score: Number(s.toFixed(2)) };
  });
  const risk = related.length ? Math.max(...related.map((rid) => incidents.find((x) => x.id === rid)!.risk_score)) : Math.round(series[13]!.score * 100);
  return { type, id, display: id, risk, baseline: BASELINES[key] ?? genericBaseline(type, id), anomaly_series: series, related_incidents: related };
}

// ---------- Metrics ----------

export const metrics = {
  logs_ingested: 1_284_392,
  confusion: { tp: 11, fp: 1, fn: 1, tn: 287 },
  comparison: [
    { scenario: "Foreign login + USB exfil (INC-001)", truth: "attack", detected: "attack", incident: "INC-001" },
    { scenario: "Low-and-slow credential spray (INC-002)", truth: "attack", detected: "attack", incident: "INC-002" },
    { scenario: "Phishing macro (INC-003)", truth: "attack", detected: "attack", incident: "INC-003" },
    { scenario: "DNS tunnelling (red team)", truth: "attack", detected: "benign", incident: null },
    { scenario: "Admin patching via PsExec (change #4412)", truth: "benign", detected: "attack", incident: null },
    { scenario: "Travel login (pre-approved)", truth: "benign", detected: "benign", incident: null },
    { scenario: "Nightly backup job", truth: "benign", detected: "benign", incident: null },
    { scenario: "Quarterly finance export", truth: "benign", detected: "benign", incident: null },
  ],
};
