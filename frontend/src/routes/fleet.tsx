import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, useRef, useEffect } from "react";
import { toast } from "sonner";
import {
  Laptop,
  Server,
  Terminal,
  Activity,
  Plus,
  Trash2,
  RefreshCw,
  Copy,
  Check,
  Radio,
  Play,
  Pause,
  AlertTriangle,
  Flame,
  KeyRound,
  HardDrive,
  Download,
  Search,
  ExternalLink,
  Cpu,
  CircleDot
} from "lucide-react";
import { qk, type FleetNode, type FleetLog, addFleetNode, deleteFleetNode, simulateFleetEvent } from "@/api";
import { Panel, RiskGauge, SeverityBadge, StatusPill, EmptyState, scoreToSeverity } from "@/components/tl";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/fleet")({
  head: () => ({
    meta: [
      { title: "Endpoint Fleet & Nodes — ThreatLens" },
      { name: "description", content: "Live computer fleet telemetry, multi-laptop monitoring, and log streaming." },
    ],
  }),
  component: FleetPage,
});

function FleetPage() {
  const qc = useQueryClient();
  const fleetQuery = useQuery(qk.fleet());
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const logsQuery = useQuery(qk.fleetLogs(selectedNode || undefined));

  // Modals & UI state
  const [showAddModal, setShowAddModal] = useState(false);
  const [showAgentModal, setShowAgentModal] = useState(false);
  const [logFilter, setLogFilter] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const [activeTab, setActiveTab] = useState<"all" | "online" | "compromised">("all");
  const logContainerRef = useRef<HTMLDivElement>(null);

  // Form state for adding custom node
  const [newNodeId, setNewNodeId] = useState("");
  const [newNodeName, setNewNodeName] = useState("");
  const [newNodeOs, setNewNodeOs] = useState("Windows 11 Pro");
  const [newNodeIp, setNewNodeIp] = useState("192.168.1.150");
  const [newNodeUser, setNewNodeUser] = useState("operator");

  // Copy agent command state
  const [copiedCmd, setCopiedCmd] = useState(false);

  // Mutations
  const addMutation = useMutation({
    mutationFn: addFleetNode,
    onSuccess: (node) => {
      toast.success(`Node ${node.id} registered into Fleet`);
      qc.invalidateQueries({ queryKey: ["fleet"] });
      setShowAddModal(false);
      setNewNodeId("");
      setNewNodeName("");
    },
    onError: (err: any) => {
      toast.error(err.message || "Failed to register node");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteFleetNode,
    onSuccess: () => {
      toast.success("Node removed from fleet");
      qc.invalidateQueries({ queryKey: ["fleet"] });
      if (selectedNode) setSelectedNode(null);
    },
  });

  const simulateMutation = useMutation({
    mutationFn: ({ nodeId, eventType }: { nodeId: string; eventType: string }) =>
      simulateFleetEvent(nodeId, eventType),
    onSuccess: (res, vars) => {
      toast.success(`Simulated '${vars.eventType}' on ${vars.nodeId}`);
      qc.invalidateQueries({ queryKey: ["fleet"] });
      qc.invalidateQueries({ queryKey: ["fleet-logs"] });
    },
    onError: () => toast.error("Simulation failed"),
  });

  // Auto-scroll logs
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logsQuery.data, autoScroll]);

  const state = fleetQuery.data;
  const nodes = state?.nodes || [];
  const stats = state?.stats || { total: 0, online: 0, offline: 0, elevated_risk: 0 };

  const filteredNodes = nodes.filter((n) => {
    if (activeTab === "online") return n.online;
    if (activeTab === "compromised") return n.risk >= 60;
    return true;
  });

  const logs = (logsQuery.data || []).filter((l) => {
    if (!logFilter) return true;
    const q = logFilter.toLowerCase();
    return (
      l.message.toLowerCase().includes(q) ||
      l.node_id.toLowerCase().includes(q) ||
      l.level.toLowerCase().includes(q)
    );
  });

  const copyAgentCommand = (id: string = "LAPTOP-1") => {
    const cmd = `python fleet_agent.py --server http://127.0.0.1:8000 --id ${id}`;
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(true);
    toast.success("Agent command copied to clipboard!");
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <div className="mx-auto max-w-[1500px] space-y-5">
      {/* Top Banner */}
      <div className="flex flex-col gap-4 rounded-xl border border-primary/20 bg-gradient-to-r from-card via-card to-primary/5 p-5 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex size-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
              Live Fleet Module (live-4-laptop compatible)
            </span>
          </div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight">Endpoint Fleet & Nodes Manager</h1>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Connect physical laptops, add custom computers, monitor live heartbeats and stream real-time logs.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setShowAgentModal(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-primary/30 bg-primary/10 px-3 py-2 text-xs font-medium text-primary hover:bg-primary/20 transition-colors"
          >
            <Terminal className="size-3.5" /> Run Physical Agent
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-3.5 py-2 text-xs font-semibold text-primary-foreground shadow-sm hover:bg-primary/90 transition-colors"
          >
            <Plus className="size-3.5" /> Add Node / Computer
          </button>
          <button
            onClick={() => {
              qc.invalidateQueries({ queryKey: ["fleet"] });
              qc.invalidateQueries({ queryKey: ["fleet-logs"] });
              toast.info("Refreshed fleet telemetry");
            }}
            className="inline-flex items-center gap-1 rounded-lg border px-2.5 py-2 text-xs hover:bg-accent transition-colors"
            title="Refresh"
          >
            <RefreshCw className={cn("size-3.5", fleetQuery.isFetching && "animate-spin")} />
          </button>
        </div>
      </div>

      {/* KPI Stats */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div className="rounded-xl border bg-card p-4">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-xs uppercase font-medium tracking-wider">Total Endpoints</span>
            <Laptop className="size-4 text-primary" />
          </div>
          <div className="mt-2 font-mono text-2xl font-bold">{stats.total}</div>
          <div className="mt-1 text-[11px] text-muted-foreground">Registered computers in fleet</div>
        </div>

        <div className="rounded-xl border bg-card p-4">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-xs uppercase font-medium tracking-wider">Online & Beating</span>
            <Radio className="size-4 text-emerald-500 animate-pulse" />
          </div>
          <div className="mt-2 font-mono text-2xl font-bold text-emerald-500">{stats.online}</div>
          <div className="mt-1 text-[11px] text-muted-foreground">Heartbeat &le; 12s interval</div>
        </div>

        <div className="rounded-xl border bg-card p-4">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-xs uppercase font-medium tracking-wider">Offline / Waiting</span>
            <CircleDot className="size-4 text-muted-foreground" />
          </div>
          <div className="mt-2 font-mono text-2xl font-bold text-muted-foreground">{stats.offline}</div>
          <div className="mt-1 text-[11px] text-muted-foreground">Awaiting agent connection</div>
        </div>

        <div className="rounded-xl border bg-card p-4">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-xs uppercase font-medium tracking-wider">Elevated Risk</span>
            <Flame className="size-4 text-critical" />
          </div>
          <div className="mt-2 font-mono text-2xl font-bold text-critical">{stats.elevated_risk}</div>
          <div className="mt-1 text-[11px] text-muted-foreground">Risk score &ge; 60 (anomalous)</div>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center justify-between border-b pb-2">
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setActiveTab("all")}
            className={cn(
              "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              activeTab === "all" ? "bg-primary text-primary-foreground font-semibold" : "text-muted-foreground hover:bg-accent"
            )}
          >
            All Nodes ({nodes.length})
          </button>
          <button
            onClick={() => setActiveTab("online")}
            className={cn(
              "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              activeTab === "online" ? "bg-emerald-600 text-white font-semibold" : "text-muted-foreground hover:bg-accent"
            )}
          >
            Online ({stats.online})
          </button>
          <button
            onClick={() => setActiveTab("compromised")}
            className={cn(
              "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              activeTab === "compromised" ? "bg-critical text-destructive-foreground font-semibold" : "text-muted-foreground hover:bg-accent"
            )}
          >
            Elevated Risk ({stats.elevated_risk})
          </button>
        </div>

        {selectedNode && (
          <button
            onClick={() => setSelectedNode(null)}
            className="text-xs font-mono text-primary hover:underline"
          >
            Viewing {selectedNode} logs &bull; Clear selection &rarr;
          </button>
        )}
      </div>

      {/* Main Grid: Fleet Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {fleetQuery.isLoading ? (
          Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-56 rounded-xl" />)
        ) : filteredNodes.length === 0 ? (
          <div className="col-span-full">
            <EmptyState
              icon={<Laptop className="size-8 text-muted-foreground" />}
              title="No nodes in this view"
              text="Try selecting 'All Nodes' or register a new computer node."
            />
          </div>
        ) : (
          filteredNodes.map((n) => {
            const isSelected = selectedNode === n.id;
            return (
              <div
                key={n.id}
                className={cn(
                  "flex flex-col justify-between rounded-xl border bg-card p-4 transition-all duration-200",
                  isSelected ? "border-primary ring-2 ring-primary/20 shadow-md" : "hover:border-primary/50",
                  n.status === "compromised" && "border-critical/40 bg-critical/5"
                )}
              >
                <div>
                  {/* Card Header */}
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <div
                        className={cn(
                          "grid size-9 place-items-center rounded-lg border",
                          n.status === "compromised"
                            ? "border-critical/30 bg-critical/15 text-critical"
                            : "border-border bg-muted/60 text-foreground"
                        )}
                      >
                        {n.os.toLowerCase().includes("linux") || n.id.includes("SERVER") ? (
                          <Server className="size-4" />
                        ) : (
                          <Laptop className="size-4" />
                        )}
                      </div>
                      <div>
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-xs font-bold">{n.id}</span>
                          <span
                            className={cn(
                              "size-2 rounded-full",
                              n.online ? "bg-emerald-500 animate-pulse" : "bg-muted-foreground/40"
                            )}
                          />
                        </div>
                        <div className="text-[11px] text-muted-foreground truncate max-w-[140px]">{n.name}</div>
                      </div>
                    </div>

                    <SeverityBadge severity={scoreToSeverity(n.risk)}>
                      {n.risk}
                    </SeverityBadge>
                  </div>

                  {/* Node Metadata */}
                  <div className="mt-3 space-y-1 rounded-lg border bg-surface/70 p-2.5 font-mono text-[11px]">
                    <div className="flex justify-between text-muted-foreground">
                      <span>Status:</span>
                      <span
                        className={cn(
                          "font-semibold uppercase text-[10px]",
                          n.online ? "text-emerald-500" : "text-muted-foreground"
                        )}
                      >
                        {n.online ? `ONLINE (${n.age_seconds ?? 0}s)` : "OFFLINE"}
                      </span>
                    </div>
                    <div className="flex justify-between text-muted-foreground">
                      <span>User:</span>
                      <span className="text-foreground">{n.user}</span>
                    </div>
                    <div className="flex justify-between text-muted-foreground">
                      <span>IP Addr:</span>
                      <span className="text-foreground">{n.ip}</span>
                    </div>
                    <div className="flex justify-between text-muted-foreground truncate">
                      <span>OS:</span>
                      <span className="text-foreground truncate max-w-[110px]" title={n.os}>{n.os}</span>
                    </div>
                    <div className="flex justify-between text-muted-foreground">
                      <span>Events:</span>
                      <span className="text-primary font-bold">{n.events}</span>
                    </div>
                  </div>
                </div>

                {/* Card Actions */}
                <div className="mt-4 space-y-2 border-t pt-3">
                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => setSelectedNode(n.id)}
                      className={cn(
                        "flex-1 rounded-md py-1.5 text-xs font-semibold transition-colors",
                        isSelected
                          ? "bg-primary text-primary-foreground"
                          : "border bg-accent/40 hover:bg-accent text-foreground"
                      )}
                    >
                      {isSelected ? "Viewing Logs" : "View Logs"}
                    </button>

                    {!n.is_default && (
                      <button
                        onClick={() => deleteMutation.mutate(n.id)}
                        className="rounded-md border p-1.5 text-muted-foreground hover:bg-critical/10 hover:text-critical"
                        title="Remove node"
                      >
                        <Trash2 className="size-3.5" />
                      </button>
                    )}
                  </div>

                  {/* Simulate Quick Triggers */}
                  <div className="grid grid-cols-2 gap-1 text-[10px]">
                    <button
                      onClick={() => simulateMutation.mutate({ nodeId: n.id, eventType: "heartbeat" })}
                      className="rounded border bg-background px-1.5 py-1 text-center font-mono hover:bg-accent"
                      title="Send simulated pulse"
                    >
                      &bull; Heartbeat
                    </button>
                    <button
                      onClick={() => simulateMutation.mutate({ nodeId: n.id, eventType: "powershell_encoded" })}
                      className="rounded border border-critical/30 bg-critical/10 px-1.5 py-1 text-center font-mono font-semibold text-critical hover:bg-critical/20"
                      title="Simulate encoded powershell execution"
                    >
                      &bull; Attack!
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Dedicated Logs Terminal */}
      <Panel
        title={
          <div className="flex items-center gap-2">
            <Terminal className="size-4 text-primary" />
            <span>
              {selectedNode ? `Live Telemetry Logs — ${selectedNode}` : "Live Fleet Telemetry Stream (All Nodes)"}
            </span>
            <span className="rounded-full bg-primary/10 px-2 py-0.5 font-mono text-[10px] text-primary">
              {logs.length} events
            </span>
          </div>
        }
        action={
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2 top-1.5 size-3.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Filter logs..."
                value={logFilter}
                onChange={(e) => setLogFilter(e.target.value)}
                className="h-7 w-40 rounded-md border bg-background pl-7 pr-2 font-mono text-xs focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <button
              onClick={() => setAutoScroll(!autoScroll)}
              className={cn(
                "inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs transition-colors",
                autoScroll ? "bg-primary/10 text-primary border-primary/30" : "text-muted-foreground hover:bg-accent"
              )}
            >
              {autoScroll ? <Pause className="size-3" /> : <Play className="size-3" />}
              {autoScroll ? "Pause Scroll" : "Auto Scroll"}
            </button>
          </div>
        }
      >
        <div
          ref={logContainerRef}
          className="h-72 overflow-y-auto rounded-lg border bg-zinc-950 p-3 font-mono text-xs text-zinc-100 shadow-inner"
        >
          {logsQuery.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-5 w-3/4 bg-zinc-800" />
              <Skeleton className="h-5 w-1/2 bg-zinc-800" />
              <Skeleton className="h-5 w-5/6 bg-zinc-800" />
            </div>
          ) : logs.length === 0 ? (
            <div className="grid h-full place-items-center text-center text-zinc-500">
              <p>No telemetry logs received yet. Start fleet_agent.py or click &quot;Simulate&quot; on any node.</p>
            </div>
          ) : (
            <div className="space-y-1.5">
              {logs.map((log) => {
                const isCrit = log.level === "CRIT";
                const isWarn = log.level === "WARN";
                return (
                  <div
                    key={log.id}
                    className={cn(
                      "flex flex-wrap items-start gap-x-2 rounded px-1.5 py-1 transition-colors hover:bg-zinc-900/80",
                      isCrit && "bg-red-950/30 text-red-300",
                      isWarn && "bg-amber-950/20 text-amber-300"
                    )}
                  >
                    <span className="text-zinc-500">{log.timestamp.slice(11, 19)}</span>
                    <span
                      className={cn(
                        "rounded px-1 text-[10px] font-bold uppercase",
                        isCrit ? "bg-red-600 text-white" : isWarn ? "bg-amber-500 text-black" : "bg-zinc-800 text-zinc-300"
                      )}
                    >
                      {log.level}
                    </span>
                    <span className="font-bold text-sky-400">[{log.node_id}]</span>
                    <span className="flex-1 text-zinc-200">{log.message}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </Panel>

      {/* Add Custom Computer Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-xs p-4">
          <div className="w-full max-w-md rounded-xl border bg-card p-5 shadow-2xl">
            <h2 className="text-lg font-bold">Register Computer / Node</h2>
            <p className="mt-1 text-xs text-muted-foreground">
              Add a new physical laptop, workstation, or server to the telemetry fleet.
            </p>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!newNodeId) return toast.error("Please enter a Node ID");
                addMutation.mutate({
                  id: newNodeId,
                  name: newNodeName,
                  os: newNodeOs,
                  ip: newNodeIp,
                  user: newNodeUser,
                });
              }}
              className="mt-4 space-y-3"
            >
              <div>
                <label className="text-[11px] font-semibold uppercase text-muted-foreground">Node Identifier (Unique)</label>
                <input
                  type="text"
                  placeholder="e.g. LAPTOP-5 or WORKSTATION-SEC"
                  value={newNodeId}
                  onChange={(e) => setNewNodeId(e.target.value.toUpperCase())}
                  className="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs focus:ring-1 focus:ring-primary"
                  required
                />
              </div>

              <div>
                <label className="text-[11px] font-semibold uppercase text-muted-foreground">Display Name</label>
                <input
                  type="text"
                  placeholder="e.g. Finance Controller Laptop"
                  value={newNodeName}
                  onChange={(e) => setNewNodeName(e.target.value)}
                  className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-xs focus:ring-1 focus:ring-primary"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[11px] font-semibold uppercase text-muted-foreground">Operating System</label>
                  <input
                    type="text"
                    value={newNodeOs}
                    onChange={(e) => setNewNodeOs(e.target.value)}
                    className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-xs focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-semibold uppercase text-muted-foreground">Primary User</label>
                  <input
                    type="text"
                    value={newNodeUser}
                    onChange={(e) => setNewNodeUser(e.target.value)}
                    className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-xs focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-semibold uppercase text-muted-foreground">IP Address</label>
                <input
                  type="text"
                  value={newNodeIp}
                  onChange={(e) => setNewNodeIp(e.target.value)}
                  className="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs focus:ring-1 focus:ring-primary"
                />
              </div>

              <div className="mt-5 flex justify-end gap-2 border-t pt-3">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={addMutation.isPending}
                  className="rounded-md bg-primary px-4 py-1.5 text-xs font-semibold text-primary-foreground hover:bg-primary/90"
                >
                  {addMutation.isPending ? "Adding..." : "Register Node"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Run Agent Instructions Modal */}
      {showAgentModal && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-xs p-4">
          <div className="w-full max-w-xl rounded-xl border bg-card p-5 shadow-2xl">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold flex items-center gap-2">
                <Terminal className="size-5 text-primary" /> Run Real Agent on Laptops
              </h2>
              <button
                onClick={() => setShowAgentModal(false)}
                className="rounded-md border px-2 py-1 text-xs hover:bg-accent"
              >
                Close
              </button>
            </div>

            <p className="mt-2 text-xs text-muted-foreground">
              Run the lightweight telemetry script on each laptop (supports LAPTOP-1, LAPTOP-2, LAPTOP-3, LAPTOP-4, or custom nodes).
              It sends periodic heartbeats to <code className="text-primary font-mono font-semibold">POST /api/heartbeat</code>.
            </p>

            <div className="mt-4 space-y-3 font-mono text-xs">
              <div className="rounded-lg border bg-zinc-950 p-3 text-zinc-200">
                <div className="text-[10px] uppercase text-zinc-500 font-bold mb-1">Terminal Command</div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-emerald-400 select-all">
                    python fleet_agent.py --server http://127.0.0.1:8000 --id LAPTOP-1
                  </span>
                  <button
                    onClick={() => copyAgentCommand("LAPTOP-1")}
                    className="inline-flex items-center gap-1 rounded bg-zinc-800 px-2 py-1 text-[11px] text-zinc-300 hover:bg-zinc-700"
                  >
                    {copiedCmd ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3" />}
                    {copiedCmd ? "Copied" : "Copy"}
                  </button>
                </div>
              </div>

              <div className="rounded-lg border bg-surface p-3 text-xs">
                <h4 className="font-semibold text-foreground mb-1">How it works:</h4>
                <ul className="list-disc pl-4 space-y-1 text-muted-foreground text-[11px]">
                  <li>Sends hostname, OS, logged-in username, and local IP every 2 seconds.</li>
                  <li>ThreatLens marks the laptop as <strong className="text-emerald-500 font-mono">ONLINE</strong> with live latency.</li>
                  <li>All heartbeats and events stream into the Live Logs console above.</li>
                  <li>Compatible with repo: <a href="https://github.com/anish232006/live-4-laptop-module.git" target="_blank" rel="noreferrer" className="text-primary hover:underline">live-4-laptop-module</a>.</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
