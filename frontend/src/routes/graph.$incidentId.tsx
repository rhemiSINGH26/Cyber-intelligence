import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { ReactFlow, Background, Controls, Handle, Position, MarkerType, type Edge, type Node, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { AppWindow, FileText, Globe, Laptop, User, X } from "lucide-react";
import { qk } from "@/api";
import { incidents, logs, type GraphNode, type IncidentGraph } from "@/data/mock";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState, SeverityBadge, fmtShort, fmtTime } from "@/components/tl";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/graph/$incidentId")({
  head: ({ params }) => ({
    meta: [
      { title: `Attack graph ${params.incidentId} — ThreatLens` },
      { name: "description", content: "Interactive graph of users, hosts, IPs, apps and files involved in an attack path." },
      { property: "og:title", content: `Attack graph ${params.incidentId} — ThreatLens` },
      { property: "og:description", content: "Visualise the attack path with numbered, highlighted events." },
    ],
  }),
  component: GraphPage,
});

const ICONS = { user: User, host: Laptop, ip: Globe, app: AppWindow, file: FileText };

function EntityNode({ data }: NodeProps<Node<{ n: GraphNode; selected: boolean }>>) {
  const { n, selected } = data;
  const Icon = ICONS[n.type];
  return (
    <div className={cn("flex min-w-[150px] items-center gap-2 rounded-lg border bg-card px-3 py-2 shadow-lg", n.suspicious ? "border-critical/70" : "border-border", selected && "glow-primary border-primary")}>
      <Handle type="target" position={Position.Left} className="!bg-muted-foreground !size-1.5 !border-0" />
      <span className={cn("grid size-8 place-items-center rounded-md", n.suspicious ? "bg-critical/15 text-critical" : "bg-muted text-muted-foreground")}>
        <Icon className="size-4" />
      </span>
      <div className="min-w-0">
        <div className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">{n.type}</div>
        <div className="max-w-[150px] truncate font-mono text-xs font-medium text-foreground">{n.label}</div>
      </div>
      <Handle type="source" position={Position.Right} className="!bg-muted-foreground !size-1.5 !border-0" />
    </div>
  );
}
const nodeTypes = { entity: EntityNode };

function layout(g: IncidentGraph) {
  const rank: Record<string, number> = {};
  g.nodes.forEach((n) => (rank[n.id] = 0));
  const maxIters = Math.min(g.nodes.length, 6);
  for (let k = 0; k < maxIters; k++) {
    for (const e of g.edges) {
      rank[e.target] = Math.min(Math.max(rank[e.target] ?? 0, (rank[e.source] ?? 0) + 1), 6);
    }
  }
  const cols: Record<number, string[]> = {};
  g.nodes.forEach((n) => (cols[rank[n.id] ?? 0] ??= []).push(n.id));
  const pos: Record<string, { x: number; y: number }> = {};
  Object.entries(cols).forEach(([c, ids]) => ids.forEach((id, i) => (pos[id] = { x: Number(c) * 260, y: i * 130 + (Number(c) % 2) * 40 })));
  return pos;
}

function GraphPage() {
  const { incidentId } = Route.useParams();
  const navigate = useNavigate();
  const { data, isLoading, error } = useQuery(qk.graph(incidentId));
  const [sel, setSel] = useState<GraphNode | null>(null);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  useEffect(() => setSel(null), [incidentId]);

  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [], edges: [] };
    const pos = layout(data);
    const nodes: Node[] = data.nodes.map((n) => ({ id: n.id, type: "entity", position: pos[n.id] ?? { x: 0, y: 0 }, data: { n, selected: sel?.id === n.id } }));
    const edges: Edge[] = data.edges.map((e) => {
      const color = e.suspicious ? "var(--critical)" : "var(--muted-foreground)";
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        animated: e.suspicious,
        label: `${e.order ? `${e.order}. ` : ""}${e.event} · ${fmtShort(e.timestamp)}`,
        labelStyle: { fill: e.suspicious ? "var(--critical)" : "var(--muted-foreground)", fontSize: 10, fontFamily: "JetBrains Mono" },
        labelBgStyle: { fill: "var(--background)" },
        labelBgPadding: [4, 2] as [number, number],
        style: { stroke: color, strokeWidth: e.suspicious ? 2 : 1, strokeDasharray: e.suspicious ? undefined : "4 4" },
        markerEnd: { type: MarkerType.ArrowClosed, color },
      };
    });
    return { nodes, edges };
  }, [data, sel]);

  const related = useMemo(() => {
    if (!sel) return { logs: [], incs: [] };
    const l = sel.label;
    return {
      logs: logs.filter((r) => r.user === l || r.host === l || r.ip === l || r.message.includes(l)).slice(0, 12),
      incs: incidents.filter((i) => [...(i.entities?.users || []), ...(i.entities?.hosts || []), ...(i.entities?.ips || []), ...(i.entities?.apps || [])].includes(l) || data?.incident_id === i.id),
    };
  }, [sel, data]);

  return (
    <div className="mx-auto flex max-w-[1500px] flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Attack graph</h1>
          <p className="text-sm text-muted-foreground">Red = suspicious · numbered edges = attack path in order</p>
        </div>
        <div className="flex items-center gap-2">
          <select value={incidentId} onChange={(e) => navigate({ to: "/graph/$incidentId", params: { incidentId: e.target.value } })} className="h-9 rounded-md border bg-surface px-2 font-mono text-sm">
            {incidents.map((i) => <option key={i.id} value={i.id}>{i.id} — {i.title.slice(0, 32)}</option>)}
          </select>
          <Link to="/incidents/$id" params={{ id: incidentId }} className="rounded-md border px-3 py-2 text-xs hover:bg-accent">Open incident</Link>
        </div>
      </div>

      <div className="relative h-[calc(100vh-170px)] min-h-[480px] overflow-hidden rounded-lg border bg-surface grid-bg">
        {isLoading || !mounted ? (
          <Skeleton className="h-full w-full" />
        ) : error || !data ? (
          <EmptyState title="Graph unavailable" text={`No graph for ${incidentId}.`} />
        ) : (
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView colorMode="dark" onNodeClick={(_, n) => setSel((n.data as { n: GraphNode }).n)} onPaneClick={() => setSel(null)} proOptions={{ hideAttribution: true }}>
            <Background color="transparent" />
            <Controls className="!border-border !bg-card" />
          </ReactFlow>
        )}

        {sel && (
          <aside className="absolute inset-y-0 right-0 z-10 flex w-full max-w-sm flex-col border-l bg-card shadow-2xl animate-in slide-in-from-right">
            <header className="flex items-center justify-between border-b px-4 py-3">
              <div>
                <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{sel.type}</div>
                <div className="font-mono text-sm font-semibold">{sel.label}</div>
              </div>
              <button onClick={() => setSel(null)} aria-label="Close"><X className="size-4" /></button>
            </header>
            <div className="flex-1 space-y-4 overflow-y-auto p-4">
              {sel.suspicious && <SeverityBadge severity="critical">Suspicious</SeverityBadge>}
              {sel.type !== "file" && (
                <Link to="/entities/$type/$id" params={{ type: sel.type, id: sel.label }} className="block rounded-md border px-3 py-2 text-xs text-primary hover:bg-accent">View entity profile →</Link>
              )}
              <div>
                <h3 className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">Related incidents</h3>
                {related.incs.map((i) => (
                  <Link key={i.id} to="/incidents/$id" params={{ id: i.id }} className="mb-1.5 block rounded-md border bg-surface p-2 text-xs hover:border-primary">
                    <span className="font-mono text-primary">{i.id}</span> · {i.title}
                  </Link>
                ))}
              </div>
              <div>
                <h3 className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">Related logs ({related.logs.length})</h3>
                {related.logs.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No matching log rows.</p>
                ) : (
                  <ul className="space-y-1.5">
                    {related.logs.map((l) => (
                      <li key={l.id} className="rounded border bg-surface p-2 font-mono text-[10px]">
                        <div className="flex justify-between text-muted-foreground"><span>#{l.id} · {l.event_type}</span><span>{fmtTime(l.timestamp).slice(5, 16)}</span></div>
                        <div className="mt-0.5 break-all">{l.message}</div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
