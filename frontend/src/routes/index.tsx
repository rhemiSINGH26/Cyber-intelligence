import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CheckCircle2, Database, Pause, Play, Radio, ShieldAlert, Siren, Target } from "lucide-react";
import { qk } from "@/api";
import { useDemoMode } from "@/lib/demo";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState, Panel, SeverityBadge, StatCard, StatusPill, sevColor, scoreToSeverity, fmtTime } from "@/components/tl";
import type { LogSeverity } from "@/data/mock";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Dashboard — ThreatLens" },
      { name: "description", content: "Live SOC overview: KPIs, risk distribution, alert trends and incidents ranked by risk." },
      { property: "og:title", content: "Dashboard — ThreatLens" },
      { property: "og:description", content: "Live SOC overview of alerts, attacks and incidents." },
    ],
  }),
  component: Dashboard,
});

const tooltipStyle = { background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12 };

function Dashboard() {
  const { mode } = useDemoMode();
  const m = useQuery(qk.metrics(mode));
  const inc = useQuery(qk.incidents(mode));
  const navigate = useNavigate();
  const clean = mode === "clean";

  return (
    <div className="mx-auto max-w-[1500px] space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Security Operations Overview</h1>
          <p className="text-sm text-muted-foreground">Last 14 days · all sensors</p>
        </div>
      </div>

      {clean && (
        <div className="flex items-center gap-3 rounded-lg border border-low/40 bg-low/10 px-4 py-3 text-low">
          <CheckCircle2 className="size-5 shrink-0" />
          <span className="text-sm font-medium">Clean logs → 0 alerts. No false alarms.</span>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {m.isLoading || !m.data ? (
          Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-[104px]" />)
        ) : (
          <>
            <StatCard label="Logs ingested" value={m.data.logs_ingested.toLocaleString()} sub="+3.1% vs prior period" icon={<Database className="size-4" />} />
            <StatCard label="Alerts raised" value={m.data.alerts_raised} tone={clean ? "low" : "high"} sub={clean ? "No alerts on benign data" : "Correlated into incidents"} icon={<Siren className="size-4" />} />
            <StatCard label="Attacks detected" value={m.data.attacks_detected} tone={clean ? "low" : "critical"} sub={clean ? "None" : "3 confirmed incidents"} icon={<Target className="size-4" />} />
            <StatCard
              label="False-positive rate"
              value={clean ? "0.00%" : `${(m.data.fpr * 100).toFixed(2)}%`}
              tone="low"
              sub={clean ? "0 false alarms on clean set" : `${m.data.confusion.fp} FP / ${m.data.confusion.fp + m.data.confusion.tn} benign`}
              icon={<CheckCircle2 className="size-4" />}
            />
          </>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Alerts over time" className="lg:col-span-2">
          {m.data ? (
            <div className="h-56">
              <ResponsiveContainer>
                <AreaChart data={m.data.alerts_over_time} margin={{ left: -20, right: 8, top: 8 }}>
                  <defs>
                    <linearGradient id="ga" x1="0" x2="0" y1="0" y2="1">
                      <stop offset="0" stopColor="var(--primary)" stopOpacity={0.4} />
                      <stop offset="1" stopColor="var(--primary)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="date" stroke="var(--muted-foreground)" fontSize={11} tickLine={false} />
                  <YAxis stroke="var(--muted-foreground)" fontSize={11} tickLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Area type="monotone" dataKey="alerts" stroke="var(--primary)" fill="url(#ga)" strokeWidth={2} />
                  <Area type="monotone" dataKey="attacks" stroke="var(--critical)" fill="transparent" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <Skeleton className="h-56" />
          )}
        </Panel>
        <Panel title="Risk score distribution">
          {!m.data ? (
            <Skeleton className="h-56" />
          ) : m.data.severity_dist.length === 0 ? (
            <EmptyState icon={<CheckCircle2 className="size-8 text-low" />} title="No scored alerts" text="Nothing above baseline in benign data." />
          ) : (
            <div className="flex h-56 items-center gap-4">
              <div className="h-full flex-1">
                <ResponsiveContainer>
                  <PieChart>
                    <Pie data={m.data.severity_dist} dataKey="value" innerRadius="58%" outerRadius="90%" paddingAngle={2} stroke="none">
                      {m.data.severity_dist.map((d) => <Cell key={d.key} fill={sevColor[d.key as LogSeverity]} />)}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <ul className="space-y-2 text-sm">
                {m.data.severity_dist.map((d) => (
                  <li key={d.key} className="flex items-center gap-2">
                    <span className="size-2.5 rounded-sm" style={{ background: sevColor[d.key as LogSeverity] }} />
                    <span className="w-16 text-muted-foreground">{d.name}</span>
                    <span className="font-mono font-semibold">{d.value}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Incidents by risk score" className="lg:col-span-2" action={<span className="font-mono text-xs text-muted-foreground">{inc.data?.length ?? 0} open</span>}>
          {inc.isLoading ? (
            <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-11" />)}</div>
          ) : !inc.data?.length ? (
            <EmptyState icon={<CheckCircle2 className="size-8 text-low" />} title="0 incidents" text="No correlated attack activity in the current dataset." />
          ) : (
            <div className="-mx-4 -my-4 overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                  <tr className="border-b">
                    <th className="px-4 py-2 font-medium">ID</th>
                    <th className="px-2 py-2 font-medium">Title</th>
                    <th className="px-2 py-2 font-medium">Risk</th>
                    <th className="px-2 py-2 font-medium">Conf.</th>
                    <th className="px-2 py-2 font-medium">Status</th>
                    <th className="px-4 py-2 font-medium">Entities</th>
                  </tr>
                </thead>
                <tbody>
                  {inc.data.map((i) => (
                    <tr key={i.id} onClick={() => navigate({ to: "/incidents/$id", params: { id: i.id } })} className="cursor-pointer border-b last:border-0 hover:bg-accent/50">
                      <td className="px-4 py-3 font-mono text-xs text-primary">{i.id}</td>
                      <td className="max-w-[280px] px-2 py-3 font-medium">{i.title}</td>
                      <td className="px-2 py-3"><SeverityBadge severity={scoreToSeverity(i.risk_score)}>{i.risk_score}</SeverityBadge></td>
                      <td className="px-2 py-3 font-mono text-xs">{Math.round(i.confidence * 100)}%</td>
                      <td className="px-2 py-3"><StatusPill status={i.status} /></td>
                      <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{[...i.entities.users, ...i.entities.hosts].slice(0, 3).join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        <LiveFeed />
      </div>
    </div>
  );
}

const FEED_TEMPLATES: { msg: string; sev: LogSeverity; inc?: string }[] = [
  { msg: "Impossible travel: alice IN → RO in 4m", sev: "critical", inc: "INC-001" },
  { msg: "Auth failure spike svc_backup @ DC-01", sev: "high", inc: "INC-002" },
  { msg: "PsExec service install on FS-02", sev: "high", inc: "INC-002" },
  { msg: "Encoded PowerShell from WINWORD.EXE", sev: "medium", inc: "INC-003" },
  { msg: "Rare DNS TXT query from PC-19", sev: "low" },
  { msg: "New USB device on PC-12", sev: "medium", inc: "INC-001" },
  { msg: "Admin login outside window: heidi", sev: "low" },
];

function LiveFeed() {
  const { mode } = useDemoMode();
  const [on, setOn] = useState(true);
  const [items, setItems] = useState<{ id: number; ts: string; msg: string; sev: LogSeverity; inc?: string }[]>([]);
  const n = useRef(0);
  useEffect(() => {
    setItems([]);
  }, [mode]);
  useEffect(() => {
    if (!on || mode === "clean") return;
    const t = setInterval(() => {
      const tpl = FEED_TEMPLATES[Math.floor(Math.random() * FEED_TEMPLATES.length)]!;
      n.current++;
      setItems((p) => [{ id: n.current, ts: new Date().toISOString(), ...tpl }, ...p].slice(0, 12));
    }, 3000);
    return () => clearInterval(t);
  }, [on, mode]);

  return (
    <Panel
      title={<span className="flex items-center gap-2"><Radio className={on && mode !== "clean" ? "size-3.5 animate-pulse text-critical" : "size-3.5"} /> Live feed</span>}
      action={
        <button onClick={() => setOn((v) => !v)} className="flex items-center gap-1 rounded border px-2 py-0.5 text-xs hover:bg-accent">
          {on ? <Pause className="size-3" /> : <Play className="size-3" />} {on ? "Pause" : "Resume"}
        </button>
      }
    >
      <ul className="h-[260px] space-y-1.5 overflow-y-auto">
        {mode === "clean" ? (
          <EmptyState icon={<CheckCircle2 className="size-8 text-low" />} title="Quiet" text="Stream is clean — no alerts generated." />
        ) : items.length === 0 ? (
          <EmptyState icon={<ShieldAlert className="size-8" />} title={on ? "Listening for alerts…" : "Feed paused"} />
        ) : (
          items.map((it) => (
            <li key={it.id} className="animate-in fade-in slide-in-from-top-1 rounded-md border bg-surface px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <SeverityBadge severity={it.sev} />
                <span className="font-mono text-[10px] text-muted-foreground">{fmtTime(it.ts).slice(11)}</span>
              </div>
              <div className="mt-1 text-xs">{it.msg}</div>
              {it.inc && <Link to="/incidents/$id" params={{ id: it.inc }} className="font-mono text-[10px] text-primary hover:underline">→ {it.inc}</Link>}
            </li>
          ))
        )}
      </ul>
    </Panel>
  );
}
