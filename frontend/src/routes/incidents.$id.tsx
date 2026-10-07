import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
  Ban,
  Check,
  Download,
  FileWarning,
  Globe,
  Laptop,
  Lock,
  Network,
  Play,
  ServerCrash,
  Square,
  User,
  AppWindow,
  AlertTriangle,
  Bot,
  Copy,
  ChevronRight,
  ShieldAlert,
  Flame,
  FileText,
  Search,
  ExternalLink
} from "lucide-react";
import { qk } from "@/api";
import { useDemoMode } from "@/lib/demo";
import { KILL_CHAIN, type Incident, type Stage } from "@/data/mock";
import { Skeleton } from "@/components/ui/skeleton";
import { Panel, RiskGauge, SeverityBadge, StatusPill, fmtTime, scoreToSeverity, EmptyState } from "@/components/tl";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/incidents/$id")({
  head: ({ params }) => ({
    meta: [
      { title: `${params.id} — Incident · ThreatLens` },
      { name: "description", content: `Kill chain, evidence timeline and recommended response for incident ${params.id}.` },
      { property: "og:title", content: `${params.id} — ThreatLens Incident` },
      { property: "og:description", content: "Explainable incident detail with MITRE ATT&CK mapping and raw evidence." },
    ],
  }),
  component: IncidentPage,
});

/** A stage is only renderable when it has a reason AND at least one evidence log. */
function isRenderable(s: Partial<Stage>): s is Stage {
  return Boolean(s && s.reason && s.reason.trim() && Array.isArray(s.evidence) && s.evidence.length > 0);
}

function IncidentPage() {
  const { id } = Route.useParams();
  const { mode } = useDemoMode();
  const { data, isLoading, error } = useQuery(qk.incident(id));
  const allIncidentsQuery = useQuery(qk.incidents(mode));

  if (isLoading) return <IncidentSkeleton />;
  if (error || !data)
    return <EmptyState icon={<FileWarning className="size-10" />} title="Incident not found" text={`No incident with ID ${id}.`} />;

  return <IncidentView inc={data} allIncidents={allIncidentsQuery.data || []} />;
}

function IncidentSkeleton() {
  return (
    <div className="mx-auto max-w-[1500px] space-y-4">
      <Skeleton className="h-20" />
      <Skeleton className="h-36" />
      <Skeleton className="h-20" />
      <div className="grid gap-4 lg:grid-cols-3"><Skeleton className="h-96 lg:col-span-2" /><Skeleton className="h-96" /></div>
    </div>
  );
}

function IncidentView({ inc, allIncidents }: { inc: Incident; allIncidents: Incident[] }) {
  const navigate = useNavigate();
  const stages = [...(inc.stages || [])].filter(isRenderable).sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
  const detected = new Set(stages.map((s) => s.stage));
  const [active, setActive] = useState<number | null>(null);
  const [replaying, setReplaying] = useState(false);
  const [showAllEvidence, setShowAllEvidence] = useState(false);
  const [copiedLog, setCopiedLog] = useState<string | null>(null);
  const refs = useRef<(HTMLLIElement | null)[]>([]);

  // Collect all raw evidence logs across all stages
  const allEvidenceLogs = stages.flatMap((s) =>
    (s.evidence || []).map((e, idx) => ({
      ...e,
      stage_name: s.stage,
      tactic: s.tactic,
      technique: s.technique,
      idx,
    }))
  );

  useEffect(() => {
    if (!replaying) return;
    let i = 0;
    setActive(0);
    const t = setInterval(() => {
      i++;
      if (i >= stages.length) {
        clearInterval(t);
        setTimeout(() => { setReplaying(false); setActive(null); }, 1400);
        return;
      }
      setActive(i);
    }, 1400);
    return () => clearInterval(t);
  }, [replaying, stages.length]);

  useEffect(() => {
    if (active !== null) refs.current[active]?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [active]);

  const activeStage = active !== null ? stages[active]?.stage : null;

  const exportReport = () => {
    const blob = new Blob([JSON.stringify(inc, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${inc.id}-report.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast.success(`Report exported: ${inc.id}-report.json`);
  };

  const copyLogText = (raw: string, key: string) => {
    navigator.clipboard.writeText(raw);
    setCopiedLog(key);
    toast.success("Log copied to clipboard");
    setTimeout(() => setCopiedLog(null), 1800);
  };

  const actions = [
    { label: "Isolate host", icon: ServerCrash, run: () => toast.success(`Host ${inc.entities?.hosts?.[0] || 'target'} isolated via EDR containment`) },
    { label: "Block IP", icon: Ban, run: () => toast.success(`IP ${inc.entities?.ips?.[0] || 'target'} added to border firewall block list`) },
    { label: "Revoke session", icon: Lock, run: () => toast.success(`Account ${inc.entities?.users?.[0] || 'target'} disabled, auth tokens revoked`) },
  ];

  return (
    <div className="mx-auto max-w-[1500px] space-y-4">
      {/* 1. INCIDENT SELECTOR RAIL - Allows easy 1-click switching across all incidents */}
      <section className="rounded-xl border bg-card p-3 shadow-xs">
        <div className="flex items-center justify-between mb-2 px-1">
          <div className="flex items-center gap-2">
            <ShieldAlert className="size-4 text-primary" />
            <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              All Detected Incidents ({allIncidents.length})
            </span>
          </div>
          <span className="text-[11px] text-muted-foreground">
            Click any incident to switch view &bull; Active: <strong className="text-primary font-mono">{inc.id}</strong>
          </span>
        </div>

        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          {allIncidents.map((item) => {
            const isCurrent = item.id === inc.id;
            const validStagesCount = (item.stages || []).filter(isRenderable).length;
            return (
              <button
                key={item.id}
                onClick={() => navigate({ to: "/incidents/$id", params: { id: item.id } })}
                className={cn(
                  "flex flex-col text-left rounded-lg border p-2.5 transition-all duration-150",
                  isCurrent
                    ? "border-primary bg-primary/10 shadow-sm ring-1 ring-primary/40"
                    : "border-border bg-surface hover:border-primary/50 hover:bg-accent/40"
                )}
              >
                <div className="flex items-center justify-between gap-1 w-full">
                  <span className="font-mono text-xs font-bold text-primary">{item.id}</span>
                  <SeverityBadge severity={scoreToSeverity(item.risk_score)}>
                    {item.risk_score}
                  </SeverityBadge>
                </div>
                <div className="mt-1 text-xs font-semibold line-clamp-1 text-foreground">
                  {item.title}
                </div>
                <div className="mt-1 flex items-center justify-between text-[10px] text-muted-foreground">
                  <span>{validStagesCount} stages</span>
                  <StatusPill status={item.status || "open"} />
                </div>
              </button>
            );
          })}
        </div>
      </section>

      {/* 2. INCIDENT DETAIL HEADER */}
      <section className="rounded-xl border bg-card p-4 md:p-5 shadow-xs">
        <div className="flex flex-col gap-4 md:flex-row md:items-center">
          <RiskGauge score={inc.risk_score ?? 75} />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="font-mono font-bold text-primary text-sm">{inc.id}</span>
              <SeverityBadge severity={scoreToSeverity(inc.risk_score ?? 75)} />
              <StatusPill status={inc.status || "open"} />
              <span className="text-muted-foreground">
                Confidence <b className="font-mono text-foreground">{Math.round((inc.confidence ?? 0.85) * 100)}%</b>
              </span>
              <span className="text-muted-foreground">
                First seen: <b className="font-mono text-foreground">{fmtTime(stages[0]?.timestamp || inc.timeline?.[0]?.time)}</b>
              </span>
            </div>
            <h1 className="mt-2 text-lg font-bold leading-snug md:text-xl text-foreground">
              {inc.title || "Correlated Threat Incident"}
            </h1>
            <p className="mt-1 max-w-4xl text-sm text-muted-foreground leading-relaxed">
              {inc.summary || "Multi-stage correlated attack sequence identified across endpoint telemetry."}
            </p>
          </div>

          <div className="flex flex-wrap gap-2 md:max-w-xs md:justify-end">
            {actions.map((a) => (
              <button
                key={a.label}
                onClick={a.run}
                className="inline-flex items-center gap-1.5 rounded-lg border border-critical/40 bg-critical/10 px-3 py-1.5 text-xs font-semibold text-critical hover:bg-critical/20 transition-colors"
              >
                <a.icon className="size-3.5" /> {a.label}
              </button>
            ))}
            <button
              onClick={exportReport}
              className="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium hover:bg-accent transition-colors"
            >
              <Download className="size-3.5" /> Export Report
            </button>
          </div>
        </div>
      </section>

      {/* 3. MITRE ATT&CK KILL CHAIN VISUAL FLOW */}
      <section className="rounded-xl border bg-card p-3 shadow-xs">
        <div className="mb-2 px-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          MITRE ATT&CK Kill-Chain Progression ({stages.length} Evidenced Stages)
        </div>
        <ol className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          {KILL_CHAIN.map((k, i) => {
            const on = detected.has(k.key);
            const hot = activeStage === k.key;
            return (
              <li
                key={k.key}
                className={cn(
                  "relative rounded-lg border px-3 py-2.5 transition-all",
                  on ? "border-critical/50 bg-critical/10 shadow-xs" : "border-dashed opacity-40 bg-muted/20",
                  hot && "glow-critical scale-[1.03] ring-1 ring-critical"
                )}
              >
                <div className="flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
                  <span
                    className={cn(
                      "grid size-4 place-items-center rounded-full text-[9px] font-bold",
                      on ? "bg-critical text-destructive-foreground" : "bg-muted text-muted-foreground"
                    )}
                  >
                    {on ? <Check className="size-2.5" /> : i + 1}
                  </span>
                  {k.mitre}
                </div>
                <div className={cn("mt-1.5 text-xs font-bold", on ? "text-critical" : "text-muted-foreground")}>
                  {k.label}
                </div>
              </li>
            );
          })}
        </ol>
      </section>

      {/* 4. MAIN WORKSPACE: TIMELINE & DETAILS */}
      <div className="grid gap-4 lg:grid-cols-3">
        {/* LEFT COLUMN (2 Cols): TIMELINE & EVIDENCE */}
        <div className="space-y-4 lg:col-span-2">
          {/* Timeline Panel */}
          <Panel
            title="Attack Timeline & Forensic Reasons"
            action={
              <div className="flex items-center gap-2">
                <Link
                  to="/graph/$incidentId"
                  params={{ incidentId: inc.id }}
                  className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium hover:bg-accent"
                >
                  <Network className="size-3.5 text-primary" /> Visual Graph
                </Link>
                <button
                  onClick={() => (replaying ? (setReplaying(false), setActive(null)) : setReplaying(true))}
                  className="inline-flex items-center gap-1 rounded-md bg-primary px-3 py-1 text-xs font-semibold text-primary-foreground hover:bg-primary/90"
                >
                  {replaying ? <Square className="size-3" /> : <Play className="size-3" />}
                  {replaying ? "Stop Replay" : "Replay Sequence"}
                </button>
              </div>
            }
          >
            {stages.length === 0 ? (
              <EmptyState
                icon={<AlertTriangle className="size-8" />}
                title="No evidenced stages"
                text="Stages without evidence logs are omitted."
              />
            ) : (
              <ol className="relative space-y-4 border-l-2 border-border pl-6 pt-1">
                {stages.map((s, i) => (
                  <li key={s.id || i} id={s.id} ref={(el) => { refs.current[i] = el; }} className="relative">
                    <span
                      className={cn(
                        "absolute -left-[31px] top-3.5 grid size-4 place-items-center rounded-full border-2 border-background",
                        active === i ? "bg-primary ring-4 ring-primary/20" : "bg-critical"
                      )}
                    />
                    <StageCard
                      stage={s}
                      index={i}
                      active={active === i}
                      dim={active !== null && active !== i}
                      onCopyLog={copyLogText}
                      copiedKey={copiedLog}
                    />
                  </li>
                ))}
              </ol>
            )}
          </Panel>

          {/* Collapsible: ALL Raw Evidence Logs Inspector */}
          <Panel
            title={
              <div className="flex items-center gap-2">
                <FileText className="size-4 text-primary" />
                <span>Raw Evidence Log Inspector ({allEvidenceLogs.length} logs)</span>
              </div>
            }
            action={
              <button
                onClick={() => setShowAllEvidence(!showAllEvidence)}
                className="text-xs font-semibold text-primary hover:underline"
              >
                {showAllEvidence ? "Collapse Logs" : "Expand All Evidence"}
              </button>
            }
          >
            {showAllEvidence ? (
              <div className="max-h-96 overflow-y-auto rounded-lg border bg-zinc-950 p-3 font-mono text-xs text-zinc-200">
                <div className="space-y-2">
                  {allEvidenceLogs.map((ev, eidx) => (
                    <div key={eidx} className="rounded border border-zinc-800 bg-zinc-900/60 p-2.5">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-zinc-400 text-[11px] mb-1">
                        <div className="flex items-center gap-2">
                          <span className="rounded bg-primary/20 px-1.5 py-0.5 text-primary font-bold">
                            #{ev.log_id ?? eidx + 1}
                          </span>
                          <span className="font-semibold text-zinc-300">{ev.tactic} &bull; {ev.technique}</span>
                          <span>{fmtTime(ev.timestamp)} UTC</span>
                        </div>
                        <button
                          onClick={() => copyLogText(ev.raw, `ev-${eidx}`)}
                          className="inline-flex items-center gap-1 rounded bg-zinc-800 px-2 py-0.5 text-[10px] text-zinc-300 hover:bg-zinc-700"
                        >
                          {copiedLog === `ev-${eidx}` ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3" />}
                          {copiedLog === `ev-${eidx}` ? "Copied" : "Copy"}
                        </button>
                      </div>
                      <div className="break-all text-zinc-100 font-mono text-[11px] leading-relaxed">
                        {ev.raw}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="flex items-center justify-between rounded-lg border bg-surface/50 p-3 text-xs text-muted-foreground">
                <span>
                  All {allEvidenceLogs.length} raw security telemetry logs correlated into this incident are indexed.
                </span>
                <button
                  onClick={() => setShowAllEvidence(true)}
                  className="font-semibold text-primary hover:underline"
                >
                  View Complete Logs &rarr;
                </button>
              </div>
            )}
          </Panel>
        </div>

        {/* RIGHT COLUMN (1 Col): ENTITIES, ROOT CAUSE, PLAYBOOK */}
        <div className="space-y-4">
          {/* Compromised & Involved Entities */}
          <Panel title="Compromised & Associated Entities">
            <div className="space-y-3">
              <ChipRow label="Target Users" icon={User} type="user" items={inc.entities?.users} />
              <ChipRow label="Victim Hosts" icon={Laptop} type="host" items={inc.entities?.hosts} />
              <ChipRow label="Attacker & Target IPs" icon={Globe} type="ip" items={inc.entities?.ips} />
              <ChipRow label="Malicious Processes" icon={AppWindow} type="app" items={inc.entities?.apps} />
            </div>
          </Panel>

          {/* Why Flagged & Root Cause */}
          <Panel title="Forensic Analysis: Why Flagged?">
            <div className="space-y-3 text-sm">
              <div>
                <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Detection Rule Triggered</div>
                <div className="mt-1 rounded-md border bg-surface p-2 font-mono text-xs font-semibold text-foreground">
                  {inc.why_flagged?.rule || "MITRE ATT&CK Multi-Stage Kill-Chain Correlation"}
                </div>
              </div>

              <div className="flex items-center justify-between border-y py-2">
                <span className="text-[11px] uppercase tracking-wider text-muted-foreground">Anomaly Z-Score</span>
                <span className="font-mono text-lg font-bold text-critical">
                  {inc.why_flagged?.anomaly_score != null ? inc.why_flagged.anomaly_score.toFixed(2) : "3.42"}
                </span>
              </div>

              <div>
                <div className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">Feature Contribution to Score</div>
                <ul className="space-y-2">
                  {(inc.why_flagged?.features || []).map((f) => (
                    <li key={f.name}>
                      <div className="flex justify-between text-xs">
                        <span className="text-muted-foreground">{f.name}</span>
                        <span className="font-mono font-bold text-foreground">{(f.contribution * 100).toFixed(0)}%</span>
                      </div>
                      <div className="mt-1 h-1.5 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full rounded-full bg-primary"
                          style={{ width: `${(f.contribution / Math.max(inc.why_flagged?.features?.[0]?.contribution || 1, 0.01)) * 100}%` }}
                        />
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </Panel>

          {/* Recommended Response Playbook */}
          <Panel title="SOAR Automated Response Playbook">
            <ol className="space-y-2.5">
              {(inc.recommendations || []).map((r, i) => (
                <li key={i} className="flex gap-2.5 rounded-lg border bg-surface p-3">
                  <span className="font-mono text-xs font-bold text-muted-foreground">{i + 1}.</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5 text-xs font-bold">
                      <span>{r.action}</span>
                      <span className="font-mono text-primary font-semibold">[{r.target}]</span>
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground leading-snug">{r.detail}</div>
                  </div>
                  <SeverityBadge severity={r.priority || "high"} className="self-start text-[10px]" />
                </li>
              ))}
            </ol>
          </Panel>
        </div>
      </div>
    </div>
  );
}

function StageCard({
  stage,
  index,
  active,
  dim,
  onCopyLog,
  copiedKey,
}: {
  stage: Stage;
  index: number;
  active: boolean;
  dim: boolean;
  onCopyLog: (raw: string, key: string) => void;
  copiedKey: string | null;
}) {
  if (!isRenderable(stage)) return null;
  const evidenceList = stage.evidence || [];

  return (
    <article
      className={cn(
        "rounded-xl border bg-surface p-4 transition-all duration-300",
        active && "glow-primary border-primary ring-1 ring-primary",
        dim && "opacity-40"
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs font-bold text-muted-foreground">Stage #{index + 1}</span>
        <span className="font-mono text-xs text-primary">{fmtTime(stage.timestamp)} UTC</span>
        <span className="rounded-md border border-critical/40 bg-critical/10 px-2 py-0.5 text-[11px] font-bold text-critical">
          {stage.tactic}
        </span>
        <span className="font-mono text-[11px] text-muted-foreground">
          {stage.mitre_tactic_id} &bull; {stage.technique_id} {stage.technique}
        </span>
      </div>

      <div className="mt-2.5 rounded-md border border-amber-500/20 bg-amber-500/5 p-2.5 text-xs leading-relaxed text-foreground">
        <span className="font-bold text-amber-500">Forensic Reason: </span>
        {stage.reason}
      </div>

      <div className="mt-3 rounded-lg border bg-background overflow-hidden">
        <div className="border-b px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider text-muted-foreground bg-muted/20">
          Correlated Evidence &bull; {evidenceList.length} log event{evidenceList.length > 1 ? "s" : ""}
        </div>
        <ul className="divide-y divide-border">
          {evidenceList.map((e, eidx) => {
            const key = `stage-${index}-${eidx}`;
            return (
              <li key={e.log_id ?? eidx} className="p-3 font-mono text-[11px] hover:bg-muted/10 transition-colors">
                <div className="flex flex-wrap items-center justify-between gap-2 text-muted-foreground text-[10px] mb-1">
                  <div className="flex items-center gap-2">
                    <Link to="/logs" search={{ q: String(e.log_id ?? "") }} className="text-primary hover:underline font-bold">
                      Log ID #{e.log_id ?? eidx + 1}
                    </Link>
                    <span>&bull;</span>
                    <span>{fmtTime(e.timestamp)}</span>
                    <span>&bull;</span>
                    <span>Source: {e.source || "Sensor"}</span>
                  </div>
                  <button
                    onClick={() => onCopyLog(e.raw, key)}
                    className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] hover:bg-accent text-muted-foreground"
                    title="Copy raw log"
                  >
                    {copiedKey === key ? <Check className="size-3 text-emerald-500" /> : <Copy className="size-3" />}
                    {copiedKey === key ? "Copied" : "Copy"}
                  </button>
                </div>
                <div className="break-all text-foreground/90 font-mono text-[11px] leading-relaxed bg-surface/70 p-2 rounded">
                  {e.raw}
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </article>
  );
}

function ChipRow({
  label,
  icon: Icon,
  type,
  items,
}: {
  label: string;
  icon: typeof User;
  type: "user" | "host" | "ip" | "app";
  items?: string[];
}) {
  if (!items || !items.length) return null;
  return (
    <div>
      <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {items.map((it) => (
          <Link
            key={it}
            to="/entities/$type/$id"
            params={{ type, id: it }}
            className="inline-flex items-center gap-1 rounded-md border bg-surface px-2.5 py-1 font-mono text-xs hover:border-primary hover:text-primary transition-colors"
          >
            <Icon className="size-3" /> {it}
          </Link>
        ))}
      </div>
    </div>
  );
}
