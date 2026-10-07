import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useRef, useState, type DragEvent } from "react";
import { toast } from "sonner";
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, FileSearch, Upload, X } from "lucide-react";
import { qk, uploadLogs } from "@/api";
import { useDemoMode } from "@/lib/demo";
import { incidents, KILL_CHAIN, type LogRow } from "@/data/mock";
import { Skeleton } from "@/components/ui/skeleton";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { EmptyState, SeverityBadge, fmtTime } from "@/components/tl";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/logs")({
  validateSearch: (s: Record<string, unknown>): { q?: string | undefined } => ({ q: typeof s["q"] === "string" ? s["q"] : undefined }),
  head: () => ({
    meta: [
      { title: "Log Explorer — ThreatLens" },
      { name: "description", content: "Search, filter and inspect raw security logs mapped to incidents and kill-chain stages." },
      { property: "og:title", content: "Log Explorer — ThreatLens" },
      { property: "og:description", content: "Searchable log table with incident/stage attribution and CSV/JSON upload." },
    ],
  }),
  component: LogsPage,
});

type SortKey = "timestamp" | "id" | "user" | "host" | "severity" | "event_type";
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const PAGE = 25;
const RANGES = { all: 0, "24h": 1, "3d": 3, "7d": 7 } as const;
const NOW = Date.parse("2026-10-07T00:00:00Z");

const stageLabel = (k?: string) => KILL_CHAIN.find((s) => s.key === k)?.label;

function parseFile(text: string, name: string): Partial<LogRow>[] {
  if (name.endsWith(".json")) {
    const j = JSON.parse(text);
    return Array.isArray(j) ? j : [j];
  }
  const [head = "", ...lines] = text.trim().split(/\r?\n/);
  const cols = head.split(",").map((c) => c.trim());
  return lines.filter(Boolean).map((l) => {
    const v = l.split(",");
    return Object.fromEntries(cols.map((c, i) => [c, v[i]?.trim()]));
  });
}

function LogsPage() {
  const { q } = Route.useSearch();
  const navigate = Route.useNavigate();
  const { mode } = useDemoMode();
  const qc = useQueryClient();
  const { data, isLoading } = useQuery(qk.logs(mode));
  const [f, setF] = useState({ range: "all" as keyof typeof RANGES, user: "", host: "", ip: "", event: "", severity: "" });
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "timestamp", dir: -1 });
  const [page, setPage] = useState(0);
  const [sel, setSel] = useState<LogRow | null>(null);
  const [drag, setDrag] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const upload = useMutation({
    mutationFn: uploadLogs,
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["logs"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
      toast.success(`Uploaded ${r.inserted} log rows`);
    },
    onError: () => toast.error("Upload failed"),
  });

  const handleFile = async (file?: File) => {
    if (!file) return;
    if (!/\.(csv|json)$/i.test(file.name)) { toast.error("Only .csv or .json files are supported"); return; }
    try {
      const rows = parseFile(await file.text(), file.name.toLowerCase());
      if (!rows.length) { toast.error("File has no rows"); return; }
      upload.mutate(rows);
    } catch {
      toast.error("Could not parse file");
    }
  };
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDrag(false);
    handleFile(e.dataTransfer.files[0]);
  };

  const opts = useMemo(() => {
    const u = (k: keyof LogRow) => [...new Set((data ?? []).map((r) => String(r[k])))].sort();
    return { user: u("user"), host: u("host"), ip: u("ip"), event: u("event_type") };
  }, [data]);

  const rows = useMemo(() => {
    let r = data ?? [];
    const days = RANGES[f.range];
    if (days) r = r.filter((x) => Date.parse(x.timestamp) >= NOW - days * 864e5);
    if (f.user) r = r.filter((x) => x.user === f.user);
    if (f.host) r = r.filter((x) => x.host === f.host);
    if (f.ip) r = r.filter((x) => x.ip === f.ip);
    if (f.event) r = r.filter((x) => x.event_type === f.event);
    if (f.severity) r = r.filter((x) => x.severity === f.severity);
    if (q) {
      const s = q.toLowerCase();
      r = r.filter((x) => `${x.id} ${x.user} ${x.host} ${x.ip} ${x.message} ${x.event_type} ${x.incident_id ?? ""}`.toLowerCase().includes(s));
    }
    const { key, dir } = sort;
    return [...r].sort((a, b) => {
      const av = key === "severity" ? SEV_RANK[a.severity] : a[key];
      const bv = key === "severity" ? SEV_RANK[b.severity] : b[key];
      return (av > bv ? 1 : av < bv ? -1 : 0) * dir;
    });
  }, [data, f, q, sort]);

  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const cur = Math.min(page, pages - 1);
  const slice = rows.slice(cur * PAGE, cur * PAGE + PAGE);
  const set = (k: keyof typeof f, v: string) => { setF((p) => ({ ...p, [k]: v })); setPage(0); };
  const th = (k: SortKey, label: string) => (
    <th className="px-3 py-2 font-medium">
      <button onClick={() => setSort((s) => ({ key: k, dir: s.key === k ? (s.dir === 1 ? -1 : 1) : -1 }))} className="inline-flex items-center gap-1 hover:text-foreground">
        {label} {sort.key === k && (sort.dir === 1 ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" />)}
      </button>
    </th>
  );
  const selectCls = "h-8 rounded-md border bg-surface px-2 text-xs min-w-0";

  return (
    <div className="mx-auto max-w-[1500px] space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Log Explorer</h1>
          <p className="text-sm text-muted-foreground">{rows.length.toLocaleString()} of {(data?.length ?? 0).toLocaleString()} rows</p>
        </div>
        <div
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={onDrop}
          onClick={() => fileRef.current?.click()}
          className={cn("flex cursor-pointer items-center gap-2 rounded-md border border-dashed px-4 py-2 text-xs transition-colors", drag ? "border-primary bg-primary/10 text-primary" : "hover:border-primary")}
        >
          <Upload className="size-4" />
          {upload.isPending ? "Uploading…" : "Upload CSV / JSON — click or drop"}
          <input ref={fileRef} type="file" accept=".csv,.json" hidden onChange={(e) => { handleFile(e.target.files?.[0]); e.target.value = ""; }} />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 rounded-lg border bg-card p-3 sm:grid-cols-3 lg:grid-cols-7">
        <input
          value={q ?? ""}
          onChange={(e) => { navigate({ search: { q: e.target.value || undefined }, replace: true }); setPage(0); }}
          placeholder="Search…"
          className="col-span-2 h-8 rounded-md border bg-surface px-2 text-xs outline-none focus:border-primary sm:col-span-3 lg:col-span-1"
        />
        <select value={f.range} onChange={(e) => set("range", e.target.value)} className={selectCls} aria-label="Time range">
          <option value="all">All time</option><option value="24h">Last 24h</option><option value="3d">Last 3 days</option><option value="7d">Last 7 days</option>
        </select>
        {(["user", "host", "ip", "event"] as const).map((k) => (
          <select key={k} value={f[k]} onChange={(e) => set(k, e.target.value)} className={selectCls} aria-label={k}>
            <option value="">All {k === "event" ? "events" : `${k}s`}</option>
            {opts[k].map((o) => <option key={o}>{o}</option>)}
          </select>
        ))}
        <select value={f.severity} onChange={(e) => set("severity", e.target.value)} className={selectCls} aria-label="Severity">
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>

      <div className="overflow-hidden rounded-lg border bg-card">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="border-b text-left text-[11px] uppercase tracking-wider text-muted-foreground">
              <tr>
                {th("id", "ID")}{th("timestamp", "Time (UTC)")}{th("user", "User")}{th("host", "Host")}
                <th className="px-3 py-2 font-medium">IP</th>
                {th("event_type", "Event")}{th("severity", "Severity")}
                <th className="px-3 py-2 font-medium">Attribution</th>
              </tr>
            </thead>
            <tbody>
              {isLoading
                ? Array.from({ length: 10 }).map((_, i) => (
                    <tr key={i} className="border-b"><td colSpan={8} className="px-3 py-2"><Skeleton className="h-5" /></td></tr>
                  ))
                : slice.map((r) => (
                    <tr key={r.id} onClick={() => setSel(r)} className={cn("cursor-pointer border-b font-mono last:border-0 hover:bg-accent/50", r.incident_id && "bg-critical/5")}>
                      <td className="px-3 py-2 text-muted-foreground">{r.id}</td>
                      <td className="whitespace-nowrap px-3 py-2">{fmtTime(r.timestamp)}</td>
                      <td className="px-3 py-2">{r.user}</td>
                      <td className="px-3 py-2">{r.host}</td>
                      <td className="px-3 py-2 text-muted-foreground">{r.ip}</td>
                      <td className="px-3 py-2">{r.event_type}</td>
                      <td className="px-3 py-2"><SeverityBadge severity={r.severity} /></td>
                      <td className="whitespace-nowrap px-3 py-2">
                        {r.incident_id ? (
                          <span className="rounded border border-critical/40 bg-critical/10 px-1.5 py-0.5 text-[10px] text-critical">{r.incident_id} · {stageLabel(r.stage)}</span>
                        ) : (
                          <span className="rounded border border-low/30 px-1.5 py-0.5 text-[10px] text-low">Benign</span>
                        )}
                      </td>
                    </tr>
                  ))}
            </tbody>
          </table>
        </div>
        {!isLoading && rows.length === 0 && <EmptyState icon={<FileSearch className="size-8" />} title="No logs match" text="Try widening the time range or clearing filters." />}
        <div className="flex items-center justify-between border-t px-3 py-2 text-xs text-muted-foreground">
          <span>Page {cur + 1} / {pages}</span>
          <div className="flex gap-1">
            <button disabled={cur === 0} onClick={() => setPage(cur - 1)} className="rounded border p-1 disabled:opacity-40" aria-label="Previous page"><ChevronLeft className="size-4" /></button>
            <button disabled={cur >= pages - 1} onClick={() => setPage(cur + 1)} className="rounded border p-1 disabled:opacity-40" aria-label="Next page"><ChevronRight className="size-4" /></button>
          </div>
        </div>
      </div>

      <Sheet open={!!sel} onOpenChange={(o) => !o && setSel(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-md">
          {sel && (
            <>
              <SheetHeader><SheetTitle className="font-mono">log#{sel.id}</SheetTitle></SheetHeader>
              <div className="space-y-4 px-4 pb-6 text-sm">
                <div className="flex gap-2"><SeverityBadge severity={sel.severity} />{sel.incident_id ? <SeverityBadge severity="critical">{sel.incident_id}</SeverityBadge> : <SeverityBadge severity="low">Benign</SeverityBadge>}</div>
                <dl className="grid grid-cols-3 gap-y-2 font-mono text-xs">
                  {([["Time", fmtTime(sel.timestamp)], ["User", sel.user], ["Host", sel.host], ["IP", sel.ip], ["Event", sel.event_type], ["Source", sel.source]] as const).map(([k, v]) => (
                    <div key={k} className="contents"><dt className="text-muted-foreground">{k}</dt><dd className="col-span-2 break-all">{v}</dd></div>
                  ))}
                </dl>
                <pre className="whitespace-pre-wrap break-all rounded-md border bg-background p-3 font-mono text-[11px]">{sel.message}</pre>
                {sel.incident_id && (
                  <Link to="/incidents/$id" params={{ id: sel.incident_id }} hash={incidents.find((i) => i.id === sel.incident_id)?.stages.find((s) => s.stage === sel.stage)?.id ?? ""} className="block rounded-md bg-primary px-3 py-2 text-center text-xs font-semibold text-primary-foreground">
                    Open {sel.incident_id} · {stageLabel(sel.stage)} stage →
                  </Link>
                )}
                <Link to="/entities/$type/$id" params={{ type: "user", id: sel.user }} className="block text-xs text-primary hover:underline">View {sel.user} profile →</Link>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
