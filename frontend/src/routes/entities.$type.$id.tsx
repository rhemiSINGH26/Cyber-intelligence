import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState, useMemo } from "react";
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
  AlertTriangle,
  AppWindow,
  CheckCircle2,
  Globe,
  Laptop,
  User,
  Search,
  Filter,
  ArrowUpDown,
  LayoutGrid,
  List,
  ShieldAlert,
  Flame,
  ArrowRight,
  ExternalLink,
  ChevronRight,
  Users,
  Server
} from "lucide-react";
import { qk, type EntityType, type EntitySummary } from "@/api";
import { incidents } from "@/data/mock";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState, Panel, RiskGauge, SeverityBadge, StatusPill, scoreToSeverity } from "@/components/tl";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/entities/$type/$id")({
  head: ({ params }) => ({
    meta: [
      { title: `${params.id === "directory" ? "All Entities Directory" : params.id} — Entity Intelligence · ThreatLens` },
      { name: "description", content: `Unified entity directory, behavioral baselines and anomaly profiles for users, hosts, IPs, and applications.` },
    ],
  }),
  component: UnifiedEntitiesPage,
});

const ICON = { user: User, host: Laptop, ip: Globe, app: AppWindow };

function UnifiedEntitiesPage() {
  const { type: paramType, id: paramId } = Route.useParams();
  const navigate = useNavigate();

  // If user navigated to /entities/all/directory or requested directory view
  const isDirectoryInitially = paramType === "all" || paramId === "directory";
  const [viewMode, setViewMode] = useState<"directory" | "profile">(isDirectoryInitially ? "directory" : "profile");

  // Query directory of ALL entities
  const dirQuery = useQuery(qk.entitiesList());

  // Search & Filters in directory
  const [searchTerm, setSearchTerm] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"risk" | "anomalies" | "id">("risk");

  // Current entity for deep profile view
  const resolvedType = (["user", "host", "ip", "app"].includes(paramType) ? paramType : "user") as EntityType;
  const resolvedId = paramId === "directory" ? "sjones" : paramId;
  const entityQuery = useQuery(qk.entity(resolvedType, resolvedId));

  const allEntities = dirQuery.data?.entities || [];

  // Filter & Sort entities
  const filteredEntities = useMemo(() => {
    let list = [...allEntities];
    if (typeFilter !== "all") {
      list = list.filter((e) => e.type === typeFilter);
    }
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      list = list.filter((e) => e.id.toLowerCase().includes(q) || e.display.toLowerCase().includes(q));
    }
    list.sort((a, b) => {
      if (sortBy === "risk") return b.risk - a.risk;
      if (sortBy === "anomalies") return b.anomalous_behaviours - a.anomalous_behaviours;
      return a.id.localeCompare(b.id);
    });
    return list;
  }, [allEntities, typeFilter, searchTerm, sortBy]);

  const stats = dirQuery.data?.stats || {
    total: allEntities.length,
    users: allEntities.filter((e) => e.type === "user").length,
    hosts: allEntities.filter((e) => e.type === "host").length,
    ips: allEntities.filter((e) => e.type === "ip").length,
    apps: allEntities.filter((e) => e.type === "app").length,
    critical_risk: allEntities.filter((e) => e.risk >= 70).length,
  };

  const handleSelectEntity = (eType: EntityType, eId: string) => {
    navigate({ to: "/entities/$type/$id", params: { type: eType, id: eId } });
    setViewMode("profile");
  };

  return (
    <div className="mx-auto max-w-[1500px] space-y-5">
      {/* Top Header & View Mode Switcher */}
      <div className="flex flex-col gap-4 rounded-xl border border-primary/20 bg-gradient-to-r from-card via-card to-primary/5 p-5 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
              SOC Entity Intelligence
            </span>
            <span className="rounded-full bg-primary/10 px-2 py-0.5 font-mono text-[10px] text-primary">
              {allEntities.length} Tracked
            </span>
          </div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight">
            {viewMode === "directory" ? "All Entities Directory" : `Entity Profile: ${resolvedId}`}
          </h1>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {viewMode === "directory"
              ? "Comprehensive inventory of users, hosts, IPs, and applications with baseline deviations and risk scores."
              : `Behavioral baseline vs observed deviations and anomaly score timeline for ${resolvedType} ${resolvedId}.`}
          </p>
        </div>

        {/* View Mode Toggle Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setViewMode("directory")}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-semibold transition-colors",
              viewMode === "directory"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "border bg-surface text-muted-foreground hover:bg-accent"
            )}
          >
            <List className="size-3.5" /> All Entities ({allEntities.length})
          </button>
          <button
            onClick={() => setViewMode("profile")}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-semibold transition-colors",
              viewMode === "profile"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "border bg-surface text-muted-foreground hover:bg-accent"
            )}
          >
            <LayoutGrid className="size-3.5" /> Single Profile ({resolvedId})
          </button>
        </div>
      </div>

      {/* VIEW 1: COMPLETE DIRECTORY OF ALL ENTITIES */}
      {viewMode === "directory" ? (
        <div className="space-y-4">
          {/* KPI Stat Cards */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <div className="rounded-xl border bg-card p-3">
              <span className="text-[11px] uppercase tracking-wider text-muted-foreground">Total Entities</span>
              <div className="mt-1 font-mono text-xl font-bold">{stats.total}</div>
            </div>
            <div className="rounded-xl border bg-card p-3">
              <span className="text-[11px] uppercase tracking-wider text-muted-foreground">Users</span>
              <div className="mt-1 font-mono text-xl font-bold text-sky-500">{stats.users}</div>
            </div>
            <div className="rounded-xl border bg-card p-3">
              <span className="text-[11px] uppercase tracking-wider text-muted-foreground">Hosts & Laptops</span>
              <div className="mt-1 font-mono text-xl font-bold text-emerald-500">{stats.hosts}</div>
            </div>
            <div className="rounded-xl border bg-card p-3">
              <span className="text-[11px] uppercase tracking-wider text-muted-foreground">IP Addresses</span>
              <div className="mt-1 font-mono text-xl font-bold text-indigo-500">{stats.ips}</div>
            </div>
            <div className="rounded-xl border bg-card p-3">
              <span className="text-[11px] uppercase tracking-wider text-muted-foreground">Applications</span>
              <div className="mt-1 font-mono text-xl font-bold text-amber-500">{stats.apps}</div>
            </div>
            <div className="rounded-xl border bg-card p-3">
              <span className="text-[11px] uppercase tracking-wider text-critical">Critical Risk</span>
              <div className="mt-1 font-mono text-xl font-bold text-critical">{stats.critical_risk}</div>
            </div>
          </div>

          {/* Directory Filter & Search Bar */}
          <div className="flex flex-col gap-3 rounded-xl border bg-card p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-wrap items-center gap-1.5">
              {[
                { id: "all", label: `All (${allEntities.length})` },
                { id: "user", label: `Users (${stats.users})` },
                { id: "host", label: `Hosts (${stats.hosts})` },
                { id: "ip", label: `IPs (${stats.ips})` },
                { id: "app", label: `Apps (${stats.apps})` },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setTypeFilter(tab.id)}
                  className={cn(
                    "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                    typeFilter === tab.id
                      ? "bg-primary text-primary-foreground font-semibold"
                      : "text-muted-foreground hover:bg-accent"
                  )}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <div className="relative flex-1 sm:w-64">
                <Search className="absolute left-2.5 top-2 size-3.5 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search entity by name or ID..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="h-8 w-full rounded-md border bg-background pl-8 pr-3 text-xs focus:ring-1 focus:ring-primary"
                />
              </div>

              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="h-8 rounded-md border bg-background px-2 text-xs text-muted-foreground focus:ring-1 focus:ring-primary"
              >
                <option value="risk">Sort: Highest Risk</option>
                <option value="anomalies">Sort: Most Deviations</option>
                <option value="id">Sort: Name (A-Z)</option>
              </select>
            </div>
          </div>

          {/* Entities Table */}
          <div className="rounded-xl border bg-card overflow-hidden shadow-xs">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b bg-muted/40 font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="px-4 py-3">Entity Identifier</th>
                    <th className="px-3 py-3">Type</th>
                    <th className="px-3 py-3">Risk Score</th>
                    <th className="px-3 py-3">Baseline Deviations</th>
                    <th className="px-3 py-3">Associated Incidents</th>
                    <th className="px-3 py-3">Status</th>
                    <th className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {dirQuery.isLoading ? (
                    Array.from({ length: 6 }).map((_, i) => (
                      <tr key={i}>
                        <td colSpan={7} className="p-4">
                          <Skeleton className="h-6 w-full" />
                        </td>
                      </tr>
                    ))
                  ) : filteredEntities.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="p-8 text-center text-muted-foreground">
                        No entities matched your search query or filter.
                      </td>
                    </tr>
                  ) : (
                    filteredEntities.map((ent) => {
                      const TypeIcon = ICON[ent.type] || Globe;
                      const hasIncidents = ent.related_incidents && ent.related_incidents.length > 0;
                      return (
                        <tr
                          key={`${ent.type}:${ent.id}`}
                          className="transition-colors hover:bg-muted/30 cursor-pointer"
                          onClick={() => handleSelectEntity(ent.type, ent.id)}
                        >
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2.5">
                              <span
                                className={cn(
                                  "grid size-8 place-items-center rounded-lg border",
                                  ent.risk >= 70
                                    ? "border-critical/30 bg-critical/10 text-critical"
                                    : "border-border bg-surface text-muted-foreground"
                                )}
                              >
                                <TypeIcon className="size-4" />
                              </span>
                              <div>
                                <div className="font-mono text-xs font-semibold text-foreground">{ent.id}</div>
                                <div className="text-[11px] text-muted-foreground">{ent.display}</div>
                              </div>
                            </div>
                          </td>

                          <td className="px-3 py-3 font-mono text-xs uppercase text-muted-foreground">
                            {ent.type}
                          </td>

                          <td className="px-3 py-3">
                            <div className="flex items-center gap-2">
                              <SeverityBadge severity={scoreToSeverity(ent.risk)}>
                                {ent.risk}
                              </SeverityBadge>
                              <div className="h-1.5 w-14 rounded-full bg-muted overflow-hidden">
                                <div
                                  className={cn(
                                    "h-full rounded-full",
                                    ent.risk >= 70 ? "bg-critical" : ent.risk >= 40 ? "bg-amber-500" : "bg-emerald-500"
                                  )}
                                  style={{ width: `${ent.risk}%` }}
                                />
                              </div>
                            </div>
                          </td>

                          <td className="px-3 py-3 font-mono text-xs">
                            <span
                              className={cn(
                                "font-semibold",
                                ent.anomalous_behaviours > 0 ? "text-critical" : "text-emerald-500"
                              )}
                            >
                              {ent.anomalous_behaviours} of {ent.total_behaviours} anomalous
                            </span>
                          </td>

                          <td className="px-3 py-3">
                            {hasIncidents ? (
                              <div className="flex flex-wrap gap-1">
                                {ent.related_incidents.map((rid) => (
                                  <Link
                                    key={rid}
                                    to="/incidents/$id"
                                    params={{ id: rid }}
                                    onClick={(e) => e.stopPropagation()}
                                    className="rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-primary hover:bg-primary/20"
                                  >
                                    {rid}
                                  </Link>
                                ))}
                              </div>
                            ) : (
                              <span className="text-xs text-muted-foreground">None</span>
                            )}
                          </td>

                          <td className="px-3 py-3">
                            <span
                              className={cn(
                                "rounded-full px-2 py-0.5 font-mono text-[10px] font-bold uppercase",
                                ent.risk >= 70
                                  ? "bg-critical/15 text-critical"
                                  : ent.risk >= 40
                                  ? "bg-amber-500/15 text-amber-500"
                                  : "bg-emerald-500/15 text-emerald-500"
                              )}
                            >
                              {ent.status || (ent.risk >= 70 ? "Critical" : "Normal")}
                            </span>
                          </td>

                          <td className="px-4 py-3 text-right">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleSelectEntity(ent.type, ent.id);
                              }}
                              className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium text-primary hover:bg-accent"
                            >
                              Profile &rarr;
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : (
        /* VIEW 2: INDIVIDUAL ENTITY DEEP PROFILE */
        <IndividualEntityView
          entityType={resolvedType}
          entityId={resolvedId}
          allEntities={allEntities}
          onBackToDirectory={() => setViewMode("directory")}
          onSwitchEntity={(t, id) => {
            navigate({ to: "/entities/$type/$id", params: { type: t, id } });
          }}
        />
      )}
    </div>
  );
}

function IndividualEntityView({
  entityType,
  entityId,
  allEntities,
  onBackToDirectory,
  onSwitchEntity,
}: {
  entityType: EntityType;
  entityId: string;
  allEntities: EntitySummary[];
  onBackToDirectory: () => void;
  onSwitchEntity: (t: EntityType, id: string) => void;
}) {
  const { data, isLoading } = useQuery(qk.entity(entityType, entityId));
  const Icon = ICON[entityType] || User;

  if (isLoading || !data) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-28" />
        <div className="grid gap-4 lg:grid-cols-2">
          <Skeleton className="h-72" />
          <Skeleton className="h-72" />
        </div>
      </div>
    );
  }

  const related = incidents.filter((i) => (data.related_incidents || []).includes(i.id));

  return (
    <div className="space-y-4">
      {/* Quick Nav & Entity Switcher Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-3">
        <button
          onClick={onBackToDirectory}
          className="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium hover:bg-accent transition-colors"
        >
          &larr; Back to All Entities Directory
        </button>

        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground font-medium">Switch Entity:</span>
          <select
            value={`${entityType}:${entityId}`}
            onChange={(e) => {
              const [nextType, nextId] = e.target.value.split(":") as [EntityType, string];
              onSwitchEntity(nextType, nextId);
            }}
            className="h-8 rounded-md border bg-background px-2 font-mono text-xs text-foreground focus:ring-1 focus:ring-primary"
          >
            {allEntities.map((ent) => (
              <option key={`${ent.type}:${ent.id}`} value={`${ent.type}:${ent.id}`}>
                [{ent.type.toUpperCase()}] {ent.id} &bull; Risk {ent.risk}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Entity Profile Card */}
      <section className="flex flex-col gap-4 rounded-xl border bg-card p-5 sm:flex-row sm:items-center">
        <span
          className={cn(
            "grid size-14 place-items-center rounded-xl",
            related.length ? "bg-critical/15 text-critical" : "bg-muted text-muted-foreground"
          )}
        >
          <Icon className="size-7" />
        </span>
        <div className="flex-1">
          <div className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
            {entityType} entity profile
          </div>
          <h2 className="font-mono text-2xl font-bold">{data.display}</h2>
          <div className="mt-1 text-xs text-muted-foreground">
            {data.baseline.filter((b) => b.anomalous).length} of {data.baseline.length} behaviours deviate from baseline
          </div>
        </div>
        <RiskGauge score={data.risk} />
      </section>

      {/* Baseline vs Observed & Anomaly Chart */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Baseline vs Observed Telemetry">
          <div className="-m-4 overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b text-left text-[11px] uppercase tracking-wider text-muted-foreground bg-muted/30">
                <tr>
                  <th className="px-4 py-2 font-medium">Behaviour Metric</th>
                  <th className="px-2 py-2 font-medium">Historical Baseline</th>
                  <th className="px-2 py-2 font-medium">Observed Value</th>
                  <th className="px-4 py-2">Anomaly</th>
                </tr>
              </thead>
              <tbody>
                {data.baseline.map((b) => (
                  <tr key={b.label} className="border-b last:border-0 hover:bg-muted/20">
                    <td className="px-4 py-2.5 text-muted-foreground">{b.label}</td>
                    <td className="px-2 py-2.5 font-mono text-xs">{b.usual}</td>
                    <td className={cn("px-2 py-2.5 font-mono text-xs", b.anomalous && "font-semibold text-critical")}>
                      {b.observed}
                    </td>
                    <td className="px-4 py-2.5">
                      {b.anomalous ? (
                        <AlertTriangle className="size-4 text-critical" />
                      ) : (
                        <CheckCircle2 className="size-4 text-low" />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="Anomaly Score Trend Over Time">
          <div className="h-64">
            <ResponsiveContainer>
              <LineChart data={data.anomaly_series} margin={{ left: -20, right: 8, top: 8 }}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="date" stroke="var(--muted-foreground)" fontSize={11} tickLine={false} />
                <YAxis domain={[0, 1]} stroke="var(--muted-foreground)" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    background: "var(--popover)",
                    border: "1px solid var(--border)",
                    borderRadius: 6,
                    fontSize: 12,
                  }}
                />
                <ReferenceLine
                  y={0.7}
                  stroke="var(--critical)"
                  strokeDasharray="4 4"
                  label={{
                    value: "alert threshold",
                    fill: "var(--critical)",
                    fontSize: 10,
                    position: "insideTopLeft",
                  }}
                />
                <Line type="monotone" dataKey="score" stroke="var(--primary)" strokeWidth={2} dot={{ r: 2 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      {/* Associated Incidents */}
      <Panel title={`Related Correlated Incidents (${related.length})`}>
        {related.length === 0 ? (
          <EmptyState
            icon={<CheckCircle2 className="size-8 text-low" />}
            title="No Correlated Incidents"
            text="This entity isn't currently flagged as part of any attack kill chain."
          />
        ) : (
          <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {related.map((i) => (
              <li key={i.id}>
                <Link
                  to="/incidents/$id"
                  params={{ id: i.id }}
                  className="block rounded-lg border bg-surface p-3.5 hover:border-primary transition-all"
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-primary">{i.id}</span>
                    <SeverityBadge severity={scoreToSeverity(i.risk_score)}>{i.risk_score}</SeverityBadge>
                    <StatusPill status={i.status} />
                  </div>
                  <div className="mt-2 text-sm font-semibold">{i.title}</div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
