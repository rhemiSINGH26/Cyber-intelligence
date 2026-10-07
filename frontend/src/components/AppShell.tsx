import { useState, useEffect, type ReactNode, type FormEvent } from "react";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  BarChart3,
  LayoutDashboard,
  LayoutGrid,
  Network,
  ScrollText,
  Search,
  ShieldAlert,
  X,
  Sparkles,
  CheckCircle2,
  Bot,
  Laptop,
} from "lucide-react";
import { useDemoMode } from "@/lib/demo";
import { cn } from "@/lib/utils";
import { SocCopilot } from "./SocCopilot";

export interface OdooApp {
  id: string;
  label: string;
  title: string;
  description: string;
  to?: string;
  params?: Record<string, string>;
  icon: typeof LayoutDashboard;
  gradient: string;
  badge?: string;
  isAction?: boolean;
}

export const ODOO_APPS: OdooApp[] = [
  {
    id: "dashboard",
    label: "Dashboard",
    title: "SOC Dashboard",
    description: "Live attack feed, risk score overview & SOC alert queue",
    to: "/",
    icon: LayoutDashboard,
    gradient: "from-blue-600 via-indigo-600 to-indigo-800",
    badge: "Live",
  },
  {
    id: "incidents",
    label: "Incidents",
    title: "Incident Center",
    description: "Kill-chain reconstruction, MITRE stages & SOAR playbooks",
    to: "/incidents/$id",
    params: { id: "INC-001" },
    icon: ShieldAlert,
    gradient: "from-rose-600 via-red-600 to-rose-800",
    badge: "Attacks (5)",
  },
  {
    id: "graph",
    label: "Attack Graph",
    title: "Attack Graph Studio",
    description: "Multi-hop entity interaction & lateral movement graph",
    to: "/graph/$incidentId",
    params: { incidentId: "INC-001" },
    icon: Network,
    gradient: "from-cyan-600 via-teal-600 to-emerald-800",
    badge: "Interactive",
  },
  {
    id: "logs",
    label: "Log Explorer",
    title: "Log Explorer",
    description: "Raw security telemetry, universal search & log ingest",
    to: "/logs",
    icon: ScrollText,
    gradient: "from-amber-500 via-orange-600 to-amber-700",
    badge: "95k Logs",
  },
  {
    id: "entities",
    label: "Entities",
    title: "All Entities Directory",
    description: "Unified directory of users, hosts, IPs, apps with baseline deviations",
    to: "/entities/$type/$id",
    params: { type: "all", id: "directory" },
    icon: Activity,
    gradient: "from-emerald-600 via-teal-600 to-green-800",
    badge: "Directory (96+)",
  },
  {
    id: "fleet",
    label: "Endpoint Fleet",
    title: "Endpoint Fleet & Nodes",
    description: "Live multi-laptop telemetry, custom nodes & log streaming",
    to: "/fleet",
    icon: Laptop,
    gradient: "from-cyan-600 via-teal-600 to-emerald-800",
    badge: "Live Telemetry",
  },
  {
    id: "metrics",
    label: "Metrics",
    title: "Benchmark & Rules",
    description: "Detection accuracy, 0% FPR benchmark & MITRE ATT&CK matrix",
    to: "/metrics",
    icon: BarChart3,
    gradient: "from-violet-600 via-purple-600 to-fuchsia-800",
    badge: "0% FPR",
  },
  {
    id: "copilot",
    label: "SOC AI Copilot",
    title: "SOC AI Copilot",
    description: "Ask questions & query attack intelligence with Groq LLM",
    icon: Bot,
    gradient: "from-fuchsia-600 via-pink-600 to-rose-700",
    badge: "Groq Qwen 2.5",
    isAction: true,
  },
];

export function AppShell({ children }: { children: ReactNode }) {
  const [appsOpen, setAppsOpen] = useState(false);
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [filterQuery, setFilterQuery] = useState("");
  const { mode, setMode } = useDemoMode();
  const navigate = useNavigate();
  const routerState = useRouterState();
  const currentPath = routerState.location.pathname;

  const [searchLog, setSearchLog] = useState("");
  const submitSearch = (e: FormEvent) => {
    e.preventDefault();
    if (searchLog.trim()) {
      navigate({ to: "/logs", search: { q: searchLog.trim() } });
    }
  };

  // Keyboard shortcut: Escape closes apps launcher
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && appsOpen) {
        setAppsOpen(false);
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [appsOpen]);

  // Determine current active app for header breadcrumb
  const activeApp =
    ODOO_APPS.find((app) => {
      if (app.to === "/" && currentPath === "/") return true;
      if (app.to && app.to !== "/" && currentPath.startsWith(app.to.split("/$")[0])) return true;
      return false;
    }) || ODOO_APPS[0];

  const filteredApps = ODOO_APPS.filter(
    (app) =>
      app.label.toLowerCase().includes(filterQuery.toLowerCase()) ||
      app.title.toLowerCase().includes(filterQuery.toLowerCase()) ||
      app.description.toLowerCase().includes(filterQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col">
      {/* Top Header - Odoo Style Header */}
      <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-card/95 px-4 backdrop-blur shadow-sm">
        {/* Odoo 9-dots App Launcher Button */}
        <button
          onClick={() => {
            setAppsOpen(!appsOpen);
            setFilterQuery("");
          }}
          className={cn(
            "group flex items-center gap-2 rounded-lg p-2 transition-all",
            appsOpen
              ? "bg-primary text-primary-foreground shadow-md ring-2 ring-primary/40"
              : "hover:bg-accent text-foreground hover:text-primary"
          )}
          title="Odoo App Launcher"
          aria-label="Toggle Odoo Apps Menu"
        >
          <LayoutGrid className="size-5 transition-transform group-hover:scale-110" />
          <span className="hidden sm:inline text-xs font-semibold tracking-wide uppercase">Apps</span>
        </button>

        <div className="h-5 w-[1px] bg-border" />

        {/* Brand & Active App Breadcrumb */}
        <div className="flex items-center gap-2">
          <Link to="/" className="flex items-center gap-2 font-bold tracking-tight text-foreground hover:opacity-90">
            <div className="grid size-7 place-items-center rounded-lg bg-primary/20 text-primary border border-primary/40 glow-primary">
              <ShieldAlert className="size-4" />
            </div>
            <span className="font-semibold text-sm tracking-tight hidden md:inline">ThreatLens</span>
          </Link>

          <span className="text-muted-foreground/50 text-sm hidden sm:inline">/</span>

          {/* Current Active App Indicator */}
          <div className="flex items-center gap-1.5 rounded-md bg-surface px-2.5 py-1 text-xs font-medium border border-border">
            <activeApp.icon className="size-3.5 text-primary" />
            <span className="font-semibold text-foreground">{activeApp.label}</span>
          </div>
        </div>

        {/* Search Bar */}
        <form onSubmit={submitSearch} className="relative ml-auto max-w-xs flex-1 hidden sm:block">
          <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            value={searchLog}
            onChange={(e) => setSearchLog(e.target.value)}
            placeholder="Search security telemetry..."
            className="h-8 w-full rounded-md border border-border bg-surface pl-8 pr-3 text-xs outline-none placeholder:text-muted-foreground focus:border-primary transition-all"
          />
        </form>

        {/* Right Section: Ask Groq Button, Demo Mode Switcher & Status */}
        <div className="flex items-center gap-2.5 ml-auto sm:ml-0">
          {/* Direct Groq Copilot Quick Button in Header */}
          <button
            onClick={() => setCopilotOpen(true)}
            className="flex items-center gap-1.5 rounded-md border border-primary/40 bg-primary/10 hover:bg-primary/20 text-primary px-2.5 py-1 text-xs font-semibold transition-all shadow-sm"
            title="Ask Groq AI about detected attacks"
          >
            <Sparkles className="size-3.5" />
            <span className="hidden md:inline">Ask AI</span>
          </button>

          <div className="flex rounded-md border border-border bg-surface p-0.5 text-xs">
            <button
              onClick={() => setMode("attack")}
              className={cn(
                "rounded px-2.5 py-1 text-[11px] font-medium transition-colors",
                mode === "attack"
                  ? "bg-critical/20 text-critical font-semibold"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              Attack data
            </button>
            <button
              onClick={() => setMode("clean")}
              className={cn(
                "rounded px-2.5 py-1 text-[11px] font-medium transition-colors",
                mode === "clean"
                  ? "bg-low/20 text-low font-semibold"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              Clean <span className="hidden sm:inline">(benign)</span>
            </button>
          </div>

          <div className="hidden xl:flex items-center gap-1.5 text-[11px] font-mono text-muted-foreground bg-surface border border-border rounded-md px-2.5 py-1">
            <span className="size-2 rounded-full bg-low animate-pulse" />
            <span>42 Sensors</span>
          </div>
        </div>
      </header>

      {/* Odoo-Style Fullscreen / Overlay App Launcher Modal */}
      {appsOpen && (
        <div className="fixed inset-0 z-50 flex flex-col bg-background/90 backdrop-blur-xl animate-in fade-in-0 duration-200">
          {/* App Switcher Header */}
          <div className="flex h-16 items-center justify-between border-b border-border/80 px-6 sm:px-12 bg-card/60 backdrop-blur-md">
            <div className="flex items-center gap-3">
              <div className="grid size-9 place-items-center rounded-xl bg-primary text-primary-foreground shadow-lg shadow-primary/20">
                <LayoutGrid className="size-5" />
              </div>
              <div>
                <h2 className="text-base font-bold tracking-tight text-foreground flex items-center gap-2">
                  ThreatLens Applications
                  <span className="text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded-full bg-primary/20 text-primary border border-primary/30">
                    Odoo Style
                  </span>
                </h2>
                <p className="text-xs text-muted-foreground">Select a security intelligence module or ask Groq AI</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {/* Instant App Filter */}
              <div className="relative w-64 sm:w-80">
                <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <input
                  autoFocus
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  placeholder="Type to filter apps..."
                  className="h-10 w-full rounded-xl border border-border bg-surface pl-9 pr-4 text-sm outline-none placeholder:text-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all shadow-inner"
                />
              </div>

              <button
                onClick={() => setAppsOpen(false)}
                className="grid size-10 place-items-center rounded-xl border border-border bg-surface text-muted-foreground hover:bg-accent hover:text-foreground transition-colors shadow-sm"
                aria-label="Close apps launcher"
              >
                <X className="size-5" />
              </button>
            </div>
          </div>

          {/* Odoo App Tiles Grid */}
          <div className="flex-1 overflow-y-auto px-6 py-12 sm:px-12 max-w-6xl mx-auto w-full flex flex-col justify-center">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-6 sm:gap-8">
              {filteredApps.map((app) => {
                const isCurrent = activeApp.id === app.id;

                if (app.isAction) {
                  return (
                    <button
                      key={app.id}
                      onClick={() => {
                        setAppsOpen(false);
                        setCopilotOpen(true);
                      }}
                      className={cn(
                        "group relative flex flex-col items-center p-5 rounded-2xl border transition-all duration-300 text-left",
                        "bg-gradient-to-b from-card/80 to-surface/80 backdrop-blur-sm shadow-lg hover:shadow-2xl hover:-translate-y-1.5",
                        "border-border/80 hover:border-primary/40 ring-1 ring-primary/20"
                      )}
                    >
                      <div
                        className={cn(
                          "grid size-18 sm:size-20 place-items-center rounded-2xl bg-gradient-to-br shadow-xl transition-transform duration-300 group-hover:scale-110",
                          app.gradient
                        )}
                      >
                        <app.icon className="size-9 sm:size-10 text-white drop-shadow-md" />
                      </div>

                      <div className="mt-4 text-center">
                        <div className="text-sm font-bold text-foreground group-hover:text-primary transition-colors flex items-center justify-center gap-1.5">
                          {app.label}
                          <Sparkles className="size-3 text-primary animate-pulse" />
                        </div>
                        <div className="mt-1 text-[11px] text-muted-foreground line-clamp-2 leading-tight">
                          {app.description}
                        </div>
                      </div>

                      {app.badge && (
                        <span className="mt-3 inline-block rounded-md bg-primary/20 text-primary border border-primary/30 px-2 py-0.5 text-[10px] font-mono font-medium shadow-sm">
                          {app.badge}
                        </span>
                      )}
                    </button>
                  );
                }

                return (
                  <Link
                    key={app.id}
                    to={app.to!}
                    {...("params" in app && app.params ? { params: app.params as never } : {})}
                    onClick={() => setAppsOpen(false)}
                    className={cn(
                      "group relative flex flex-col items-center p-5 rounded-2xl border transition-all duration-300",
                      "bg-gradient-to-b from-card/80 to-surface/80 backdrop-blur-sm shadow-lg hover:shadow-2xl hover:-translate-y-1.5",
                      isCurrent
                        ? "border-primary/60 ring-2 ring-primary/40 bg-card"
                        : "border-border/80 hover:border-primary/40"
                    )}
                  >
                    {/* Active Checkmark Pill */}
                    {isCurrent && (
                      <span className="absolute -top-2.5 -right-2.5 flex items-center gap-1 bg-primary text-primary-foreground text-[10px] font-bold px-2 py-0.5 rounded-full shadow-md">
                        <CheckCircle2 className="size-3" /> Active
                      </span>
                    )}

                    {/* App Icon Container - Rich Odoo Style Rounded Icon */}
                    <div
                      className={cn(
                        "grid size-18 sm:size-20 place-items-center rounded-2xl bg-gradient-to-br shadow-xl transition-transform duration-300 group-hover:scale-110",
                        app.gradient
                      )}
                    >
                      <app.icon className="size-9 sm:size-10 text-white drop-shadow-md" />
                    </div>

                    {/* App Title & Subtitle */}
                    <div className="mt-4 text-center">
                      <div className="text-sm font-bold text-foreground group-hover:text-primary transition-colors">
                        {app.label}
                      </div>
                      <div className="mt-1 text-[11px] text-muted-foreground line-clamp-2 leading-tight">
                        {app.description}
                      </div>
                    </div>

                    {/* Badge */}
                    {app.badge && (
                      <span className="mt-3 inline-block rounded-md bg-surface px-2 py-0.5 text-[10px] font-mono font-medium text-muted-foreground border border-border/80">
                        {app.badge}
                      </span>
                    )}
                  </Link>
                );
              })}
            </div>

            {filteredApps.length === 0 && (
              <div className="text-center py-16">
                <p className="text-muted-foreground text-sm">No applications matching "{filterQuery}"</p>
                <button
                  onClick={() => setFilterQuery("")}
                  className="mt-3 text-xs text-primary hover:underline font-semibold"
                >
                  Clear filter
                </button>
              </div>
            )}

            {/* Bottom Keyboard Hint */}
            <div className="mt-12 text-center text-xs text-muted-foreground/60 flex items-center justify-center gap-2">
              <Sparkles className="size-3.5 text-primary" />
              <span>Press <kbd className="rounded border bg-surface px-1.5 py-0.5 font-mono text-[10px]">ESC</kbd> or click anywhere to exit App Switcher</span>
            </div>
          </div>
        </div>
      )}

      {/* Main App Content Canvas - 100% Full Width */}
      <main className="flex-1 w-full max-w-[1700px] mx-auto p-4 md:p-6 lg:p-8">
        {children}
      </main>

      {/* Groq AI SOC Copilot Chatbot */}
      <SocCopilot isOpen={copilotOpen} onClose={() => setCopilotOpen(false)} />
    </div>
  );
}
