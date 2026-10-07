import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import type { LogSeverity, Severity } from "@/data/mock";

export const sevColor: Record<LogSeverity, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--muted-foreground)",
};

const sevClass: Record<LogSeverity, string> = {
  critical: "bg-critical/15 text-critical border-critical/40",
  high: "bg-high/15 text-high border-high/40",
  medium: "bg-medium/15 text-medium border-medium/40",
  low: "bg-low/15 text-low border-low/40",
  info: "bg-muted text-muted-foreground border-border",
};

export function scoreToSeverity(score: number): Severity {
  return score >= 85 ? "critical" : score >= 65 ? "high" : score >= 40 ? "medium" : "low";
}

export function SeverityBadge({ severity, children, className }: { severity: LogSeverity; children?: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wide", sevClass[severity], className)}>
      <span className="size-1.5 rounded-full" style={{ background: sevColor[severity] }} />
      {children ?? severity}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    open: "border-critical/40 text-critical",
    investigating: "border-high/40 text-high",
    contained: "border-primary/40 text-primary",
    resolved: "border-low/40 text-low",
  };
  return <span className={cn("rounded-full border px-2 py-0.5 text-[11px] font-medium capitalize", map[status] ?? "border-border text-muted-foreground")}>{status}</span>;
}

export function Panel({ title, action, children, className }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("rounded-lg border bg-card", className)}>
      {title && (
        <header className="flex items-center justify-between gap-2 border-b px-4 py-2.5">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function StatCard({ label, value, sub, tone = "primary", icon }: { label: string; value: ReactNode; sub?: ReactNode; tone?: "primary" | LogSeverity; icon?: ReactNode }) {
  const color = tone === "primary" ? "var(--primary)" : sevColor[tone];
  return (
    <div className="relative overflow-hidden rounded-lg border bg-card p-4">
      <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: color }} />
      <div className="flex items-center justify-between text-xs font-medium uppercase tracking-wider text-muted-foreground">
        {label}
        <span style={{ color }}>{icon}</span>
      </div>
      <div className="mt-2 font-mono text-2xl font-semibold tabular-nums" style={{ color: tone === "primary" ? undefined : color }}>{value}</div>
      {sub && <div className="mt-1 text-xs text-muted-foreground">{sub}</div>}
    </div>
  );
}

export function EmptyState({ icon, title, text }: { icon?: ReactNode; title: string; text?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center">
      <div className="text-muted-foreground">{icon}</div>
      <div className="text-sm font-medium">{title}</div>
      {text && <p className="max-w-sm text-xs text-muted-foreground">{text}</p>}
    </div>
  );
}

export function RiskGauge({ score, size = 120 }: { score: number; size?: number }) {
  const sev = scoreToSeverity(score);
  const r = 46;
  const c = Math.PI * r;
  return (
    <svg width={size} height={size * 0.62} viewBox="0 0 120 74" role="img" aria-label={`Risk ${score} of 100`}>
      <path d="M14 64 A46 46 0 0 1 106 64" fill="none" stroke="var(--muted)" strokeWidth="10" strokeLinecap="round" />
      <path d="M14 64 A46 46 0 0 1 106 64" fill="none" stroke={sevColor[sev]} strokeWidth="10" strokeLinecap="round" strokeDasharray={`${(score / 100) * c} ${c}`} />
      <text x="60" y="58" textAnchor="middle" className="font-mono" fontSize="24" fontWeight="700" fill="var(--foreground)">{score}</text>
      <text x="60" y="72" textAnchor="middle" fontSize="8" fill="var(--muted-foreground)" letterSpacing="1">RISK / 100</text>
    </svg>
  );
}

export const fmtTime = (iso: string) => {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.toISOString().replace("T", " ").slice(0, 19);
  } catch {
    return String(iso);
  }
};

export const fmtShort = (iso: string) => {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.toISOString().slice(11, 16);
  } catch {
    return String(iso);
  }
};
