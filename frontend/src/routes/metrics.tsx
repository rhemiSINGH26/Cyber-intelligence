import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, XCircle } from "lucide-react";
import { qk } from "@/api";
import { useDemoMode } from "@/lib/demo";
import { Skeleton } from "@/components/ui/skeleton";
import { Panel, StatCard } from "@/components/tl";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/metrics")({
  head: () => ({
    meta: [
      { title: "Detection Metrics — ThreatLens" },
      { name: "description", content: "Precision, recall, F1, false-positive rate and confusion matrix for ThreatLens detections." },
      { property: "og:title", content: "Detection Metrics — ThreatLens" },
      { property: "og:description", content: "How accurate is the detector? True labels vs detected." },
    ],
  }),
  component: MetricsPage,
});

const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

function MetricsPage() {
  const { mode } = useDemoMode();
  const { data } = useQuery(qk.metrics(mode));
  if (!data)
    return (
      <div className="mx-auto max-w-[1500px] space-y-4">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-[104px]" />)}</div>
        <Skeleton className="h-80" />
      </div>
    );
  const c = data.confusion;
  const cells = [
    { label: "True positive", v: c.tp, good: true },
    { label: "False negative", v: c.fn, good: false },
    { label: "False positive", v: c.fp, good: false },
    { label: "True negative", v: c.tn, good: true },
  ];
  return (
    <div className="mx-auto max-w-[1500px] space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Detection metrics</h1>
        <p className="text-sm text-muted-foreground">Evaluated on labelled replay set · {c.tp + c.fp + c.fn + c.tn} scenarios-windows</p>
      </div>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Precision" value={pct(data.precision)} sub="TP / (TP + FP)" />
        <StatCard label="Recall" value={pct(data.recall)} sub="TP / (TP + FN)" />
        <StatCard label="F1 score" value={pct(data.f1)} sub="Harmonic mean" />
        <StatCard label="False-positive rate" value={`${(data.fpr * 100).toFixed(2)}%`} tone="low" sub="FP / (FP + TN)" />
      </div>
      <div className="grid gap-4 lg:grid-cols-5">
        <Panel title="Confusion matrix" className="lg:col-span-2">
          <div className="grid grid-cols-[auto_1fr_1fr] gap-2 text-xs">
            <div />
            <div className="text-center text-muted-foreground">Detected attack</div>
            <div className="text-center text-muted-foreground">Detected benign</div>
            {[0, 1].map((row) => (
              <div key={row} className="contents">
                <div className="flex items-center pr-2 text-muted-foreground [writing-mode:vertical-rl] rotate-180 justify-center">{row === 0 ? "True attack" : "True benign"}</div>
                {cells.slice(row * 2, row * 2 + 2).map((cell) => (
                  <div key={cell.label} className={cn("flex aspect-[4/3] flex-col items-center justify-center rounded-md border", cell.good ? "border-low/40 bg-low/10" : "border-critical/40 bg-critical/10")}>
                    <div className={cn("font-mono text-3xl font-semibold", cell.good ? "text-low" : "text-critical")}>{cell.v}</div>
                    <div className="mt-1 text-[11px] text-muted-foreground">{cell.label}</div>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="True labels vs detected" className="lg:col-span-3">
          <div className="-m-4 overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                <tr><th className="px-4 py-2 font-medium">Scenario</th><th className="px-2 py-2 font-medium">True label</th><th className="px-2 py-2 font-medium">Detected</th><th className="px-4 py-2 font-medium">Result</th></tr>
              </thead>
              <tbody>
                {(data.comparison || []).map((r) => {
                  const ok = r.truth === r.detected;
                  const kind = ok ? (r.truth === "attack" ? "TP" : "TN") : r.truth === "attack" ? "FN" : "FP";
                  return (
                    <tr key={r.scenario} className="border-b last:border-0">
                      <td className="px-4 py-2.5">{r.incident ? <Link to="/incidents/$id" params={{ id: r.incident }} className="hover:text-primary">{r.scenario}</Link> : r.scenario}</td>
                      <td className="px-2 py-2.5 font-mono text-xs capitalize">{r.truth}</td>
                      <td className="px-2 py-2.5 font-mono text-xs capitalize">{r.detected}</td>
                      <td className="px-4 py-2.5">
                        <span className={cn("inline-flex items-center gap-1 font-mono text-xs font-semibold", ok ? "text-low" : "text-critical")}>
                          {ok ? <CheckCircle2 className="size-3.5" /> : <XCircle className="size-3.5" />} {kind}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </div>
  );
}
