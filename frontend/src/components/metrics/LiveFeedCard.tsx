import type { SessionRun } from "../../pages/Workflow";
import { Card, Empty, Stat } from "../primitives";

const LABEL_TONE: Record<string, string> = {
  TruePositive: "bg-tp",
  BenignPositive: "bg-bp",
  FalsePositive: "bg-fp",
};

/**
 * Workflows completed in this browser session.
 *
 * Derived entirely from responses already in hand — no fetch, no polling, no storage — so it stays
 * inside the zero-RPC guarantee this screen makes. It is a demo tally, not a measurement: the
 * incidents are hand-picked and the sample is whatever was clicked, which is why the caveat sits in
 * the header rather than in a footnote.
 */
export function LiveFeedCard({ runs }: { runs: SessionRun[] }) {
  const total = runs.length;
  const meanLatency = total
    ? Math.round(runs.reduce((sum, run) => sum + run.total_latency_ms, 0) / total)
    : 0;
  const cacheHits = runs.filter((run) => run.cache_status === "hit").length;
  const degraded = runs.reduce((sum, run) => sum + run.degraded, 0);
  const resampled = runs.reduce((sum, run) => sum + run.resampled, 0);
  const revisions = runs.filter((run) => run.revision_fired).length;

  const byLabel = runs.reduce<Record<string, number>>((acc, run) => {
    const key = run.label || "unlabelled";
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <Card
      title="This session"
      subtitle="Workflows run in this browser since the page loaded. Hand-picked incidents, so this is a tally rather than a measurement — no reported figure is computed from it."
      right={<span className="text-2xs text-faint">live · no network call</span>}
    >
      {total === 0 ? (
        <Empty>Run a workflow to start the tally.</Empty>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="Workflows" value={total} />
            <Stat label="Mean latency" value={`${meanLatency.toLocaleString()}ms`} />
            <Stat
              label="Cache hits"
              value={`${Math.round((cacheHits / total) * 100)}%`}
              hint={`${cacheHits} of ${total}`}
              tone={cacheHits === total ? "good" : undefined}
            />
            <Stat
              label="Degraded"
              value={degraded}
              hint={resampled ? `${resampled} resampled` : revisions ? `${revisions} revised` : "none"}
              tone={degraded ? "warn" : "good"}
            />
          </div>

          <div className="mt-4">
            <div className="text-2xs uppercase tracking-wider text-faint">Labels returned</div>
            <div className="mt-1.5 flex h-2 overflow-hidden rounded-full bg-line">
              {Object.entries(byLabel).map(([label, count]) => (
                <div
                  key={label}
                  className={LABEL_TONE[label] ?? "bg-primary-line"}
                  style={{ width: `${(count / total) * 100}%` }}
                  title={`${label}: ${count}`}
                />
              ))}
            </div>
            <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-2xs text-muted">
              {Object.entries(byLabel).map(([label, count]) => (
                <span key={label} className="flex items-center gap-1.5">
                  <span
                    aria-hidden="true"
                    className={`h-2 w-2 rounded-full ${LABEL_TONE[label] ?? "bg-primary-line"}`}
                  />
                  {label} {count}
                </span>
              ))}
            </div>
          </div>

          <ol className="mt-4 space-y-1 border-t border-line pt-3">
            {runs
              .slice(-6)
              .reverse()
              .map((run) => (
                <li
                  key={`${run.incident_id}-${run.at}`}
                  className="flex flex-wrap items-center gap-2 text-2xs"
                >
                  <span className="mono truncate text-muted">{run.incident_id}</span>
                  <span className="text-text">{run.label || "—"}</span>
                  <span className="text-faint">{(run.confidence * 100).toFixed(0)}%</span>
                  <span className="mono ml-auto text-faint">{run.total_latency_ms}ms</span>
                  <span className="text-faint">{run.execution_mode}</span>
                </li>
              ))}
          </ol>
        </>
      )}
    </Card>
  );
}
