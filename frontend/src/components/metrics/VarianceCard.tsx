import { Badge, Card, Empty, Kpi, Note, Stat } from "../primitives";

const LABEL_CLASS: Record<string, string> = {
  TruePositive: "bg-tp",
  BenignPositive: "bg-bp",
  FalsePositive: "bg-fp",
};

/**
 * Measured live run-to-run variance.
 *
 * The honest centrepiece of this screen. Two things must survive the summarising: that a single
 * incident returned three different labels on three runs of byte-identical input, and that *both*
 * incidents produced three distinct output hashes — so "0.50 stability" must not be allowed to
 * imply the other half was reproducible.
 */
export function VarianceCard({ variance }: { variance?: Record<string, any> }) {
  const incidents: Record<string, any> = variance?.incidents ?? {};
  const ids = Object.keys(incidents);

  if (!ids.length) {
    return (
      <Card title="Live variance" subtitle="How much a live run moves when nothing about the input changes.">
        <Empty>
          Not measured yet. Run <span className="mono">python scripts/measure_variance.py --confirm</span>{" "}
          — it makes live calls, so it is never run automatically.
        </Empty>
      </Card>
    );
  }

  const stability = variance?.decision_stability;
  const runs = variance?.runs_per_incident ?? 0;
  const unstableHashes = ids.filter((id) => (incidents[id]?.output_hash?.n_distinct ?? 0) > 1);
  const flipped = ids.filter((id) => (incidents[id]?.triage?.label?.n_distinct ?? 0) > 1);

  return (
    <Card
      title="Live variance, measured"
      subtitle={`${ids.length} incident${ids.length === 1 ? "" : "s"} run ${runs} times each with the cache suppressed in both directions — reads always miss, writes never land, so no run replays another.`}
      right={<Badge tone="info">{variance?.model_profile?.support ?? "live"}</Badge>}
    >
      <div className="grid gap-3 sm:grid-cols-3">
        <Kpi
          label="Decision stability"
          value={typeof stability === "number" ? stability.toFixed(2) : "—"}
          hint={`same label and gate outcome across all ${runs} runs`}
          tone={stability === 1 ? "good" : stability !== undefined && stability < 1 ? "warn" : undefined}
        />
        <Stat label="Live calls" value={variance?.total_live_calls ?? "—"} />
        <Stat
          label="Wall clock"
          value={variance?.wall_seconds ? `${Math.round(variance.wall_seconds)}s` : "—"}
          hint={variance?.reasoning_effort ? `${variance.reasoning_effort} reasoning` : undefined}
        />
      </div>

      <div className="mt-4 space-y-3">
        {ids.map((id) => {
          const entry = incidents[id];
          const labels: Record<string, number> = entry?.triage?.label?.counts ?? {};
          const total = Object.values(labels).reduce((sum, value) => sum + value, 0) || 1;
          const confidence = entry?.triage?.confidence ?? {};
          const hashes = entry?.output_hash?.n_distinct ?? 0;

          return (
            <div key={id} className="min-w-0 rounded-xl bg-raised p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="mono truncate text-xs text-text">{id}</span>
                <Badge tone={entry?.decision_stable ? "low" : "high"}>
                  {entry?.decision_stable ? "decision held" : "decision flipped"}
                </Badge>
              </div>

              <div className="mt-2 flex h-2 overflow-hidden rounded-full bg-line">
                {Object.entries(labels).map(([label, count]) => (
                  <div
                    key={label}
                    className={LABEL_CLASS[label] ?? "bg-primary-line"}
                    style={{ width: `${(count / total) * 100}%` }}
                    title={`${label}: ${count} of ${total}`}
                  />
                ))}
              </div>
              <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-2xs text-muted">
                {Object.entries(labels).map(([label, count]) => (
                  <span key={label} className="flex items-center gap-1.5">
                    <span
                      aria-hidden="true"
                      className={`h-2 w-2 rounded-full ${LABEL_CLASS[label] ?? "bg-primary-line"}`}
                    />
                    {label} ×{count}
                  </span>
                ))}
              </div>

              <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-2xs sm:grid-cols-4">
                <Fact
                  label="Confidence"
                  value={
                    confidence.min !== undefined
                      ? `${confidence.min.toFixed(2)}–${confidence.max.toFixed(2)}`
                      : "—"
                  }
                />
                <Fact label="Output hashes" value={`${hashes} distinct`} warn={hashes > 1} />
                <Fact
                  label="Verifier"
                  value={Object.keys(entry?.verifier?.verdict?.counts ?? {}).join(", ") || "—"}
                />
                <Fact
                  label="Clusters"
                  value={entry?.correlation?.deterministic ? "identical" : "VARIED"}
                  warn={!entry?.correlation?.deterministic}
                />
              </dl>
            </div>
          );
        })}
      </div>

      {flipped.length > 0 && (
        <Note tone="warn">
          On three consecutive runs of byte-identical input,{" "}
          <span className="mono">{flipped[0]}</span> returned{" "}
          {Object.keys(incidents[flipped[0]]?.triage?.label?.counts ?? {}).join(", ")} — every label
          the schema allows. The verifier escalated on every run and the policy gate demanded a human
          on every run, so the unstable layer was contained by the deterministic one. That is the
          argument for the gate, stated as a measurement rather than a hope.
        </Note>
      )}

      <p className="mt-3 text-2xs leading-relaxed text-faint">
        {unstableHashes.length === ids.length && ids.length > 1 && (
          <>
            <strong className="text-muted">Both</strong> incidents produced {runs} distinct output
            hashes, including the one whose decision held — stability of the decision is not
            reproducibility of the run.{" "}
          </>
        )}
        Replay and deterministic mode are reproducible and tested as such. Live is not and cannot
        be: the routed reasoning models expose no temperature, top_p or seed to pin, and a schema or
        grounding retry re-sends an identical prompt. The demo therefore runs on validated replay.
      </p>
    </Card>
  );
}

function Fact({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-3xs uppercase tracking-wider text-faint">{label}</dt>
      <dd className={`mono truncate ${warn ? "font-semibold text-bp" : "text-muted"}`}>{value}</dd>
    </div>
  );
}
