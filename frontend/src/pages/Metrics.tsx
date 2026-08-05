import { useEffect, useState } from "react";
import { api, type MetricsResponse } from "../lib/api";
import { Card, Empty, Spinner, Stat } from "../components/primitives";

const LABELS = ["TruePositive", "BenignPositive", "FalsePositive"] as const;

/** Scene 6: the system is measured, not merely claimed — including where it measures badly. */
export function Metrics() {
  const [data, setData] = useState<MetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .metrics()
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Card><Spinner label="Loading metrics…" /></Card>;
  if (!data) return <Card><Empty>No metrics available.</Empty></Card>;

  const baseline = data.baseline ?? {};
  const evaluation = data.evaluation ?? {};
  const agents = evaluation.agents ?? {};
  const evalBaseline = evaluation.baseline ?? {};
  const delta =
    agents.macro_f1 !== undefined && evalBaseline.macro_f1 !== undefined
      ? agents.macro_f1 - evalBaseline.macro_f1
      : null;

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card
        title="Non-LLM baseline"
        subtitle={`${baseline.implementation ?? "unavailable"} on ${baseline.test_incidents ?? "?"} held-out incidents`}
      >
        <div className="grid grid-cols-3 gap-2">
          <Stat label="Accuracy" value={baseline.accuracy?.toFixed(4) ?? "—"} />
          <Stat label="Macro F1" value={baseline.macro_f1?.toFixed(4) ?? "—"} />
          <Stat
            label="TP recall"
            value={baseline.true_positive_recall?.toFixed(4) ?? "—"}
            hint="missed attacks are the dangerous failure"
          />
        </div>
        {baseline.per_class && (
          <table className="mt-3 w-full text-xs">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wide text-ink-400">
                <th className="py-1 font-medium">Class</th>
                <th className="py-1 text-right font-medium">P</th>
                <th className="py-1 text-right font-medium">R</th>
                <th className="py-1 text-right font-medium">F1</th>
                <th className="py-1 text-right font-medium">n</th>
              </tr>
            </thead>
            <tbody>
              {LABELS.map((label) => {
                const row = baseline.per_class[label];
                if (!row) return null;
                return (
                  <tr key={label} className="border-t border-ink-850">
                    <td className="py-1 text-ink-300">{label}</td>
                    <td className="mono py-1 text-right text-ink-300">{row.precision?.toFixed(3)}</td>
                    <td className="mono py-1 text-right text-ink-300">{row.recall?.toFixed(3)}</td>
                    <td className="mono py-1 text-right text-ink-300">{row.f1?.toFixed(3)}</td>
                    <td className="mono py-1 text-right text-ink-400">{row.support}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>

      <Card
        title="Agent chain vs baseline"
        subtitle={
          evaluation.incidents
            ? `${evaluation.incidents} incidents from the ${evaluation.split} split on backend ${evaluation.backend}`
            : "Run scripts/evaluate.py to populate"
        }
      >
        {!evaluation.incidents ? (
          <Empty>No evaluation recorded yet.</Empty>
        ) : (
          <>
            <div className="grid grid-cols-3 gap-2">
              <Stat label="Agent macro F1" value={agents.macro_f1?.toFixed(4) ?? "—"} />
              <Stat label="Baseline macro F1" value={evalBaseline.macro_f1?.toFixed(4) ?? "—"} />
              <Stat
                label="Delta"
                value={delta === null ? "—" : `${delta >= 0 ? "+" : ""}${delta.toFixed(4)}`}
                tone={delta === null ? undefined : delta >= 0 ? "good" : "bad"}
                hint="agents − baseline"
              />
            </div>

            {delta !== null && delta < 0 && (
              <p className="mt-3 rounded border border-bp/30 bg-bp/10 px-3 py-2 text-xs leading-relaxed text-bp">
                The agent chain currently scores <strong>below</strong> the non-LLM baseline on
                this sample. Reported rather than hidden: the agent layer's value here is
                evidence-grounded explanation, policy enforcement and auditability, not raw
                classification accuracy. The baseline remains the stronger classifier.
              </p>
            )}

            <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat
                label="Verifier rejects"
                value={`${((evaluation.verifier?.rejection_rate ?? 0) * 100).toFixed(0)}%`}
              />
              <Stat
                label="Escalations"
                value={`${((evaluation.verifier?.escalation_rate ?? 0) * 100).toFixed(0)}%`}
              />
              <Stat
                label="Auto-approved"
                value={`${((evaluation.gate?.auto_approval_rate ?? 0) * 100).toFixed(0)}%`}
              />
              <Stat
                label="Degraded"
                value={`${((evaluation.reliability?.degraded_rate ?? 0) * 100).toFixed(0)}%`}
                tone={evaluation.reliability?.degraded_rate ? "warn" : "good"}
              />
            </div>
          </>
        )}
      </Card>

      <Card
        title="Proof integrity"
        subtitle="Every anchored decision re-verified by recomputing its digests from stored data."
      >
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Stat label="Decisions" value={data.proofs?.decisions ?? "—"} />
          <Stat label="Anchored" value={data.proofs?.anchored ?? "—"} />
          <Stat
            label="Still valid"
            value={
              data.proofs?.validity_rate === null || data.proofs?.validity_rate === undefined
                ? "—"
                : `${(data.proofs.validity_rate * 100).toFixed(0)}%`
            }
            tone={data.proofs?.validity_rate === 1 ? "good" : undefined}
          />
          <Stat
            label="Tampered"
            value={data.proofs?.tampered ?? "—"}
            tone={data.proofs?.tampered ? "bad" : undefined}
          />
        </div>
        <p className="mt-2 text-[11px] text-ink-600">
          {data.proofs?.chain_available
            ? "Verified against the deployed contract, not against a stored hash column."
            : "No chain reachable — compared against the locally recorded proof only."}
        </p>
      </Card>

      <Card title="Entity graph" subtitle="Built from GUIDE evidence rows — GUIDE ships no graph.">
        <div className="grid grid-cols-3 gap-2">
          <Stat label="Nodes" value={data.graph?.nodes?.toLocaleString() ?? "—"} />
          <Stat label="Edges" value={data.graph?.edges?.toLocaleString() ?? "—"} />
          <Stat
            label="Worst hub"
            value={data.graph?.max_degree?.toLocaleString() ?? "—"}
            hint={data.graph?.hubs?.[0]?.node}
          />
        </div>
        <p className="mt-2 text-[11px] text-ink-600">
          Traversal is capped at 2–3 hops and refuses to expand through nodes above the hub
          threshold. An uncapped BFS from the worst hub returns most of the graph.
        </p>
      </Card>

      <Card title="Retrieval index" subtitle="BM25 + vectors, fused with RRF (k=60).">
        <div className="grid grid-cols-3 gap-2">
          <Stat label="Documents" value={data.index?.incidents?.toLocaleString() ?? "—"} />
          <Stat label="Dimensions" value={data.index?.dimensions ?? "—"} />
          <Stat
            label="Build time"
            value={data.index?.build_seconds ? `${data.index.build_seconds}s` : "—"}
            hint={data.index?.embedding_backend}
          />
        </div>
        <p className="mt-2 text-[11px] text-ink-600">
          Every query incident is already in the corpus, so its embedding is a lookup rather than
          an API call — retrieval works with the network unplugged.
        </p>
      </Card>
    </div>
  );
}
