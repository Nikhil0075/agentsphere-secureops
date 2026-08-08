import { useEffect, useState } from "react";
import { api, type GraphInfo } from "../../lib/api";
import { Card, Note, Skeleton } from "../primitives";

interface Column {
  heading: string;
  origin: string;
  nodes: string;
  edges: string;
  confidence: string;
  confidenceTone: "grounded" | "prior";
  note: string;
}

/**
 * The comparison the "Compare shipped graph" button actually promises.
 *
 * Pressing it used to drop you into the Provenance Lab on an unrelated WitFoo incident, with
 * nothing tying the two together — a navigation link wearing the word "compare". The point being
 * made is narrow and worth stating plainly: **the traversal code is identical on both sides**.
 * What differs is where edge confidence comes from — hand-set weights on GUIDE, dataset scores on
 * WitFoo — and that is the only honest claim available, so it is the one this panel makes.
 */
export function GraphComparison({
  incidentId,
  summary,
}: {
  incidentId?: string | null;
  summary?: Record<string, unknown>;
}) {
  const [guide, setGuide] = useState<GraphInfo | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!incidentId) {
      setGuide(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    api
      .graph(incidentId)
      .then((g) => !cancelled && setGuide(g))
      .catch(() => !cancelled && setGuide(null))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  const grounded = Number(summary?.grounding && (summary.grounding as any).scored_fraction) || 0;

  const columns: Column[] = [
    {
      heading: "Built from GUIDE",
      origin: incidentId ? incidentId : "no incident selected",
      nodes: guide ? guide.node_count.toLocaleString() : "—",
      edges: guide ? guide.edge_count.toLocaleString() : "—",
      confidence: "hand-set weights",
      confidenceTone: "prior",
      note: "GUIDE ships no graph. Edges are constructed from evidence co-occurrence within an alert — not within an incident, or a 1,313-row incident would produce a near-complete graph.",
    },
    {
      heading: "Shipped by WitFoo",
      origin: String(summary?.source ?? "witfoo/precinct6-cybersecurity"),
      nodes: Number(summary?.declared_nodes ?? 0).toLocaleString(),
      edges: Number(summary?.declared_edges ?? 0).toLocaleString(),
      confidence: grounded ? `${(grounded * 100).toFixed(1)}% dataset-scored` : "dataset-scored",
      confidenceTone: "grounded",
      note: "The graph arrives with the dataset, already labelled. Only a third of its edges carry a confidence score; the rest fall back to the same prior GUIDE uses throughout.",
    },
  ];

  return (
    <Card
      title="Same traversal, two sources of confidence"
      subtitle="Depth-capped BFS and Dijkstra over −log(confidence) run unmodified on both graphs."
    >
      {loading ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {columns.map((col) => (
            <div key={col.heading} className="min-w-0 rounded-xl border border-line p-4">
              <div className="mono text-3xs uppercase tracking-[0.12em] text-faint">
                {col.origin}
              </div>
              <h3 className="mt-1 text-sm font-semibold text-text">{col.heading}</h3>
              <dl className="mt-3 grid grid-cols-2 gap-3">
                <div>
                  <dt className="text-3xs uppercase tracking-[0.12em] text-faint">Nodes</dt>
                  <dd className="mono mt-0.5 text-lg font-medium tracking-[-0.015em] text-text">
                    {col.nodes}
                  </dd>
                </div>
                <div>
                  <dt className="text-3xs uppercase tracking-[0.12em] text-faint">Edges</dt>
                  <dd className="mono mt-0.5 text-lg font-medium tracking-[-0.015em] text-text">
                    {col.edges}
                  </dd>
                </div>
              </dl>
              <div className="mt-3 border-t border-line pt-2.5">
                <div className="text-3xs uppercase tracking-[0.12em] text-faint">Edge confidence</div>
                <div
                  className={`mt-0.5 text-xs font-semibold ${
                    col.confidenceTone === "grounded" ? "text-fp" : "text-bp"
                  }`}
                >
                  {col.confidence}
                </div>
              </div>
              <p className="mt-2.5 text-2xs leading-relaxed text-muted">{col.note}</p>
            </div>
          ))}
        </div>
      )}

      <Note tone="warn">
        The two node counts are not comparable as a measure of quality. The left is one incident's
        subgraph; the right is an entire shipped corpus. What is comparable is the{" "}
        <strong>provenance of the weights</strong> — and that is the only claim made here.
      </Note>
    </Card>
  );
}
