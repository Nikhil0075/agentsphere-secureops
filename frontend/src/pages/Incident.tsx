import { useEffect, useState } from "react";
import {
  api,
  type EvidenceRow,
  type GraphInfo,
  type IncidentDetail,
  type SimilarIncident,
} from "../lib/api";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNote,
  LabelBadge,
  Note,
  PageIntro,
  Skeleton,
  Spinner,
  Stat,
} from "../components/primitives";

/** Scene 3: the result is inspectable. Evidence, retrieval, blast radius, attack chain. */
export function Incident({
  incidentId,
  onSelectIncident,
  onOpenProvenance,
}: {
  incidentId: string;
  onSelectIncident: (id: string) => void;
  onOpenProvenance: () => void;
}) {
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [evidence, setEvidence] = useState<EvidenceRow[]>([]);
  const [similar, setSimilar] = useState<SimilarIncident[]>([]);
  const [graph, setGraph] = useState<GraphInfo | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    Promise.all([
      api.incident(incidentId),
      api.evidence(incidentId, 60),
      api.similar(incidentId, 6),
      api.graph(incidentId, 2),
    ])
      .then(([d, e, s, g]) => {
        if (cancelled) return;
        setDetail(d);
        setEvidence(e);
        setSimilar(s);
        setGraph(g);
      })
      .catch((e) => !cancelled && setError(String(e.message)))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  if (loading)
    return (
      <Card>
        <Spinner label="Loading incident…" />
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Skeleton className="h-24" />
          <Skeleton className="h-24" />
        </div>
      </Card>
    );
  if (error)
    return (
      <Card>
        <ErrorNote>{error}</ErrorNote>
      </Card>
    );
  if (!detail) return null;

  return (
    <div className="space-y-4">
      <PageIntro
        eyebrow="Scene 3 · Inspectable reasoning"
        title="Follow every conclusion back to evidence."
        description="Inspect the selected incident, compare retrieval results, and trace the capped graph traversal before any response is proposed."
      />
      <Card
        title={detail.incident_id}
        subtitle={`${detail.top_category || "uncategorised"} · detector ${detail.top_detector || "unknown"}`}
        right={<LabelBadge label={detail.label} />}
      >
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="Risk" value={detail.risk_score.toFixed(3)} />
          <Stat label="Alerts" value={detail.alert_count} />
          <Stat label="Evidence" value={detail.evidence_count} />
          <Stat
            label="Duration"
            value={`${detail.duration_minutes.toFixed(0)}m`}
            hint={detail.first_seen.slice(0, 16).replace("T", " ")}
          />
        </div>

        {detail.summary && (
          <pre className="mt-4 max-h-48 overflow-auto rounded-xl bg-raised p-4 text-xs leading-relaxed whitespace-pre-wrap text-muted">
            {detail.summary}
          </pre>
        )}

        <div className="mt-3 flex flex-wrap gap-1.5">
          {Object.entries(detail.entity_counts).map(([type, n]) => (
            <Badge key={type}>
              {type} <span className="opacity-60">×{n}</span>
            </Badge>
          ))}
          {detail.mitre_techniques
            .split(";")
            .filter(Boolean)
            .slice(0, 8)
            .map((t) => (
              <Badge key={t} tone="info">
                {t}
              </Badge>
            ))}
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
        <Card
          title="Similar incidents"
          subtitle="BM25 + vector search fused with Reciprocal Rank Fusion (k=60), then a metadata re-rank."
        >
          {similar.length === 0 && <Empty>No sufficiently similar incident found.</Empty>}
          <ul className="space-y-2">
            {similar.map((hit) => (
              <li key={hit.incident_id}>
                <button
                  type="button"
                  onClick={() => onSelectIncident(hit.incident_id)}
                  className="interactive-card w-full rounded-xl bg-raised p-3 text-left hover:bg-primary-soft"
                >
                <div className="flex items-center justify-between gap-2">
                  <span className="mono text-xs font-medium text-text">{hit.incident_id}</span>
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-16 overflow-hidden rounded-full bg-line">
                      <div
                        className="h-full rounded-full bg-primary"
                        style={{ width: `${hit.score * 100}%` }}
                      />
                    </div>
                    <span className="mono text-xs text-muted">{hit.score.toFixed(2)}</span>
                  </div>
                </div>
                <p className="mt-1 text-2xs text-muted">{hit.why}</p>
                </button>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-2xs leading-relaxed text-faint">
            Retrieved incidents never carry their ground-truth label — that would leak the answer
            into the agent's prompt.
          </p>
        </Card>

        <Card
          title="Blast radius and attack chain"
          subtitle="Depth-capped BFS; Dijkstra over −log(confidence) for the most probable chain."
          right={<Button onClick={onOpenProvenance}>Compare shipped graph →</Button>}
        >
          {!graph || graph.node_count === 0 ? (
            <Empty>No entity graph for this incident.</Empty>
          ) : (
            <>
              <div className="grid grid-cols-3 gap-3">
                <Stat label="Graph nodes" value={graph.node_count} />
                <Stat label="Edges" value={graph.edge_count} />
                <Stat
                  label="Impacted"
                  value={graph.blast_radius.total_nodes}
                  hint={graph.blast_radius.truncated ? "truncated" : undefined}
                />
              </div>

              {graph.blast_radius.hubs_blocked.length > 0 && (
                <div className="mt-3">
                  <Note tone="warn">
                    {graph.blast_radius.hubs_blocked.length} hub node(s) reached but not expanded
                    through — an uncapped traversal from a hub returns most of the graph.
                  </Note>
                </div>
              )}

              <div className="mt-3 space-y-1.5">
                {Object.entries(graph.blast_radius.impacted_by_type).map(([type, values]) => (
                  <div key={type} className="flex gap-2 text-xs">
                    <span className="w-16 shrink-0 font-medium text-faint">{type}</span>
                    <span className="mono truncate text-muted" title={values.join(", ")}>
                      {values.slice(0, 4).join(", ")}
                      {values.length > 4 && ` +${values.length - 4}`}
                    </span>
                  </div>
                ))}
              </div>

              {graph.attack_path && graph.attack_path.hops > 0 && (
                <div className="mt-3 rounded-xl bg-raised p-3.5">
                  <div className="flex items-center justify-between">
                    <span className="text-2xs font-medium uppercase tracking-wider text-faint">
                      Most probable chain
                    </span>
                    <span className="mono text-xs font-semibold text-primary">
                      p = {graph.attack_path.probability.toFixed(4)}
                    </span>
                  </div>
                  <div className="mono mt-2 flex flex-wrap items-center gap-1 text-2xs text-muted">
                    {graph.attack_path.path.map((node, i) => (
                      <span key={`${node}-${i}`} className="flex items-center gap-1">
                        <span className="rounded-md bg-surface px-1.5 py-0.5 text-text">{node}</span>
                        {i < graph.attack_path!.path.length - 1 && (
                          <span className="text-faint">
                            →{graph.attack_path!.edge_confidences[i]?.toFixed(2)}
                          </span>
                        )}
                      </span>
                    ))}
                  </div>
                  <p className="mt-2 text-2xs leading-relaxed text-faint">
                    Weakest link {graph.attack_path.weakest_link.toFixed(2)}. Costs are
                    −log(confidence), so this is the highest-probability path, not merely a
                    reachable one.
                  </p>
                </div>
              )}
            </>
          )}
        </Card>
      </div>

      <Card
        title="Evidence"
        subtitle={`${evidence.length} row(s) shown. Every agent claim cites these ids.`}
        pad={false}
      >
        <div className="max-h-80 overflow-auto">
          <table className="w-full min-w-[720px] text-xs">
            <thead className="sticky top-0 bg-surface">
              <tr className="border-b border-line text-left text-2xs font-medium uppercase tracking-wider text-faint">
                <th className="px-5 py-2.5">Evidence id</th>
                <th className="px-2 py-2.5">Type</th>
                <th className="px-2 py-2.5">Role</th>
                <th className="px-2 py-2.5">Verdict</th>
                <th className="px-5 py-2.5">Entities</th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((row) => (
                <tr key={row.evidence_id} className="odd:bg-raised/60">
                  <td className="mono px-5 py-2 text-muted">{row.evidence_id}</td>
                  <td className="px-2 py-2 text-muted">{row.entity_type || "—"}</td>
                  <td className="px-2 py-2 text-faint">{row.evidence_role || "—"}</td>
                  <td className="px-2 py-2">
                    {row.last_verdict || row.suspicion_level ? (
                      <Badge>{row.last_verdict || row.suspicion_level}</Badge>
                    ) : (
                      <span className="text-faint">—</span>
                    )}
                  </td>
                  <td className="mono px-5 py-2 text-faint">
                    {Object.entries(row.fields)
                      .slice(0, 3)
                      .map(([k, v]) => `${k}=${v.slice(0, 18)}`)
                      .join("  ") || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
