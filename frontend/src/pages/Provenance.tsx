import { useEffect, useState } from "react";
import {
  api,
  type ProvenanceGraph,
  type WitFooIncident,
} from "../lib/api";
import { Badge, Card, Empty, ErrorNote, Spinner, Stat } from "../components/primitives";

/** Colour by the dataset's own threat label. Deliberately not the triage palette used elsewhere —
 *  these are different judgements and should not look like the same ones. */
const THREAT_TONE: Record<string, string> = {
  malicious: "text-tp",
  suspicious: "text-bp",
  benign: "text-fp",
};

function ThreatBadge({ label }: { label: string }) {
  if (!label) return <span className="text-ink-600">—</span>;
  return <span className={`mono text-[11px] ${THREAT_TONE[label] ?? "text-ink-400"}`}>{label}</span>;
}

/**
 * WitFoo Precinct6 — a provenance graph the dataset *ships*, rather than one we construct.
 *
 * GUIDE is tabular, so the entity graph elsewhere in this app is built from evidence rows. WitFoo
 * publishes 35,133 nodes and 634,190 labelled edges directly, and every edge carries the dataset's
 * own confidence. The traversal code is unchanged from the GUIDE path — that reuse is the point.
 */
export function Provenance() {
  const [incidents, setIncidents] = useState<WitFooIncident[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [graph, setGraph] = useState<ProvenanceGraph | null>(null);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    api
      .witfooIncidents({ limit: 60, search })
      .then(setIncidents)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [search]);

  useEffect(() => {
    if (!selected) return;
    setLoadingGraph(true);
    setError("");
    api
      .witfooGraph(selected)
      .then(setGraph)
      .catch((e) => setError(e.message))
      .finally(() => setLoadingGraph(false));
  }, [selected]);

  if (loading && incidents.length === 0) {
    return (
      <Card>
        <Spinner label="Loading WitFoo incidents…" />
      </Card>
    );
  }

  if (!loading && incidents.length === 0 && !search) {
    return (
      <Card title="WitFoo provenance" subtitle="Not downloaded">
        <Empty>
          Run <code className="mono text-ink-300">python scripts/download_witfoo.py</code> then{" "}
          <code className="mono text-ink-300">python scripts/build_witfoo_graph.py</code>. Nothing
          else in the system depends on it.
        </Empty>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card
        title="WitFoo Precinct6 — a provenance graph the dataset ships"
        subtitle="GUIDE is tabular, so its entity graph is constructed from evidence rows. This one is published: 35,133 nodes, 634,190 labelled edges. The traversal code below is the same code, unchanged."
        right={<Badge>Apache-2.0</Badge>}
      >
        {/* Stated wherever WitFoo numbers appear next to GUIDE's, because the distinction is
            easy to lose once both are on screen. */}
        <p className="rounded border border-bp/30 bg-bp/10 px-3 py-2 text-xs leading-relaxed text-bp">
          WitFoo labels are <strong>threat assessments</strong> (benign / suspicious / malicious),
          not the analyst <strong>triage verdicts</strong> GUIDE carries. They are excluded from
          every accuracy metric in this project.
        </p>

        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search incident id, MO name or technique"
          className="mt-3 w-full rounded border border-ink-700 bg-ink-900 px-3 py-1.5 text-xs text-ink-100 placeholder:text-ink-600"
        />

        {error && <ErrorNote>{error}</ErrorNote>}

        <div className="mt-3 max-h-72 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-ink-900 text-[11px] uppercase tracking-wide text-ink-400">
              <tr>
                <th className="py-1 text-left font-medium">Incident</th>
                <th className="py-1 text-left font-medium">Modus operandi</th>
                <th className="py-1 text-right font-medium">Suspicion</th>
                <th className="py-1 text-right font-medium">Nodes</th>
                <th className="py-1 text-right font-medium">Edges</th>
                <th className="py-1 text-left font-medium">MITRE</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <tr
                  key={incident.incident_id}
                  onClick={() => setSelected(incident.incident_id)}
                  className={`cursor-pointer border-t border-ink-850 hover:bg-ink-850 ${
                    selected === incident.incident_id ? "bg-ink-850" : ""
                  }`}
                >
                  <td className="mono py-1 text-ink-300">
                    {incident.incident_id.slice(0, 8)}…
                  </td>
                  <td className="py-1 text-ink-200">{incident.mo_name || "—"}</td>
                  <td className="mono py-1 text-right text-ink-300">
                    {incident.suspicion_score.toFixed(2)}
                  </td>
                  <td className="mono py-1 text-right text-ink-400">{incident.node_count}</td>
                  <td className="mono py-1 text-right text-ink-400">{incident.edge_count}</td>
                  <td className="mono py-1 text-[10px] text-ink-500">
                    {(incident.attack_techniques || []).slice(0, 3).join(" ") || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {loadingGraph && (
        <Card>
          <Spinner label="Building the provenance subgraph…" />
        </Card>
      )}

      {graph && !loadingGraph && (
        <>
          <Card
            title={`Provenance subgraph · ${graph.incident.mo_name || "incident"}`}
            subtitle={graph.incident.incident_id}
            right={
              graph.incident.disposition_category ? (
                <Badge tone={graph.incident.disposition_category.includes("malicious") ? "high" : undefined}>
                  {graph.incident.disposition_category}
                </Badge>
              ) : null
            }
          >
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat label="Entities" value={graph.node_count} />
              <Stat
                label="Connections"
                value={graph.edge_count}
                hint={`from ${graph.edge_records} observations`}
              />
              <Stat
                label="Confidence source"
                value={`${((graph.confidence_sources?.grounded_fraction ?? 0) * 100).toFixed(0)}%`}
                hint="from the dataset, not hand-set"
                tone={graph.confidence_sources?.grounded_fraction === 1 ? "good" : undefined}
              />
              <Stat
                label="Lifecycle"
                value={graph.incident.lifecycle_stage || "—"}
                hint={graph.incident.status_name}
              />
            </div>

            {graph.attack_path && graph.attack_path.path.length > 1 && (
              <div className="mt-3 rounded border border-ink-800 bg-ink-850 p-3">
                <div className="text-[11px] uppercase tracking-wide text-ink-400">
                  Most probable chain · Dijkstra on −log(confidence)
                </div>
                <div className="mono mt-1.5 text-xs text-ink-200">
                  {graph.attack_path.path.join("  →  ")}
                </div>
                <div className="mt-1 text-[11px] text-ink-500">
                  probability {graph.attack_path.probability.toFixed(4)} · weakest link{" "}
                  {graph.attack_path.weakest_link.toFixed(2)} ·{" "}
                  {graph.confidence_sources?.grounded_lookups ?? 0} of{" "}
                  {(graph.confidence_sources?.grounded_lookups ?? 0) +
                    (graph.confidence_sources?.fallback_lookups ?? 0)}{" "}
                  confidence lookups came from the dataset
                </div>
              </div>
            )}

            <div className="mt-3 max-h-64 overflow-y-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-ink-900 text-[11px] uppercase tracking-wide text-ink-400">
                  <tr>
                    <th className="py-1 text-left font-medium">Source</th>
                    <th className="py-1 text-left font-medium">Target</th>
                    <th className="py-1 text-left font-medium">Threat label</th>
                    <th className="py-1 text-right font-medium">Confidence</th>
                    <th className="py-1 text-left font-medium">Scored</th>
                  </tr>
                </thead>
                <tbody>
                  {graph.edges.map((edge, i) => (
                    <tr key={i} className="border-t border-ink-850">
                      <td className="mono py-1 text-ink-300">{edge.source}</td>
                      <td className="mono py-1 text-ink-300">{edge.target}</td>
                      <td className="py-1">
                        <ThreatBadge label={edge.threat_label} />
                      </td>
                      <td className="mono py-1 text-right text-ink-300">
                        {edge.confidence.toFixed(2)}
                      </td>
                      <td className="py-1 text-[10px] text-ink-500">
                        {edge.scored ? "dataset" : "prior"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          {graph.incident.report_text && (
            <Card title="Analyst report" subtitle="Shipped with the dataset">
              <p className="whitespace-pre-wrap text-xs leading-relaxed text-ink-300">
                {graph.incident.report_text}
              </p>
              {graph.incident.matched_rules.length > 0 && (
                <p className="mt-2 text-[11px] text-ink-500">
                  Matched rules: {graph.incident.matched_rules.join(", ")}
                </p>
              )}
            </Card>
          )}
        </>
      )}
    </div>
  );
}
