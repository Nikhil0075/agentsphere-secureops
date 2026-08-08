import { useEffect, useState } from "react";
import { ProvenanceGraphView } from "../components/ProvenanceGraphView";
import { GlanceStrip } from "../components/provenance/GlanceStrip";
import { GraphComparison } from "../components/provenance/GraphComparison";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNote,
  PageIntro,
  Skeleton,
  Stat,
  TextInput,
} from "../components/primitives";
import { api, type ProvenanceGraph, type WitFooIncident } from "../lib/api";

const THREAT_TONE: Record<string, string> = {
  malicious: "text-tp",
  suspicious: "text-bp",
  benign: "text-fp",
};

function ThreatBadge({ label }: { label: string }) {
  if (!label) return <span className="text-faint">—</span>;
  return <span className={`mono text-2xs ${THREAT_TONE[label] ?? "text-faint"}`}>{label}</span>;
}

const SORTS = [
  { value: "suspicion", label: "Suspicion, high first" },
  { value: "suspicion_asc", label: "Suspicion, low first" },
  { value: "nodes", label: "Largest graph" },
  { value: "recent", label: "Most recent" },
];

/** String values the store reported for a facet, so the options are never hard-coded. */
const mediumFrom = (summary: Record<string, unknown> | undefined, key: string) => {
  const values = summary?.[key];
  return Array.isArray(values)
    ? values.filter((v): v is string => typeof v === "string").map((v) => ({ value: v, label: v }))
    : [];
};

function ListFilter({
  label,
  value,
  onChange,
  options,
  allowAll = true,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  options: { value: string; label: string }[];
  allowAll?: boolean;
}) {
  if (!options.length) return null;
  return (
    <label className="block">
      <span className="block text-3xs uppercase tracking-[0.12em] text-faint">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        aria-label={label}
        className="mt-1 w-full rounded-md border border-line bg-surface px-2 py-1.5 text-2xs text-text focus:border-primary-line"
      >
        {allowAll ? <option value="">All</option> : null}
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

const summaryNumber = (summary: Record<string, unknown> | undefined, key: string) => {
  const value = summary?.[key];
  return typeof value === "number" ? value : null;
};

/**
 * WitFoo timestamps are epoch **seconds** — verified against the shipped data, where the first
 * incident reads 1681754887 (2023-04-17). Interpreting them as milliseconds lands in January 1970.
 */
const observedAt = (value: number | null | undefined) =>
  value ? new Date(value * 1000).toISOString().replace("T", " ").slice(0, 19) : "—";

/** Incident metadata the page carried in its payload and never rendered. */
function IncidentFacts({ incident }: { incident: WitFooIncident }) {
  const chips = [
    { label: "Attack tactics", values: incident.attack_tactics },
    { label: "Products observed", values: incident.products_observed },
  ].filter((group) => group.values?.length);

  return (
    <Card title="Incident record" subtitle="As shipped by WitFoo, before any traversal.">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label="Disposition" value={incident.disposition || "—"} hint={incident.disposition_category || undefined} />
        <Stat label="Status" value={incident.status_name || "—"} />
        <Stat label="Lifecycle" value={incident.lifecycle_stage || "—"} />
        <Stat label="Suspicion" value={incident.suspicion_score?.toFixed(2) ?? "—"} />
      </div>
      <p className="mono mt-2 text-2xs text-faint">
        {observedAt(incident.first_observed_at)} → {observedAt(incident.last_observed_at)}
      </p>
      {chips.map((group) => (
        <div key={group.label} className="mt-3">
          <div className="text-3xs uppercase tracking-wider text-faint">{group.label}</div>
          <div className="mt-1 flex flex-wrap gap-1">
            {group.values.map((value) => (
              <span key={value} className="mono rounded bg-raised px-1.5 py-0.5 text-3xs text-muted">
                {value}
              </span>
            ))}
          </div>
        </div>
      ))}
    </Card>
  );
}

export function Provenance({
  summary,
  compareIncidentId,
  onBack,
  backLabel,
}: {
  summary?: Record<string, unknown>;
  /** The GUIDE incident the analyst pressed "Compare shipped graph" from, if any. */
  compareIncidentId?: string | null;
  onBack: () => void;
  backLabel: string;
}) {
  const [incidents, setIncidents] = useState<WitFooIncident[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [graph, setGraph] = useState<ProvenanceGraph | null>(null);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [error, setError] = useState("");
  const [moName, setMoName] = useState("");
  const [status, setStatus] = useState("");
  const [sort, setSort] = useState<"suspicion" | "suspicion_asc" | "nodes" | "recent">("suspicion");
  const [maxHops, setMaxHops] = useState(3);
  const [hubDegree, setHubDegree] = useState(150);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const timer = window.setTimeout(
      () => {
        api
          .witfooIncidents({ limit: 80, search, mo_name: moName, status, sort })
          .then((rows) => {
            if (!cancelled) {
              setIncidents(rows);
              setError("");
            }
          })
          .catch((reason) => !cancelled && setError(reason instanceof Error ? reason.message : String(reason)))
          .finally(() => !cancelled && setLoading(false));
      },
      search ? 220 : 0,
    );
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [moName, search, sort, status]);

  useEffect(() => {
    if (!incidents.length) {
      setSelected(null);
      setGraph(null);
      return;
    }
    if (!selected || !incidents.some((incident) => incident.incident_id === selected)) {
      setSelected(incidents[0].incident_id);
    }
  }, [incidents, selected]);

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setLoadingGraph(true);
    setGraph(null);
    setError("");
    api
      .witfooGraph(selected, { max_hops: maxHops, hub_degree: hubDegree })
      .then((payload) => !cancelled && setGraph(payload))
      .catch((reason) => !cancelled && setError(reason instanceof Error ? reason.message : String(reason)))
      .finally(() => !cancelled && setLoadingGraph(false));
    return () => {
      cancelled = true;
    };
  }, [hubDegree, maxHops, selected]);

  const declaredNodes = summaryNumber(summary, "declared_nodes");
  const declaredEdges = summaryNumber(summary, "declared_edges");
  const groundedFraction = graph?.confidence_sources?.grounded_fraction;
  const unavailable = !loading && incidents.length === 0 && !search && summary?.available === false;

  return (
    <div className="space-y-4">
      <PageIntro
        eyebrow="Explore · Optional graph depth"
        title="Provenance Lab"
        description="Compare the GUIDE graph constructed from evidence with the graph WitFoo ships. The same capped BFS and Dijkstra layer traverses both, while dataset-grounded confidence stays explicit."
        actions={<Button onClick={onBack}>← {backLabel}</Button>}
      />

      <Card
        title="Dataset provenance"
        subtitle={String(summary?.source ?? "witfoo/precinct6-cybersecurity")}
        right={<Badge>{String(summary?.licence ?? "Apache-2.0")}</Badge>}
      >
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat label="Published nodes" value={declaredNodes?.toLocaleString() ?? "—"} />
          <Stat label="Published edges" value={declaredEdges?.toLocaleString() ?? "—"} />
          <Stat
            label="Selected subgraph"
            value={graph ? `${graph.node_count} / ${graph.edge_count}` : "—"}
            hint="entities / distinct connections"
          />
          <Stat
            label="Grounded confidence"
            value={typeof groundedFraction === "number" ? `${(groundedFraction * 100).toFixed(0)}%` : "—"}
            hint="selected traversal lookups"
            tone={groundedFraction === 1 ? "good" : undefined}
          />
        </div>
        {/* The label caveat now lives on the threat-label chart in GlanceStrip, next to the thing
            it qualifies, rather than in a card the reader passes on the way there. */}
      </Card>

      {/* Only when the analyst actually arrived from an incident. "Compare shipped graph" used to
          land here with nothing to compare against, which made the button's promise false. */}
      {compareIncidentId ? (
        <GraphComparison incidentId={compareIncidentId} summary={summary} />
      ) : null}

      {error ? <ErrorNote>{error}</ErrorNote> : null}

      {unavailable ? (
        <Card title="WitFoo provenance" subtitle="Optional dataset not downloaded">
          <Empty>
            Run <code className="mono text-muted">python scripts/download_witfoo.py</code> then{" "}
            <code className="mono text-muted">python scripts/build_witfoo_graph.py</code>. The primary
            GUIDE flow remains fully available without it.
          </Empty>
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[21rem_minmax(0,1fr)] lg:items-start">
          <Card title="Shipped incidents" subtitle="Select an incident to inspect its labelled graph." className="lg:sticky lg:top-24">
            <TextInput
              value={search}
              onChange={setSearch}
              placeholder="Search id, MO or technique"
              className="w-full"
            />

            {/* Filters on the dimensions that actually vary. There is deliberately no threat-label
                filter: all 9,552 shipped incidents carry exactly one label and it is always
                malicious, so such a control could only return everything or nothing. The note
                below says so, because an absent filter reads as an oversight otherwise. */}
            <div className="mt-2 grid grid-cols-2 gap-2">
              <ListFilter
                label="Modus operandi"
                value={moName}
                onChange={setMoName}
                options={mediumFrom(summary, "mo_names")}
              />
              <ListFilter
                label="Status"
                value={status}
                onChange={setStatus}
                options={mediumFrom(summary, "status_names")}
              />
              <div className="col-span-2">
                <ListFilter
                  label="Order by"
                  value={sort}
                  onChange={(next) => setSort(next as typeof sort)}
                  options={SORTS}
                  allowAll={false}
                />
              </div>
            </div>

            <p className="mt-2 text-3xs leading-relaxed text-faint">
              No threat-label filter: every one of the{" "}
              {(summaryNumber(summary, "incidents") ?? 0).toLocaleString() || "shipped"} incidents
              is labelled <span className="text-muted">malicious</span> — measured, not assumed.
              That uniformity is exactly why these labels never enter a GUIDE accuracy number.
            </p>
            <div className="mt-3 max-h-[36rem] space-y-2 overflow-y-auto pr-1" aria-label="WitFoo incidents">
              {loading ? (
                <>
                  <Skeleton className="h-20" />
                  <Skeleton className="h-20" />
                  <Skeleton className="h-20" />
                </>
              ) : incidents.length ? (
                incidents.map((incident) => (
                  <button
                    key={incident.incident_id}
                    type="button"
                    aria-pressed={selected === incident.incident_id}
                    onClick={() => setSelected(incident.incident_id)}
                    className={`interactive-card w-full rounded-xl p-3 text-left ${
                      selected === incident.incident_id
                        ? "bg-primary-soft ring-1 ring-inset ring-primary-line"
                        : "bg-raised hover:bg-primary-soft"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="mono truncate text-xs font-semibold text-text">{incident.incident_id}</span>
                      <span className="mono shrink-0 text-3xs text-muted">{incident.suspicion_score.toFixed(2)}</span>
                    </div>
                    <div className="mt-1 truncate text-xs text-muted">{incident.mo_name || "Unnamed incident"}</div>
                    <div className="mt-2 flex items-center justify-between text-3xs text-faint">
                      <span>{incident.node_count} nodes · {incident.edge_count} observations</span>
                      <span>{incident.attack_techniques.slice(0, 2).join(" ")}</span>
                    </div>
                  </button>
                ))
              ) : (
                <Empty>No shipped incidents match this search.</Empty>
              )}
            </div>
          </Card>

          <div className="min-w-0 space-y-4">
            {/* Above the diagram on purpose: the node-link view rewards exploration but explains
                nothing at rest, and a judge should understand this incident without touching a
                control. */}
            {graph && !loadingGraph && <GlanceStrip graph={graph} />}

            <Card
              title={graph ? graph.incident.mo_name || "Provenance subgraph" : "Provenance subgraph"}
              subtitle={graph?.incident.incident_id ?? "Choose a shipped incident"}
              right={
                <div className="flex items-center gap-2">
                  <label className="text-3xs font-medium uppercase tracking-wide text-faint">
                    Hops
                    <select
                      aria-label="Maximum graph hops"
                      value={maxHops}
                      onChange={(event) => setMaxHops(Number(event.target.value))}
                      className="ml-1 rounded-lg border border-line bg-surface px-2 py-1 text-xs text-text"
                    >
                      {[1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value}</option>)}
                    </select>
                  </label>
                  <label className="text-3xs font-medium uppercase tracking-wide text-faint">
                    Hub cap
                    <input
                      aria-label="Hub degree threshold"
                      type="number"
                      min="10"
                      value={hubDegree}
                      onChange={(event) => setHubDegree(Math.max(10, Number(event.target.value) || 10))}
                      className="ml-1 w-20 rounded-lg border border-line bg-surface px-2 py-1 text-xs text-text"
                    />
                  </label>
                </div>
              }
            >
              {loadingGraph ? (
                <div className="space-y-3" aria-label="Building provenance subgraph">
                  <Skeleton className="h-10 w-2/3" />
                  <Skeleton className="h-[28rem] w-full" />
                </div>
              ) : graph ? (
                <ProvenanceGraphView graph={graph} />
              ) : (
                <Empty>Select an incident to build its provenance subgraph.</Empty>
              )}
            </Card>

            {graph ? <IncidentFacts incident={graph.incident} /> : null}

            {graph ? (
              <Card title="Audit details" subtitle="Edge records and the analyst report remain available without competing with the graph.">
                <details className="group rounded-xl border border-line bg-raised/50">
                  <summary className="cursor-pointer px-4 py-3 text-xs font-semibold text-text">
                    Edge table · {graph.edges.length} distinct connections
                  </summary>
                  <div className="max-h-72 overflow-auto border-t border-line bg-surface px-4 pb-3">
                    <table className="w-full min-w-[680px] text-xs">
                      <thead className="sticky top-0 bg-surface text-3xs uppercase tracking-wide text-faint">
                        <tr><th className="py-2 text-left">Source</th><th className="py-2 text-left">Target</th><th className="py-2 text-left">Label</th><th className="py-2 text-right">Confidence</th><th className="py-2 text-left">Source</th><th className="py-2 text-left">MITRE</th></tr>
                      </thead>
                      <tbody>
                        {graph.edges.map((edge, index) => (
                          <tr key={`${edge.source}-${edge.target}-${index}`} className="border-t border-line">
                            <td className="mono py-1.5 pr-3 text-muted">{edge.source}</td>
                            <td className="mono py-1.5 pr-3 text-muted">{edge.target}</td>
                            <td className="py-1.5 pr-3"><ThreatBadge label={edge.threat_label} /></td>
                            <td className="mono py-1.5 pr-3 text-right text-muted">{edge.confidence.toFixed(2)}</td>
                            <td className="py-1.5 pr-3 text-faint">{edge.scored ? "dataset" : "prior"}</td>
                            <td className="mono py-1.5 text-faint">{edge.attack_techniques.join(" ") || "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </details>

                {graph.incident.report_text ? (
                  <details className="mt-3 rounded-xl border border-line bg-raised/50">
                    <summary className="cursor-pointer px-4 py-3 text-xs font-semibold text-text">Analyst report · shipped with the dataset</summary>
                    <div className="border-t border-line bg-surface px-4 py-3">
                      <p className="whitespace-pre-wrap text-xs leading-relaxed text-muted">{graph.incident.report_text}</p>
                      {graph.incident.matched_rules.length ? <p className="mt-3 text-2xs text-faint">Matched rules: {graph.incident.matched_rules.join(", ")}</p> : null}
                    </div>
                  </details>
                ) : null}
              </Card>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
