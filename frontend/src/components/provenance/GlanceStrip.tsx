import type { ProvenanceGraph } from "../../lib/api";
import { Card, Kpi, Note, Stat } from "../primitives";

const THREAT_CLASS: Record<string, string> = {
  malicious: "bg-tp",
  suspicious: "bg-bp",
  benign: "bg-fp",
};

const nodeType = (node: string) => (node.includes(":") ? node.slice(0, node.indexOf(":")) : "entity");
const nodeValue = (node: string) => (node.includes(":") ? node.slice(node.indexOf(":") + 1) : node);

/** Every label WitFoo can assign, so "how many are present" has a denominator. */
const ALL_THREAT_LABELS = ["malicious", "suspicious", "benign"] as const;

/**
 * A claim folded away until asked for.
 *
 * Each of these three cards carried a paragraph justifying its method — why Dijkstra costs
 * −log(confidence), why traversal refuses to cross a hub, why WitFoo's labels are not GUIDE's.
 * Every one of those is worth making and none of them is worth more screen than the number it
 * qualifies, which is what was happening: the threat-label card was four lines of amber warning
 * above one line of data. Collapsing them keeps the claim one click away and hands the card back
 * to its own content. The text stays in the DOM, so it remains searchable and reachable.
 */
function Footnote({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <details className="mt-3 border-t border-line pt-2">
      <summary className="cursor-pointer list-none text-3xs font-semibold uppercase tracking-[0.12em] text-faint transition-colors hover:text-primary">
        {label} <span aria-hidden="true">›</span>
      </summary>
      <div className="mt-1.5 text-2xs leading-relaxed text-muted">{children}</div>
    </details>
  );
}

/**
 * The five-second read.
 *
 * The node-link diagram rewards exploration but explains nothing at rest, so these three panels sit
 * above it and answer the questions a viewer actually has: how far can this spread, how strong is
 * the worst link on the likeliest path, and how much of this dataset is malicious at all. No
 * control has to be touched.
 */
export function GlanceStrip({ graph }: { graph: ProvenanceGraph }) {
  const confidences = graph.attack_path?.edge_confidences ?? [];
  const weakest = graph.attack_path?.weakest_link ?? 0;
  const path = graph.attack_path?.path ?? [];
  // Null when the links genuinely differ; a number when they are all the same, which on this
  // dataset is every incident sampled.
  const uniformConfidence =
    confidences.length > 0 && new Set(confidences.map((c) => c.toFixed(4))).size === 1
      ? confidences[0]
      : null;

  const impacted = graph.blast_radius?.impacted_by_type ?? {};
  const blastData = Object.entries(impacted)
    .map(([type, nodes]) => ({ type, count: nodes.length }))
    .sort((a, b) => b.count - a.count);
  const blastMax = Math.max(1, ...blastData.map((row) => row.count));

  const threats = graph.incident?.threat_labels ?? {};
  const threatTotal = Object.values(threats).reduce((sum, value) => sum + value, 0);
  const present = Object.entries(threats).filter(([, count]) => count > 0);
  const dominant = [...present].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      {/* Attack path */}
      <Card className="min-w-0" title="Most probable attack path">
        <div className="grid grid-cols-2 gap-2">
          <Kpi label="Hops" value={graph.attack_path?.hops ?? "—"} />
          <Kpi
            label="Path probability"
            value={
              graph.attack_path?.probability !== undefined
                ? graph.attack_path.probability.toFixed(3)
                : "—"
            }
            hint={weakest ? `weakest link ${weakest.toFixed(2)}` : undefined}
            tone={weakest && weakest < 0.4 ? "warn" : undefined}
          />
        </div>
        {path.length > 1 ? (
          <div className="mt-3">
            <h4 className="text-2xs font-semibold uppercase tracking-wider text-faint">
              The path itself
            </h4>
            <ol aria-label="Attack path, in order" className="mt-2 space-y-0">
              {path.map((node, index) => (
                <li key={`${node}-${index}`}>
                  <div className="flex items-center gap-2">
                    <span
                      aria-hidden="true"
                      className={`h-2 w-2 shrink-0 rounded-full ${
                        index === 0 ? "bg-tp" : index === path.length - 1 ? "bg-primary" : "bg-line-strong"
                      }`}
                    />
                    <span className="mono min-w-0 flex-1 truncate text-2xs text-text" title={node}>
                      {nodeValue(node)}
                    </span>
                    <span className="mono shrink-0 text-3xs text-faint">{nodeType(node)}</span>
                  </div>
                  {index < path.length - 1 && (
                    <div className="ml-[3px] flex items-center gap-2 border-l border-line py-1 pl-[13px]">
                      <span className="mono text-3xs text-muted">
                        {confidences[index] !== undefined
                          ? confidences[index].toFixed(3)
                          : "—"}
                      </span>
                      <span className="text-3xs text-faint">confidence</span>
                    </div>
                  )}
                </li>
              ))}
            </ol>
            {/* Measured, not assumed: across 25 sampled incidents the spread between the highest
                and lowest edge confidence was 0.000 every time. A bar chart of that is a row of
                identical rectangles, which is what used to sit here. */}
            <p className="mt-2 text-2xs leading-relaxed text-faint">
              {uniformConfidence !== null ? (
                <>
                  Every link on this path carries the same confidence,{" "}
                  <span className="mono text-muted">{uniformConfidence.toFixed(3)}</span> — WitFoo
                  scores an incident's edges as a set, so there is no per-hop variation to plot.
                </>
              ) : (
                <>Confidence is shown per link above.</>
              )}
            </p>
          </div>
        ) : (
          <p className="mt-3 text-2xs text-faint">No path found between the seed entities.</p>
        )}
        <Footnote label="Why this path and not a shorter one">
          Dijkstra costs <span className="mono">−log(confidence)</span>, not{" "}
          <span className="mono">1 − confidence</span>: the linear cost prefers a long path
          containing one very weak link, which is exactly the path an attacker cannot take.
        </Footnote>
      </Card>

      {/* Blast radius */}
      <Card className="min-w-0" title="Blast radius">
        <div className="grid grid-cols-2 gap-2">
          <Kpi label="Reachable" value={graph.blast_radius?.total_nodes ?? "—"} hint="entities" />
          <Stat
            label="Hubs blocked"
            value={graph.blast_radius?.hubs_blocked?.length ?? 0}
            tone={graph.blast_radius?.hubs_blocked?.length ? "warn" : undefined}
          />
        </div>
        {blastData.length > 0 && (
          <div className="mt-3">
            <h4 className="text-2xs font-semibold uppercase tracking-wider text-faint">
              Reachable entities by type
            </h4>
            {/* 19 of 25 sampled incidents reach exactly one entity type and 6 reach none, so a bar
                chart here was a single lonely bar in an axis frame. Rows carry the same
                information and read correctly at one type or at seven. */}
            <ul aria-label="Reachable entities by type" className="mt-2 space-y-1.5">
              {blastData.map((row) => (
                <li key={row.type} className="flex items-center gap-2">
                  <span className="w-20 shrink-0 truncate text-2xs text-muted">{row.type}</span>
                  <span className="h-2 min-w-0 flex-1 overflow-hidden rounded-full bg-raised">
                    <span
                      className="block h-full rounded-full bg-primary"
                      style={{ width: `${(row.count / blastMax) * 100}%` }}
                    />
                  </span>
                  <span className="mono w-8 shrink-0 text-right text-2xs text-text">
                    {row.count}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {graph.blast_radius?.truncated && (
          <Note tone="warn">
            Truncated at the traversal cap — the true reachable set is larger than shown.
          </Note>
        )}
        <Footnote label="Why the count stops where it does">
          Traversal never expands through a hub. Blocking them is what keeps this a blast radius
          rather than most of the graph.
        </Footnote>
      </Card>

      {/* Threat labels */}
      <Card className="min-w-0" title="Threat labels on this incident">
        {threatTotal > 0 ? (
          <>
            {/* How much variety there actually is, stated rather than left to be inferred from a
                bar that reads as solid when one label holds every edge — which is the common
                case here, and the most misleading one to show without saying so. */}
            <div className="mb-2 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
              <span className="text-2xs text-muted">
                <strong className="text-text">{present.length}</strong> of{" "}
                {ALL_THREAT_LABELS.length} labels present
              </span>
              <span className="mono text-2xs text-faint">
                {threatTotal.toLocaleString()} edges
              </span>
            </div>
            {present.length === 1 && (
              <p className="mb-2 text-2xs leading-relaxed text-muted">
                Every edge on this incident carries the same label
                {dominant ? ` (${dominant})` : ""}, so the bar below is one colour by fact, not by
                rounding.
              </p>
            )}
            <div className="flex h-3 overflow-hidden rounded-full bg-line">
              {Object.entries(threats).map(([label, count]) => (
                <div
                  key={label}
                  className={THREAT_CLASS[label] ?? "bg-primary-line"}
                  style={{ width: `${(count / threatTotal) * 100}%` }}
                  title={`${label}: ${count.toLocaleString()}`}
                />
              ))}
            </div>
            <ul className="mt-2 space-y-1">
              {Object.entries(threats)
                .sort((a, b) => b[1] - a[1])
                .map(([label, count]) => (
                  <li key={label} className="flex items-center gap-2 text-2xs text-muted">
                    <span
                      aria-hidden="true"
                      className={`h-2 w-2 rounded-full ${THREAT_CLASS[label] ?? "bg-primary-line"}`}
                    />
                    <span className="flex-1 capitalize">{label}</span>
                    <span className="mono text-text">{count.toLocaleString()}</span>
                    <span className="w-10 text-right text-faint">
                      {((count / threatTotal) * 100).toFixed(0)}%
                    </span>
                  </li>
                ))}
            </ul>
          </>
        ) : (
          <p className="text-2xs text-faint">No threat labels on this incident's edges.</p>
        )}

        <Footnote label="Not GUIDE triage verdicts">
          These are WitFoo <strong>threat assessments</strong> — benign, suspicious, malicious. They
          are not GUIDE's analyst triage verdicts, and they are excluded from every accuracy number
          reported anywhere in this app. Two different judgements should not be averaged because both
          are called labels.
        </Footnote>
      </Card>
    </div>
  );
}
