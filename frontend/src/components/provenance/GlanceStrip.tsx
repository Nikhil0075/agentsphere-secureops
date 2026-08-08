import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { ProvenanceGraph } from "../../lib/api";
import {
  axisProps,
  ChartFrame,
  chartTooltipStyle,
  gridProps,
  useReducedMotion,
  useThemeTokens,
} from "../charts";
import { Card, Kpi, Note, Stat } from "../primitives";

const THREAT_CLASS: Record<string, string> = {
  malicious: "bg-tp",
  suspicious: "bg-bp",
  benign: "bg-fp",
};

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
  const tokens = useThemeTokens();
  const reduced = useReducedMotion();

  const confidences = graph.attack_path?.edge_confidences ?? [];
  const weakest = graph.attack_path?.weakest_link ?? 0;
  const pathData = confidences.map((confidence, index) => ({
    hop: `${index + 1}`,
    confidence: Number(confidence.toFixed(3)),
  }));

  const impacted = graph.blast_radius?.impacted_by_type ?? {};
  const blastData = Object.entries(impacted)
    .map(([type, nodes]) => ({ type, count: nodes.length }))
    .sort((a, b) => b.count - a.count);

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
        {pathData.length > 0 ? (
          <div className="mt-3">
            <ChartFrame title="Confidence per hop" height={140}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={pathData} margin={{ left: -22, right: 8, top: 4, bottom: 0 }}>
                  <CartesianGrid {...gridProps(tokens)} />
                  <XAxis dataKey="hop" {...axisProps(tokens)} />
                  <YAxis domain={[0, 1]} {...axisProps(tokens)} />
                  <Tooltip {...chartTooltipStyle(tokens)} cursor={{ fill: tokens.raised }} />
                  {weakest > 0 && (
                    <ReferenceLine
                      y={weakest}
                      stroke={tokens.tp}
                      strokeDasharray="4 3"
                      label={{ value: "weakest", fontSize: 9, fill: tokens.tp, position: "right" }}
                    />
                  )}
                  <Bar dataKey="confidence" radius={[3, 3, 0, 0]} isAnimationActive={!reduced}>
                    {/* Printed, because hops on this dataset routinely differ in the second
                        decimal — a difference no bar height at this size can carry. */}
                    <LabelList
                      dataKey="confidence"
                      position="top"
                      fontSize={9}
                      fill={tokens.muted}
                    />
                    {pathData.map((row) => (
                      <Cell
                        key={row.hop}
                        fill={
                          row.confidence >= 0.66
                            ? tokens.fp
                            : row.confidence >= 0.33
                              ? tokens.bp
                              : tokens.tp
                        }
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </ChartFrame>
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
            <ChartFrame
              title="Reachable entities by type"
              height={Math.max(120, blastData.length * 26)}
            >
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={blastData}
                  layout="vertical"
                  margin={{ left: 4, right: 12, top: 0, bottom: 0 }}
                >
                  <XAxis type="number" {...axisProps(tokens)} />
                  <YAxis type="category" dataKey="type" width={72} {...axisProps(tokens)} />
                  <Tooltip {...chartTooltipStyle(tokens)} cursor={{ fill: tokens.raised }} />
                  <Bar
                    dataKey="count"
                    fill={tokens.primary}
                    radius={[0, 3, 3, 0]}
                    isAnimationActive={!reduced}
                  />
                </BarChart>
              </ResponsiveContainer>
            </ChartFrame>
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
