import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  axisProps,
  ChartFrame,
  chartTooltipStyle,
  gridProps,
  toneFor,
  useReducedMotion,
  useThemeTokens,
} from "../charts";
import { Note } from "../primitives";

const LABELS = ["TruePositive", "BenignPositive", "FalsePositive"] as const;
const SHORT: Record<string, string> = {
  TruePositive: "TP",
  BenignPositive: "BP",
  FalsePositive: "FP",
};

/**
 * The confusion matrix as a heatmap.
 *
 * Hand-built rather than Recharts — it has no heatmap primitive, and a 3x3 grid of divs is both
 * simpler and more accessible than coercing a scatter chart into one.
 */
export function ConfusionHeatmap({ matrix }: { matrix?: Record<string, any> }) {
  const labels: string[] = matrix?.labels ?? [];
  const rows: number[][] = matrix?.matrix ?? [];
  if (!labels.length || !rows.length) return null;

  const max = Math.max(...rows.flat(), 1);

  return (
    <ChartFrame
      title="Confusion matrix"
      height={undefined as unknown as number}
      caption={
        <>
          Rows are the <strong>actual</strong> label, columns the prediction — the diagonal is
          correct. Off-diagonal cells are where the baseline is wrong, and the top-right corner
          (true positives called false) is the expensive kind.
        </>
      }
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[20rem] border-collapse text-center text-xs">
          <thead>
            <tr>
              <th className="p-1 text-left text-3xs font-medium uppercase tracking-wider text-faint">
                actual ↓ / predicted →
              </th>
              {labels.map((label) => (
                <th key={label} className="p-1 text-3xs font-medium text-muted">
                  {SHORT[label] ?? label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, r) => (
              <tr key={labels[r]}>
                <th className="p-1 text-left text-3xs font-medium text-muted">
                  {SHORT[labels[r]] ?? labels[r]}
                </th>
                {row.map((value, c) => (
                  <td key={c} className="p-0.5">
                    <div
                      className={`mono rounded-md px-2 py-2.5 font-semibold ${
                        r === c ? "ring-1 ring-fp-line" : ""
                      }`}
                      style={{
                        background: `color-mix(in srgb, var(--color-primary) ${Math.round(
                          (value / max) * 70,
                        )}%, var(--color-surface))`,
                        color: value / max > 0.55 ? "#fff" : "var(--color-text)",
                      }}
                      title={`actual ${labels[r]} → predicted ${labels[c]}: ${value}`}
                    >
                      {value}
                    </div>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </ChartFrame>
  );
}

/** Top feature weights. `hour_of_day` is flagged because the README already discloses it. */
export function FeatureImportanceChart({ importance }: { importance?: Record<string, number> }) {
  const tokens = useThemeTokens();
  const reduced = useReducedMotion();
  const entries = Object.entries(importance ?? {});
  if (!entries.length) return null;

  const data = entries
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([name, weight]) => ({ name, weight: Number(weight.toFixed(4)) }));

  const suspect = data.some((row) => row.name === "hour_of_day");

  return (
    <ChartFrame
      title={`Feature importance (top ${data.length} of ${entries.length})`}
      height={300}
      caption={
        suspect ? (
          <Note tone="warn">
            <span className="mono">hour_of_day</span> ranks first. That is more likely a temporal
            artefact of how GUIDE was collected than a security signal, and it is worth pruning
            before any of these numbers are quoted as evidence the model learned something real.
          </Note>
        ) : undefined
      }
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 12, top: 4, bottom: 4 }}>
          <CartesianGrid {...gridProps(tokens)} horizontal={false} vertical />
          <XAxis type="number" {...axisProps(tokens)} />
          <YAxis type="category" dataKey="name" width={132} {...axisProps(tokens)} />
          <Tooltip {...chartTooltipStyle(tokens)} cursor={{ fill: tokens.raised }} />
          <Bar dataKey="weight" radius={[0, 3, 3, 0]} isAnimationActive={!reduced}>
            {data.map((row) => (
              <Cell key={row.name} fill={row.name === "hour_of_day" ? tokens.bp : tokens.primary} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}

/** Precision / recall / F1 per class, baseline against agents where both exist. */
export function PerClassChart({
  baseline,
  agents,
}: {
  baseline?: Record<string, any>;
  agents?: Record<string, any>;
}) {
  const tokens = useThemeTokens();
  const reduced = useReducedMotion();
  if (!baseline) return null;

  const data = LABELS.flatMap((label) => {
    const b = baseline[label];
    if (!b) return [];
    const a = agents?.[label];
    return [
      {
        name: SHORT[label],
        precision: b.precision,
        recall: b.recall,
        f1: b.f1,
        support: b.support,
        agentF1: a?.f1,
      },
    ];
  });
  if (!data.length) return null;

  return (
    <ChartFrame
      title="Per class"
      height={220}
      caption={`Support: ${data.map((row) => `${row.name} ${row.support}`).join(" · ")}. Recall on TruePositive is the number that matters — a missed attack is the dangerous failure.`}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ left: -18, right: 8, top: 4, bottom: 4 }}>
          <CartesianGrid {...gridProps(tokens)} />
          <XAxis dataKey="name" {...axisProps(tokens)} />
          <YAxis domain={[0, 1]} {...axisProps(tokens)} />
          <Tooltip {...chartTooltipStyle(tokens)} cursor={{ fill: tokens.raised }} />
          <Bar dataKey="precision" fill={tokens.primary} radius={[3, 3, 0, 0]} isAnimationActive={!reduced} />
          <Bar dataKey="recall" fill={tokens.info} radius={[3, 3, 0, 0]} isAnimationActive={!reduced} />
          <Bar dataKey="f1" fill={tokens.primaryLine} radius={[3, 3, 0, 0]} isAnimationActive={!reduced} />
          {data.some((row) => row.agentF1 !== undefined) && (
            <Bar dataKey="agentF1" fill={tokens.bp} radius={[3, 3, 0, 0]} isAnimationActive={!reduced} />
          )}
        </BarChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}

/** Train and validation label distribution, stacked. */
export function LabelDistributionChart({ dataset }: { dataset?: Record<string, any> }) {
  const tokens = useThemeTokens();
  const reduced = useReducedMotion();
  const train = dataset?.train_label_distribution;
  const val = dataset?.val_label_distribution;
  if (!train && !val) return null;

  const data = [
    { split: "train", ...(train ?? {}) },
    { split: "val", ...(val ?? {}) },
  ];

  return (
    <ChartFrame
      title="Label distribution"
      height={160}
      caption="Class balance across the split. Macro-F1 is reported precisely because accuracy flatters an imbalanced set."
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 4, right: 12, top: 4, bottom: 4 }}>
          <XAxis type="number" {...axisProps(tokens)} />
          <YAxis type="category" dataKey="split" width={44} {...axisProps(tokens)} />
          <Tooltip {...chartTooltipStyle(tokens)} cursor={{ fill: tokens.raised }} />
          {LABELS.map((label) => (
            <Bar
              key={label}
              dataKey={label}
              stackId="labels"
              fill={toneFor(tokens, label)}
              isAnimationActive={!reduced}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}
