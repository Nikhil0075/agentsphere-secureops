import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
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

/** Per-agent latency. On the deterministic backend every bar is ~0, which is itself the point. */
export function LatencyChart({ latency }: { latency?: Record<string, { mean: number; max: number }> }) {
  const tokens = useThemeTokens();
  const reduced = useReducedMotion();
  const entries = Object.entries(latency ?? {});
  if (!entries.length) return null;

  const data = entries.map(([agent, value]) => ({
    agent,
    mean: Math.round(value?.mean ?? 0),
    max: Math.round(value?.max ?? 0),
  }));
  const allZero = data.every((row) => row.mean === 0 && row.max === 0);

  return (
    <ChartFrame
      title="Latency per agent"
      height={200}
      caption={
        allZero
          ? "All zero: this evaluation ran on the deterministic backend, which is pure Python and never leaves the process. It measures plumbing, not reasoning."
          : "Mean and worst case per stage. The judge models are the slow ones — they carry the calls that decide."
      }
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ left: -14, right: 8, top: 4, bottom: 4 }}>
          <CartesianGrid {...gridProps(tokens)} />
          <XAxis dataKey="agent" {...axisProps(tokens)} interval={0} angle={-18} textAnchor="end" height={52} />
          <YAxis {...axisProps(tokens)} unit="ms" />
          <Tooltip {...chartTooltipStyle(tokens)} cursor={{ fill: tokens.raised }} />
          <Bar dataKey="max" fill={tokens.primaryLine} radius={[3, 3, 0, 0]} isAnimationActive={!reduced} />
          <Bar dataKey="mean" fill={tokens.primary} radius={[3, 3, 0, 0]} isAnimationActive={!reduced} />
        </BarChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}

/** Verifier verdict split. */
export function VerdictDonut({ verdicts }: { verdicts?: Record<string, number> }) {
  const tokens = useThemeTokens();
  const reduced = useReducedMotion();
  const entries = Object.entries(verdicts ?? {}).filter(([, count]) => count > 0);
  if (!entries.length) return null;

  const data = entries.map(([verdict, count]) => ({ name: verdict, value: count }));
  const total = data.reduce((sum, row) => sum + row.value, 0);

  return (
    <ChartFrame
      title="Verifier verdicts"
      height={200}
      caption={
        <>
          {total.toLocaleString()} decisions. Left to itself the live model rejected 40 of 40 real
          incidents citing evidence gaps, so the structural checks run in code on every backend: the
          model may escalate freely, but may only <em>reject</em> where a check actually failed.
        </>
      }
    >
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius="58%"
            outerRadius="82%"
            paddingAngle={2}
            isAnimationActive={!reduced}
          >
            {data.map((row) => (
              <Cell key={row.name} fill={toneFor(tokens, row.name)} />
            ))}
          </Pie>
          <Tooltip {...chartTooltipStyle(tokens)} />
        </PieChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}

/** Entity-type mix in the built graph. */
export function EntityTypeDonut({ byType }: { byType?: Record<string, number> }) {
  const tokens = useThemeTokens();
  const reduced = useReducedMotion();
  const entries = Object.entries(byType ?? {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return null;

  const palette = [
    tokens.primary,
    tokens.info,
    tokens.fp,
    tokens.bp,
    tokens.tp,
    tokens.primaryLine,
    tokens.faint,
  ];
  const data = entries.map(([name, value]) => ({ name, value }));

  return (
    <ChartFrame
      title="Graph nodes by entity type"
      height={200}
      caption="GUIDE ships no graph. These nodes are built from evidence co-occurrence within an alert — not within an incident, because a 1,313-row incident would otherwise produce a near-complete graph."
    >
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius="52%"
            outerRadius="80%"
            paddingAngle={2}
            isAnimationActive={!reduced}
          >
            {data.map((row, index) => (
              <Cell key={row.name} fill={palette[index % palette.length]} />
            ))}
          </Pie>
          <Tooltip {...chartTooltipStyle(tokens)} />
        </PieChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}

/** Worst hubs by degree — the reason traversal is capped. */
export function HubsChart({ hubs }: { hubs?: { node: string; degree: number }[] }) {
  const tokens = useThemeTokens();
  const reduced = useReducedMotion();
  if (!hubs?.length) return null;

  const data = hubs
    .slice(0, 12)
    .map((hub) => ({ node: hub.node, degree: hub.degree }))
    .sort((a, b) => b.degree - a.degree);
  const worst = data[0]?.degree ?? 0;

  return (
    <ChartFrame
      title={`Worst hubs (top ${data.length})`}
      height={280}
      caption={
        <>
          Traversal never expands <em>through</em> a hub. An uncapped breadth-first search from the
          worst one at degree {worst.toLocaleString()} returns most of the graph and freezes the
          demo, so depth and hub degree are both capped.
        </>
      }
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 12, top: 4, bottom: 4 }}>
          <CartesianGrid {...gridProps(tokens)} horizontal={false} vertical />
          <XAxis type="number" {...axisProps(tokens)} />
          <YAxis type="category" dataKey="node" width={128} {...axisProps(tokens)} />
          <Tooltip {...chartTooltipStyle(tokens)} cursor={{ fill: tokens.raised }} />
          <Bar dataKey="degree" radius={[0, 3, 3, 0]} isAnimationActive={!reduced}>
            {data.map((row, index) => (
              <Cell key={row.node} fill={index === 0 ? tokens.tp : tokens.primary} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}
