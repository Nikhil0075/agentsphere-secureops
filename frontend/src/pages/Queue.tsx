import { useEffect, useState } from "react";
import { api, type IncidentSummary } from "../lib/api";
import { Badge, Card, Empty, ErrorNote, LabelBadge, Spinner } from "../components/primitives";

/** Scene 1 of the demo arc: a real, high-volume queue, ordered by the risk heap. */
export function Queue({
  selected,
  onSelect,
}: {
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const [rows, setRows] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showcaseOnly, setShowcaseOnly] = useState(false);
  const [label, setLabel] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const timer = setTimeout(() => {
      api
        .incidents({ limit: 60, showcase_only: showcaseOnly, label, search })
        .then((data) => !cancelled && setRows(data))
        .catch((e) => !cancelled && setError(String(e.message)))
        .finally(() => !cancelled && setLoading(false));
    }, search ? 250 : 0); // debounce typing, but never delay a filter click
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [showcaseOnly, label, search]);

  return (
    <Card
      title="Incident queue"
      subtitle="Ordered by a max-heap over the normalised risk score. Highest risk first."
      right={
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search id or summary"
            className="w-44 rounded border border-ink-700 bg-ink-850 px-2 py-1 text-xs text-ink-200 placeholder:text-ink-600 focus:border-accent focus:outline-none"
          />
          <select
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            className="rounded border border-ink-700 bg-ink-850 px-2 py-1 text-xs text-ink-200 focus:border-accent focus:outline-none"
          >
            <option value="">All labels</option>
            <option value="TruePositive">True positive</option>
            <option value="BenignPositive">Benign positive</option>
            <option value="FalsePositive">False positive</option>
          </select>
          <label className="flex items-center gap-1.5 text-xs text-ink-300">
            <input
              type="checkbox"
              checked={showcaseOnly}
              onChange={(e) => setShowcaseOnly(e.target.checked)}
              className="accent-accent"
            />
            Showcase
          </label>
        </div>
      }
    >
      {error && <ErrorNote>{error}</ErrorNote>}
      {loading && <Spinner label="Loading queue…" />}

      {!loading && rows.length === 0 && <Empty>No incidents match those filters.</Empty>}

      {!loading && rows.length > 0 && (
        <div className="-mx-4 -mb-4 overflow-x-auto">
          <table className="w-full min-w-[820px] text-sm">
            <thead>
              <tr className="border-b border-ink-800 text-left text-[11px] uppercase tracking-wide text-ink-400">
                <th className="px-4 py-2 font-medium">Risk</th>
                <th className="px-2 py-2 font-medium">Incident</th>
                <th className="px-2 py-2 font-medium">Truth</th>
                <th className="px-2 py-2 font-medium">Baseline</th>
                <th className="px-2 py-2 font-medium">Category</th>
                <th className="px-2 py-2 text-right font-medium">Alerts</th>
                <th className="px-2 py-2 text-right font-medium">Evidence</th>
                <th className="px-4 py-2 font-medium">Suspicion</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.incident_id}
                  onClick={() => onSelect(row.incident_id)}
                  className={`cursor-pointer border-b border-ink-850 transition-colors hover:bg-ink-850 ${
                    selected === row.incident_id ? "bg-accent/10" : ""
                  }`}
                >
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-12 overflow-hidden rounded-full bg-ink-800">
                        <div
                          className="h-full rounded-full bg-accent"
                          style={{ width: `${Math.min(100, row.risk_score * 100)}%` }}
                        />
                      </div>
                      <span className="mono text-xs text-ink-300">
                        {row.risk_score.toFixed(3)}
                      </span>
                    </div>
                  </td>
                  <td className="mono px-2 py-2 text-xs text-ink-200">
                    {row.incident_id}
                    {row.is_showcase && (
                      <span className="ml-1.5 text-[10px] text-accent">★</span>
                    )}
                  </td>
                  <td className="px-2 py-2">
                    <LabelBadge label={row.label} />
                  </td>
                  <td className="px-2 py-2">
                    {row.baseline_label ? (
                      <span
                        className={`text-xs ${
                          row.baseline_label === row.label ? "text-ink-400" : "text-bp"
                        }`}
                        title={
                          row.baseline_label === row.label
                            ? "baseline agrees with ground truth"
                            : "baseline disagrees with ground truth"
                        }
                      >
                        {row.baseline_label.replace("Positive", "")}{" "}
                        {(row.baseline_confidence * 100).toFixed(0)}%
                      </span>
                    ) : (
                      <span className="text-ink-600">—</span>
                    )}
                  </td>
                  <td className="px-2 py-2 text-xs text-ink-300">{row.top_category || "—"}</td>
                  <td className="px-2 py-2 text-right text-xs text-ink-300">{row.alert_count}</td>
                  <td className="px-2 py-2 text-right text-xs text-ink-300">
                    {row.evidence_count}
                  </td>
                  <td className="px-4 py-2">
                    {row.max_suspicion_level ? (
                      <Badge>{row.max_suspicion_level}</Badge>
                    ) : (
                      <span className="text-ink-600">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
