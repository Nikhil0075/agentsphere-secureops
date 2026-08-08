import { useEffect, useMemo, useState } from "react";
import { api, type IncidentPage, type IncidentSummary, type QueueSort } from "../lib/api";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNote,
  LabelBadge,
  PageIntro,
  SegmentedFilter,
  Skeleton,
  TextInput,
  Toolbar,
} from "../components/primitives";

type QueueTab = "all" | "showcase" | "demo";
type SortDirection = "asc" | "desc";

const sortLabels: Record<QueueSort, string> = {
  risk: "Risk",
  incident: "Incident",
  first_seen: "First seen",
  alerts: "Alerts",
  evidence: "Evidence",
  baseline_confidence: "Baseline",
  demo_rank: "Case",
};

/** The arc is six cases by construction, so it is always exactly one page. */
const ARC_SIZE = 6;

export function Queue({
  selected,
  onSelect,
}: {
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const [data, setData] = useState<IncidentPage | null>(null);
  // The arc is held separately from the table on purpose. "Next demo" used to walk `data.items`,
  // which is one paginated page, so with the default page size of 25 it could never reach cases
  // beyond the first page and a filter could drop cases out of the walk entirely.
  const [arc, setArc] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<QueueTab>("all");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [label, setLabel] = useState("");
  const [category, setCategory] = useState("");
  const [suspicion, setSuspicion] = useState("");
  const [minRisk, setMinRisk] = useState(0);
  const [baselineStatus, setBaselineStatus] = useState("");
  const [sortBy, setSortBy] = useState<QueueSort>("risk");
  const [sortDir, setSortDir] = useState<SortDirection>("desc");
  const [pageSize, setPageSize] = useState(25);
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), search ? 250 : 0);
    return () => clearTimeout(timer);
  }, [search]);

  useEffect(() => {
    setOffset(0);
  }, [tab, debouncedSearch, label, category, suspicion, minRisk, baselineStatus, sortBy, sortDir, pageSize]);

  // Fetched once, deliberately with no dependency on filters, sorting or paging: this is the
  // narration order, and it must not change because the analyst typed into the search box.
  useEffect(() => {
    let cancelled = false;
    api
      .queryIncidents({
        limit: ARC_SIZE,
        demo_only: true,
        sort_by: "demo_rank",
        sort_dir: "asc",
      })
      .then((result) => !cancelled && setArc(result.items))
      .catch(() => !cancelled && setArc([]));
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    const isArc = tab === "demo";
    api
      .queryIncidents({
        // The arc is six rows, so it is pinned to one page in rank order. Paging cannot
        // reintroduce the walk bug if there is never a second page.
        limit: isArc ? ARC_SIZE : pageSize,
        offset: isArc ? 0 : offset,
        demo_only: isArc || undefined,
        showcase_only: tab === "showcase" || undefined,
        label,
        category,
        suspicion,
        min_risk: minRisk,
        baseline_status: baselineStatus,
        search: debouncedSearch,
        sort_by: isArc ? "demo_rank" : sortBy,
        sort_dir: isArc ? "asc" : sortDir,
      })
      .then((result) => !cancelled && setData(result))
      .catch((reason) => !cancelled && setError(String(reason.message ?? reason)))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [tab, debouncedSearch, label, category, suspicion, minRisk, baselineStatus, sortBy, sortDir, pageSize, offset]);

  const rows = data?.items ?? [];
  // The arc tab pins its own page size, so the counter must not report the select's value.
  const effectivePageSize = tab === "demo" ? ARC_SIZE : pageSize;
  const effectiveOffset = tab === "demo" ? 0 : offset;
  const page = Math.floor(effectiveOffset / effectivePageSize) + 1;
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / effectivePageSize));
  const filtersActive = Boolean(search || label || category || suspicion || minRisk || baselineStatus);

  const range = useMemo(() => {
    if (!data?.total) return "0 results";
    return `${effectiveOffset + 1}–${Math.min(effectiveOffset + effectivePageSize, data.total)} of ${data.total.toLocaleString()}`;
  }, [data, effectiveOffset, effectivePageSize]);

  const resetFilters = () => {
    setSearch("");
    setLabel("");
    setCategory("");
    setSuspicion("");
    setMinRisk(0);
    setBaselineStatus("");
  };

  const toggleSort = (next: QueueSort) => {
    if (sortBy === next) setSortDir((current) => (current === "desc" ? "asc" : "desc"));
    else {
      setSortBy(next);
      setSortDir(next === "incident" || next === "first_seen" ? "asc" : "desc");
    }
  };

  // Walks the whole arc, not the visible page: unaffected by page size, filters or sort order,
  // and wraps from the last case back to the first. An unselected or off-arc incident starts at
  // case 1, because findIndex returns -1.
  const arcPosition = arc.findIndex((row) => row.incident_id === selected);
  const openNextDemo = () => {
    if (!arc.length) return;
    onSelect(arc[(arcPosition + 1) % arc.length].incident_id);
  };
  const nextDemoLabel = arc.length
    ? `Next demo (${((arcPosition + 1) % arc.length) + 1} of ${arc.length})`
    : "Next demo";

  const sortableHeading = (key: QueueSort, align = "left") => (
    <button
      type="button"
      onClick={() => toggleSort(key)}
      className={`inline-flex items-center gap-1 hover:text-primary ${align === "right" ? "justify-end" : ""}`}
      aria-label={`Sort by ${sortLabels[key]}`}
    >
      {sortLabels[key]}
      <span aria-hidden="true" className={sortBy === key ? "text-primary" : "text-faint"}>
        {sortBy === key ? (sortDir === "asc" ? "↑" : "↓") : "↕"}
      </span>
    </button>
  );

  return (
    <div className="space-y-4">
      <PageIntro
        eyebrow="Scene 1 · Alert overload"
        title="Start with the incidents that matter most."
        description="Search, filter, and sort the complete GUIDE queue—or switch to a stable set of presentation-ready incidents."
        actions={
          <SegmentedFilter
            label="Ticket set"
            value={tab}
            options={[
              { value: "all", label: "All tickets" },
              { value: "showcase", label: "Showcase" },
              { value: "demo", label: `Demo arc (${arc.length || ARC_SIZE})` },
            ]}
            onChange={setTab}
          />
        }
      />

      <Card
        title={tab === "demo" ? "Demo arc" : tab === "showcase" ? "Showcase pool" : "Incident queue"}
        subtitle={
          tab === "demo"
            ? "Six curated cases in narration order, spanning all three labels and the full risk range. Presentation only — no reported metric is computed over them."
            : tab === "showcase"
              ? "The 30-case showcase pool, filtered to a 3–60 evidence band. Correlation and rehearsal numbers run over this set."
              : "Filtering and sorting run over the full incident corpus, not only the visible page."
        }
        pad={false}
        right={tab === "demo" ? <Button variant="primary" onClick={openNextDemo} disabled={!arc.length}>{nextDemoLabel}</Button> : null}
      >
        <div className="border-b border-line px-5 py-4">
          <Toolbar>
            <TextInput value={search} onChange={setSearch} placeholder="Search incident or alert" className="w-52" />
            <select aria-label="Filter by label" value={label} onChange={(event) => setLabel(event.target.value)} className="queue-select">
              <option value="">All labels</option>
              <option value="TruePositive">True positive</option>
              <option value="BenignPositive">Benign positive</option>
              <option value="FalsePositive">False positive</option>
            </select>
            <select aria-label="Filter by category" value={category} onChange={(event) => setCategory(event.target.value)} className="queue-select max-w-44">
              <option value="">All categories</option>
              {(data?.facets.categories ?? []).map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
            <select aria-label="Filter by suspicion" value={suspicion} onChange={(event) => setSuspicion(event.target.value)} className="queue-select">
              <option value="">All suspicion</option>
              {(data?.facets.suspicions ?? []).map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
            <select aria-label="Minimum risk" value={minRisk} onChange={(event) => setMinRisk(Number(event.target.value))} className="queue-select">
              <option value={0}>Any risk</option>
              <option value={0.35}>Risk ≥ 0.35</option>
              <option value={0.6}>Risk ≥ 0.60</option>
              <option value={0.8}>Risk ≥ 0.80</option>
            </select>
            <select aria-label="Filter by baseline agreement" value={baselineStatus} onChange={(event) => setBaselineStatus(event.target.value)} className="queue-select">
              <option value="">Any baseline</option>
              <option value="agree">Agrees</option>
              <option value="disagree">Disagrees</option>
              <option value="unavailable">Unavailable</option>
            </select>
            {filtersActive ? <button type="button" onClick={resetFilters} className="px-2 py-1.5 text-xs font-semibold text-primary hover:underline">Reset</button> : null}
          </Toolbar>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 text-xs text-muted">
          <span aria-live="polite">{loading ? "Loading tickets…" : range}</span>
          <div className="flex items-center gap-2">
            <label htmlFor="queue-page-size">Rows</label>
            <select id="queue-page-size" value={pageSize} onChange={(event) => setPageSize(Number(event.target.value))} className="queue-select py-1">
              <option value={25}>25</option><option value={50}>50</option><option value={100}>100</option>
            </select>
          </div>
        </div>

        {error ? <div className="px-5 pb-4"><ErrorNote>{error}</ErrorNote></div> : null}
        {loading ? (
          <div className="space-y-2 px-5 pb-5" aria-label="Loading queue">
            {Array.from({ length: 6 }, (_, index) => <Skeleton key={index} className="h-11 w-full" />)}
          </div>
        ) : rows.length === 0 ? (
          <div className="px-5 pb-5"><Empty>No tickets match this view. Reset the filters or choose another ticket set.</Empty></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1080px] text-sm">
              <thead>
                <tr className="border-y border-line bg-raised/70 text-left text-2xs font-medium uppercase tracking-wider text-faint">
                  <th className="px-5 py-2.5" aria-sort={sortBy === "risk" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>{sortableHeading("risk")}</th>
                  <th className="px-2 py-2.5" aria-sort={sortBy === "incident" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>{sortableHeading("incident")}</th>
                  <th className="px-2 py-2.5">Truth</th>
                  <th className="px-2 py-2.5" aria-sort={sortBy === "baseline_confidence" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>{sortableHeading("baseline_confidence")}</th>
                  <th className="px-2 py-2.5">Category</th>
                  <th className="px-2 py-2.5" aria-sort={sortBy === "first_seen" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>{sortableHeading("first_seen")}</th>
                  <th className="px-2 py-2.5 text-right" aria-sort={sortBy === "alerts" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>{sortableHeading("alerts", "right")}</th>
                  <th className="px-2 py-2.5 text-right" aria-sort={sortBy === "evidence" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>{sortableHeading("evidence", "right")}</th>
                  <th className="px-5 py-2.5">Suspicion</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => <QueueRow key={row.incident_id} row={row} selected={selected === row.incident_id} onSelect={onSelect} />)}
              </tbody>
            </table>
          </div>
        )}

        <div className="flex items-center justify-between gap-3 border-t border-line px-5 py-4 text-xs text-muted">
          <span>Page {page} of {pages}</span>
          <div className="flex gap-2">
            <Button onClick={() => setOffset(Math.max(0, offset - pageSize))} disabled={effectiveOffset === 0}>Previous</Button>
            <Button onClick={() => setOffset(offset + pageSize)} disabled={effectiveOffset + effectivePageSize >= (data?.total ?? 0)}>Next</Button>
          </div>
        </div>
      </Card>
    </div>
  );
}

function QueueRow({ row, selected, onSelect }: { row: IncidentSummary; selected: boolean; onSelect: (id: string) => void }) {
  return (
    <tr
      tabIndex={0}
      aria-selected={selected}
      onClick={() => onSelect(row.incident_id)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect(row.incident_id);
        }
      }}
      className={`cursor-pointer border-b border-line/70 transition-colors hover:bg-primary-soft focus:outline-none focus:ring-2 focus:ring-inset focus:ring-primary ${selected ? "bg-primary-soft" : "odd:bg-raised/35"}`}
    >
      <td className="px-5 py-3"><div className="flex items-center gap-2"><div className="h-1.5 w-12 overflow-hidden rounded-full bg-line"><div className="h-full rounded-full bg-primary" style={{ width: `${Math.min(100, row.risk_score * 100)}%` }} /></div><span className="mono text-xs font-semibold text-text">{row.risk_score.toFixed(3)}</span></div></td>
      <td className="px-2 py-3">
        <span className="mono text-xs text-text">{row.incident_id}</span>
        {row.demo_rank !== null ? (
          <span
            className="ml-1.5 rounded bg-primary-soft px-1 text-3xs font-semibold text-primary"
            title={`Demo case ${row.demo_rank} — ${row.demo_role.replace(/_/g, " ")}`}
          >
            {row.demo_rank}
          </span>
        ) : row.is_showcase ? (
          <span className="ml-1.5 text-3xs text-bp" title="Showcase incident">★</span>
        ) : null}
      </td>
      <td className="px-2 py-3"><LabelBadge label={row.label} /></td>
      <td className="px-2 py-3 text-xs text-muted">{row.baseline_label ? <span className={row.baseline_label === row.label ? "" : "font-semibold text-bp"}>{row.baseline_label.replace("Positive", "")} {(row.baseline_confidence * 100).toFixed(0)}%</span> : "—"}</td>
      <td className="max-w-40 truncate px-2 py-3 text-xs text-muted" title={row.top_category}>{row.top_category || "—"}</td>
      <td className="px-2 py-3 text-xs text-muted">{row.first_seen ? row.first_seen.slice(0, 10) : "—"}</td>
      <td className="px-2 py-3 text-right text-xs text-muted">{row.alert_count.toLocaleString()}</td>
      <td className="px-2 py-3 text-right text-xs text-muted">{row.evidence_count.toLocaleString()}</td>
      <td className="px-5 py-3">{row.max_suspicion_level ? <Badge>{row.max_suspicion_level}</Badge> : <span className="text-faint">—</span>}</td>
    </tr>
  );
}
