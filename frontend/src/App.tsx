import { lazy, Suspense, useEffect, useState } from "react";
import { Popover, Spinner } from "./components/primitives";
import { api, type DatasetInfo, type ExecutionMode } from "./lib/api";
import { Home } from "./pages/Home";
import { Incident } from "./pages/Incident";
import { Proof } from "./pages/Proof";
import { Queue } from "./pages/Queue";
import { Workflow, type SessionRun } from "./pages/Workflow";

// Metrics and Provenance are the only Recharts consumers, and both are secondary tabs. Splitting
// them keeps the charting library out of the first paint: the initial bundle stays near where it
// was before charts existed, which matters because the venue network may be unusable.
const Metrics = lazy(() => import("./pages/Metrics").then((m) => ({ default: m.Metrics })));
const Provenance = lazy(() =>
  import("./pages/Provenance").then((m) => ({ default: m.Provenance })),
);

type PrimaryTab = "home" | "queue" | "incident" | "workflow" | "proof" | "metrics";
type Tab = PrimaryTab | "provenance";

const PRIMARY_TABS: { id: PrimaryTab; label: string; needsIncident: boolean }[] = [
  { id: "home", label: "Home", needsIncident: false },
  { id: "queue", label: "Queue", needsIncident: false },
  { id: "incident", label: "Incident", needsIncident: true },
  { id: "workflow", label: "Workflow", needsIncident: true },
  { id: "proof", label: "Proof", needsIncident: true },
  { id: "metrics", label: "Metrics", needsIncident: false },
];

const primaryLabel = (tab: PrimaryTab) =>
  PRIMARY_TABS.find((item) => item.id === tab)?.label ?? "workspace";

export default function App() {
  const [tab, setTab] = useState<Tab>("home");
  const [lastPrimaryTab, setLastPrimaryTab] = useState<PrimaryTab>("home");
  const [selected, setSelected] = useState<string | null>(null);
  const [decisionId, setDecisionId] = useState<string | null>(null);
  const [dataset, setDataset] = useState<DatasetInfo | null>(null);
  const [mode, setMode] = useState<ExecutionMode>("replay");
  const [demoLoading, setDemoLoading] = useState(false);
  // Workflows completed in this browser session. Held here rather than fetched, so the Metrics
  // live feed costs nothing and stays zero-RPC. Not persisted, and never a metric denominator.
  const [sessionRuns, setSessionRuns] = useState<SessionRun[]>([]);

  useEffect(() => {
    api.dataset().then((data) => {
      setDataset(data);
      setMode(data.execution_mode || "replay");
    });
  }, []);

  const openPrimary = (next: PrimaryTab) => {
    setLastPrimaryTab(next);
    setTab(next);
  };

  const select = (id: string) => {
    setSelected(id);
    setDecisionId(null);
    openPrimary("incident");
  };

  const openProvenance = () => setTab("provenance");
  // Opens case 1 of the curated arc — the highest-risk true positive, and the one the proof
  // tamper/restore scene runs on. Ranked rather than risk-sorted so the opener cannot drift if
  // the risk weights are retuned.
  const runDemo = () => {
    setDemoLoading(true);
    api
      .queryIncidents({ limit: 1, demo_only: true, sort_by: "demo_rank", sort_dir: "asc" })
      .then((result) => {
        if (result.items[0]) select(result.items[0].incident_id);
        else openPrimary("queue");
      })
      .finally(() => setDemoLoading(false));
  };

  const needsIncident =
    tab !== "provenance" &&
    PRIMARY_TABS.find((item) => item.id === tab)?.needsIncident &&
    !selected;

  return (
    <div className="min-h-full">
      <header className="sticky top-0 z-20 border-b border-header-line bg-header">
        <div className="mx-auto flex max-w-[1240px] flex-wrap items-center gap-4 px-5 py-3">
          <button type="button" onClick={() => openPrimary("home")} className="flex items-center gap-3 text-left" aria-label="Open AgentSphere home">
            <img src="/brand/mark.svg" alt="" className="h-9 w-9" />
            <span className="leading-none">
              <span className="wordmark block text-code text-brand">AGENTSPHERE</span>
              <span className="wordmark-sub mt-1 block text-4xs text-brand-dim">SECUREOPS</span>
            </span>
          </button>

          <nav aria-label="Primary workflow" className="order-3 flex w-full items-center gap-1 lg:order-none lg:ml-auto lg:w-auto">
            {PRIMARY_TABS.map((item, index) => {
              const active = tab === item.id;
              return (
                <div key={item.id} className="flex min-w-0 flex-1 items-center lg:flex-none">
                  {index > 0 ? <span aria-hidden="true" className="hidden h-px w-2 bg-white/15 xl:block" /> : null}
                  <button
                    type="button"
                    aria-current={active ? "page" : undefined}
                    onClick={() => openPrimary(item.id)}
                    className={`relative w-full rounded-md px-3 py-2 text-xs font-semibold transition-colors duration-100 lg:w-auto ${active ? "bg-brand text-header" : "text-white/65 hover:bg-white/10 hover:text-white"}`}
                  >
                    {item.label}
                    {active ? <span aria-hidden="true" className="absolute inset-x-3 -bottom-1 h-0.5 rounded-full bg-brand" /> : null}
                  </button>
                </div>
              );
            })}

            <span aria-hidden="true" className="mx-1 h-6 w-px shrink-0 bg-white/15" />
            <Popover label="Open Explore menu" trigger="Explore ▾" active={tab === "provenance"}>
              <button type="button" role="menuitem" onClick={openProvenance} className="interactive-card w-full rounded-xl px-3 py-3 text-left hover:bg-primary-soft">
                <span className="block text-sm font-semibold text-text">Provenance Lab</span>
                <span className="mt-1 block text-xs leading-relaxed text-muted">Optional graph-depth view using the graph shipped by WitFoo.</span>
              </button>
            </Popover>
          </nav>

          <select
            value={mode}
            onChange={(event) => setMode(event.target.value as ExecutionMode)}
            aria-label="Agent execution mode"
            title="How the agents execute"
            className="ml-auto rounded-md border border-header-line bg-header px-2.5 py-1.5 text-xs text-white/80 focus:border-brand lg:ml-0"
          >
            <option value="replay">replay (validated)</option>
            <option value="live">agents sdk (live)</option>
            <option value="deterministic">deterministic (offline)</option>
          </select>
        </div>
      </header>

      <main className="mx-auto max-w-[1240px] px-5 py-5">
        {needsIncident ? (
          <div className="rounded-2xl border border-line bg-surface px-6 py-12 text-center">
            <p className="text-sm font-medium text-text">No incident selected</p>
            <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-muted">Pick one from the queue to open this view.</p>
            <button type="button" onClick={() => openPrimary("queue")} className="mt-4 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-white hover:bg-primary-hover">Go to the queue</button>
          </div>
        ) : (
          <div key={tab} className="page-enter">
            <Suspense fallback={<Spinner label="Loading…" />}>
            {tab === "home" ? <Home dataset={dataset} mode={mode} onOpenQueue={() => openPrimary("queue")} onRunDemo={runDemo} demoLoading={demoLoading} /> : null}
            {tab === "queue" ? <Queue selected={selected} onSelect={select} /> : null}
            {tab === "incident" && selected ? <Incident incidentId={selected} onSelectIncident={select} onOpenProvenance={openProvenance} /> : null}
            {tab === "workflow" && selected ? <Workflow incidentId={selected} backend={mode} onDecision={setDecisionId} onRunComplete={(run) => setSessionRuns((prev) => [...prev, run])} /> : null}
            {tab === "proof" && selected ? <Proof decisionId={decisionId} chain={dataset?.chain} onGoToWorkflow={() => openPrimary("workflow")} /> : null}
            {tab === "provenance" ? <Provenance summary={dataset?.witfoo} compareIncidentId={selected} onBack={() => openPrimary(lastPrimaryTab)} backLabel={`Back to ${primaryLabel(lastPrimaryTab)}`} /> : null}
            {tab === "metrics" ? <Metrics runs={sessionRuns} /> : null}
            </Suspense>
          </div>
        )}
      </main>

      <footer className="mx-auto max-w-[1240px] px-5 pb-8 pt-2">
        <p className="text-2xs text-faint">All remediation in this system is <span className="font-medium text-muted">simulated</span>. Nothing here isolates a device, disables an account or acts on a real system.</p>
      </footer>
    </div>
  );
}
