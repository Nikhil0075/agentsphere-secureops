import { useEffect, useState } from "react";
import { api, type DatasetInfo } from "./lib/api";
import { Badge } from "./components/primitives";
import { Incident } from "./pages/Incident";
import { Metrics } from "./pages/Metrics";
import { Queue } from "./pages/Queue";
import { Workflow } from "./pages/Workflow";

type Tab = "queue" | "incident" | "workflow" | "metrics";

const TABS: { id: Tab; label: string; needsIncident: boolean }[] = [
  { id: "queue", label: "Queue", needsIncident: false },
  { id: "incident", label: "Incident", needsIncident: true },
  { id: "workflow", label: "Workflow", needsIncident: true },
  { id: "metrics", label: "Metrics", needsIncident: false },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("queue");
  const [selected, setSelected] = useState<string | null>(null);
  const [dataset, setDataset] = useState<DatasetInfo | null>(null);
  const [backend, setBackend] = useState("deterministic");

  useEffect(() => {
    api.dataset().then((d) => {
      setDataset(d);
      setBackend(d.llm_backend || "deterministic");
    });
  }, []);

  const select = (id: string) => {
    setSelected(id);
    setTab("incident");
  };

  return (
    <div className="min-h-full">
      <header className="sticky top-0 z-10 border-b border-ink-800 bg-ink-950/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-3 px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="text-lg">🛡️</span>
            <div>
              <h1 className="text-sm font-semibold text-ink-100">AgentSphere SecureOps</h1>
              <p className="text-[11px] text-ink-400">
                Permissioned AI agents for SOC triage · all remediation simulated
              </p>
            </div>
          </div>

          <nav className="ml-auto flex gap-1">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                disabled={t.needsIncident && !selected}
                className={`rounded px-3 py-1.5 text-xs font-medium transition disabled:opacity-30 ${
                  tab === t.id
                    ? "bg-accent/15 text-accent"
                    : "text-ink-300 hover:bg-ink-850 hover:text-ink-100"
                }`}
              >
                {t.label}
              </button>
            ))}
          </nav>

          <select
            value={backend}
            onChange={(e) => setBackend(e.target.value)}
            title="Which LLM backend the agents use"
            className="rounded border border-ink-700 bg-ink-850 px-2 py-1 text-xs text-ink-200 focus:border-accent focus:outline-none"
          >
            <option value="deterministic">deterministic (offline)</option>
            <option value="cache">cache (replay)</option>
            <option value="openai">openai (live)</option>
          </select>
        </div>

        {dataset && (
          <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-2 border-t border-ink-850 px-4 py-1.5 text-[11px] text-ink-400">
            <span>
              <span className="text-ink-300">{dataset.incidents.toLocaleString()}</span> incidents
            </span>
            <span className="text-ink-700">·</span>
            <span>
              <span className="text-ink-300">{dataset.evidence_rows.toLocaleString()}</span>{" "}
              evidence rows
            </span>
            <span className="text-ink-700">·</span>
            <span>{dataset.source}</span>
            {dataset.sentinels_masked.length > 0 && (
              <>
                <span className="text-ink-700">·</span>
                <span title={dataset.sentinels_masked.join(", ")}>
                  {dataset.sentinels_masked.length} sentinels masked
                </span>
              </>
            )}
            <span className="ml-auto flex items-center gap-2">
              <Badge tone={dataset.index_available ? "low" : "medium"}>
                {dataset.index_available ? "hybrid index" : "entity overlap"}
              </Badge>
              <Badge tone={dataset.chain.available ? "low" : "medium"}>
                {dataset.chain.available
                  ? `chain: ${dataset.chain.network} (${dataset.chain.chain_id})`
                  : "chain offline"}
              </Badge>
            </span>
          </div>
        )}
      </header>

      <main className="mx-auto max-w-[1400px] px-4 py-4">
        {tab === "queue" && <Queue selected={selected} onSelect={select} />}
        {tab === "incident" && selected && <Incident incidentId={selected} />}
        {tab === "workflow" && selected && <Workflow incidentId={selected} backend={backend} />}
        {tab === "metrics" && <Metrics />}
      </main>
    </div>
  );
}
