import { useEffect, useState } from "react";
import { Badge, Button, Card, ErrorNote, Kpi, Skeleton } from "../components/primitives";
import { api, type DatasetInfo, type ExecutionMode, type MetricsResponse } from "../lib/api";

const stages = [
  ["Detection", "Scores severity and identifies the entities that deserve attention."],
  ["Correlation", "Collapses related alerts into an evidence bundle and timeline."],
  ["Investigation", "Adds hybrid retrieval, graph context, and MITRE mappings."],
  ["Triage", "Makes the TP, benign-positive, or false-positive decision."],
  ["Remediation", "Chooses a bounded, simulated response from the policy catalogue."],
  ["Verifier", "Challenges citations, confidence, contradictions, and action fit."],
] as const;

function modeCopy(mode: ExecutionMode) {
  if (mode === "live") return "OpenAI Agents SDK · live Responses API";
  if (mode === "replay") return "Validated replay · live fill · deterministic fallback";
  return "Deterministic rules · no network dependency";
}

export function Home({
  dataset,
  mode,
  onOpenQueue,
  onRunDemo,
  demoLoading,
}: {
  dataset: DatasetInfo | null;
  mode: ExecutionMode;
  onOpenQueue: () => void;
  onRunDemo: () => void;
  demoLoading: boolean;
}) {
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.metrics().then(setMetrics).catch((reason) => setError(String(reason.message ?? reason)));
  }, []);

  const evaluation = metrics?.evaluation ?? {};
  const agentMetrics = (evaluation.agents ?? {}) as Record<string, number>;
  const promotion = (evaluation.promotion ?? {}) as Record<string, any>;
  const profile = dataset?.model_profile ?? {};
  const chainNetwork = dataset?.chain.network || "not configured";

  return (
    <div className="space-y-5">
      <section className="overflow-hidden rounded-3xl bg-header px-6 py-8 text-white lg:px-10 lg:py-10">
        <div className="grid items-center gap-8 lg:grid-cols-[1.2fr_0.8fr]">
          <div className="max-w-3xl">
            {/* Mono eyebrow and a light, tightly-tracked display line — the reference's voice, and
                the one place on the app where gold is legible enough to lead with. */}
            <p className="mono text-code uppercase tracking-[0.14em] text-brand">AgentSphere SecureOps</p>
            {/* The hero animation. Lazy and explicitly sized: at 495kB it must never touch first
                paint, and the fixed box means loading it late shifts nothing on the page.

                It plays once and holds its final frame. That is a property of the file, not of
                this markup: `public/brand/hero.gif` has had its 19-byte Netscape Application
                Extension stripped, and a GIF without that block does not loop. HTML gives no way
                to stop a looping GIF, so re-exporting this asset from any ordinary tool will
                silently restore the loop — strip the block again if that happens. */}
            <img
              src="/brand/hero.gif"
              alt=""
              width={650}
              height={520}
              loading="lazy"
              decoding="async"
              className="mt-5 h-auto w-full max-w-md rounded-2xl lg:hidden"
            />
            <h1 className="mt-4 text-display sm:text-[3.5rem] sm:leading-[1.02] sm:tracking-[-0.028em]">Turn evidence overload into decisions you can inspect and prove.</h1>
            <p className="mt-5 max-w-2xl text-sm leading-6 text-white/65">Six bounded agents investigate GUIDE incidents, a separate verifier challenges the result, deterministic policy controls autonomy, and the proof layer records exactly what was decided.</p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
            <img
              src="/brand/hero.gif"
              alt=""
              width={650}
              height={520}
              loading="lazy"
              decoding="async"
              className="mb-4 hidden h-auto w-full rounded-xl lg:block"
            />
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="mono text-2xs uppercase tracking-[0.14em] text-brand-dim">Execution mode</p>
                <p className="mt-1 text-xl font-medium capitalize tracking-[-0.015em]">{mode}</p>
              </div>
              <span className="rounded-full bg-brand px-3 py-1 text-xs font-bold text-header">ready</span>
            </div>
            <p className="mt-3 text-sm leading-relaxed text-white/65">{modeCopy(mode)}</p>
            <div className="mt-5 flex flex-wrap gap-2">
              <Button onClick={onRunDemo} disabled={demoLoading} variant="primary">{demoLoading ? "Opening demo…" : "Run demo"}</Button>
              <Button onClick={onOpenQueue} variant="secondary">Open queue</Button>
            </div>
          </div>
        </div>
      </section>

      {!dataset ? (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5" aria-label="Loading platform statistics">
          {Array.from({ length: 5 }, (_, index) => <Skeleton key={index} className="h-28" />)}
        </div>
      ) : (
        <section aria-label="Platform statistics" className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <Kpi label="Incidents" value={dataset.incidents.toLocaleString()} hint={`${dataset.source.toUpperCase()} incident corpus`} />
          <Kpi label="Evidence rows" value={dataset.evidence_rows.toLocaleString()} hint={`${dataset.sentinels_masked.length} sentinels masked before agents`} />
          <Kpi label="Retrieval" value={dataset.index_available ? "Hybrid" : "Overlap"} hint={dataset.index_available ? "BM25 + vectors, RRF k=60" : "Entity overlap fallback"} tone={dataset.index_available ? "good" : "warn"} />
          <Kpi label="Chain" value={chainNetwork} hint={dataset.chain.chain_id ? `chainId ${dataset.chain.chain_id} · live status in Proof` : dataset.chain.reason || "No deployment"} tone={dataset.chain.available ? "good" : "warn"} />
          <Kpi label="Provenance" value={dataset.witfoo?.available ? Number(dataset.witfoo.declared_edges ?? 0).toLocaleString() : "Unavailable"} hint={dataset.witfoo?.available ? "WitFoo labelled edges" : "Optional dataset not loaded"} tone={dataset.witfoo?.available ? undefined : "warn"} />
        </section>
      )}

      <div className="grid gap-5 xl:grid-cols-[1.45fr_0.55fr]">
        <Card title="A bounded agent workforce" subtitle="Explicit orchestration keeps every stage inspectable; no agent can bypass policy.">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {stages.map(([name, description], index) => (
              <div key={name} className="interactive-card rounded-xl border border-line bg-raised p-4">
                <div className="flex items-center gap-2">
                  <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary-soft text-2xs font-bold text-primary">{index + 1}</span>
                  <h3 className="text-sm font-semibold text-text">{name}</h3>
                </div>
                <p className="mt-2 text-xs leading-relaxed text-muted">{description}</p>
              </div>
            ))}
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <div className="rounded-xl border border-primary-line bg-primary-soft p-4">
              <p className="text-xs font-bold uppercase tracking-wider text-primary">Deterministic gate</p>
              <p className="mt-1 text-xs leading-relaxed text-muted">Catalogue, citation, confidence, and approval rules remain authoritative after the model finishes.</p>
            </div>
            <div className="rounded-xl border border-line bg-surface p-4">
              <p className="text-xs font-bold uppercase tracking-wider text-text">Decision proof</p>
              <p className="mt-1 text-xs leading-relaxed text-muted">Evidence and output digests can be verified locally, with live Sepolia confirmation kept in Proof.</p>
            </div>
          </div>
        </Card>

        <div className="space-y-5">
          <Card title="Model routing" subtitle="Quality where judgment matters; balance everywhere else.">
            <div className="space-y-3 text-sm">
              <div className="flex items-start justify-between gap-3"><span className="text-muted">Supporting agents</span><span className="mono text-right text-xs text-text">{profile.support ?? "gpt-5.6-terra"}</span></div>
              <div className="flex items-start justify-between gap-3"><span className="text-muted">Triage + verifier</span><span className="mono text-right text-xs text-text">{profile.judge ?? "gpt-5.6-sol"}</span></div>
              <div className="flex items-start justify-between gap-3"><span className="text-muted">Reasoning</span><span className="capitalize text-text">{profile.reasoning ?? "medium"}</span></div>
              <div className="flex items-start justify-between gap-3"><span className="text-muted">Replay entries</span><span className="text-text">{dataset?.replay_entries?.toLocaleString() ?? "—"}</span></div>
            </div>
          </Card>

          <Card title="Measured quality" subtitle="Promotion is evidence-gated, not claimed from a model name.">
            {error ? <ErrorNote>{error}</ErrorNote> : null}
            {!metrics && !error ? <Skeleton className="h-24" /> : null}
            {metrics ? (
              <div className="space-y-3">
                <div className="flex items-end justify-between gap-3">
                  <div><p className="text-xs text-muted">Agent macro F1</p><p className="mt-1 text-2xl font-semibold text-text">{typeof agentMetrics.macro_f1 === "number" ? agentMetrics.macro_f1.toFixed(4) : "—"}</p></div>
                  <Badge tone={promotion.passed === true ? "good" : promotion.passed === false ? "warn" : undefined}>{promotion.passed === true ? "Gate passed" : promotion.passed === false ? "Gate not passed" : "Awaiting full evaluation"}</Badge>
                </div>
                <p className="text-xs leading-relaxed text-muted">Requires +0.03 macro-F1 over the current workflow, no regression below the non-LLM baseline, and no true-positive recall decline.</p>
              </div>
            ) : null}
          </Card>
        </div>
      </div>
    </div>
  );
}
