import { useEffect, useMemo, useState } from "react";
import { api, type ExecutionMode, type WorkflowResponse } from "../lib/api";
import {
  Badge,
  Button,
  Card,
  CheckRow,
  Empty,
  ErrorNote,
  Hash,
  LabelBadge,
  Note,
  PageIntro,
  Spinner,
  Stat,
  TextInput,
} from "../components/primitives";
import { AgentStageCard } from "../components/workflow/AgentStageCard";

/** The contract sequence. A run longer than this fired the live revision pass. */
const BASE_STAGES = 6;

export interface SessionRun {
  at: number;
  incident_id: string;
  label: WorkflowResponse["label"];
  confidence: number;
  total_latency_ms: number;
  cache_status: WorkflowResponse["cache_status"];
  execution_mode: ExecutionMode;
  degraded: number;
  resampled: number;
  revision_fired: boolean;
}

/**
 * Scenes 2 and 4 — agent collaboration, and the human authority that constrains it.
 *
 * Every agent now gets its own card carrying three things: the prompt it was given, the output it
 * produced, and how the call went. Detection, Correlation and Investigation used to render nothing
 * at all while their full output sat in the payload.
 *
 * Stages are derived from `result.runs` rather than from a fixed list of six names, because the
 * live revision pass runs triage, remediation and verifier a second time and a name-keyed view
 * silently collapses the two.
 */
export function Workflow({
  incidentId,
  backend,
  onDecision,
  onRunComplete,
}: {
  incidentId: string;
  backend: ExecutionMode;
  onDecision: (id: string | null) => void;
  onRunComplete?: (run: SessionRun) => void;
}) {
  const [result, setResult] = useState<WorkflowResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [analyst, setAnalyst] = useState("analyst@soc");
  const [comment, setComment] = useState("");
  const [approved, setApproved] = useState<boolean | null>(null);
  const [focused, setFocused] = useState<number | null>(null);

  useEffect(() => {
    setResult(null);
    setApproved(null);
    setFocused(null);
    onDecision(null);
  }, [incidentId, onDecision]);

  const run = async () => {
    setRunning(true);
    setError("");
    setResult(null);
    setApproved(null);
    onDecision(null);
    try {
      const r = await api.runWorkflow(incidentId, backend);
      setResult(r);
      onDecision(r.decision_id || null);
      onRunComplete?.({
        at: Date.now(),
        incident_id: r.incident_id,
        label: r.label,
        confidence: r.confidence,
        total_latency_ms: r.total_latency_ms,
        cache_status: r.cache_status,
        execution_mode: r.execution_mode,
        degraded: r.degraded_agents.length,
        resampled: r.resampled_agents.length,
        revision_fired: r.revision_fired,
      });
    } catch (e: any) {
      setError(e.message);
    } finally {
      setRunning(false);
    }
  };

  const decide = async (ok: boolean) => {
    if (!result?.decision_id) return;
    setBusy(ok ? "approve" : "reject");
    setError("");
    try {
      await api.approve(result.decision_id, ok, analyst, comment);
      setApproved(ok);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  };

  const focusStage = (index: number) => {
    setFocused(index);
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    document.getElementById(`agent-stage-${index}`)?.scrollIntoView({
      behavior: reducedMotion ? "auto" : "smooth",
      block: "center",
    });
  };

  const stages = useMemo(
    () =>
      (result?.runs ?? []).map((run, index) => ({
        run,
        index,
        trace: result?.traces?.find((t) => t.run_index === index) ?? null,
      })),
    [result],
  );

  return (
    <div className="space-y-4">
      <PageIntro
        eyebrow="Scenes 2 & 4 · Coordinated analysis"
        title="Let specialists collaborate—then stop at human authority."
        description="Each stage shows what it was asked, what it produced, and how the call went. The prompts are readable on purpose: no ground-truth label reaches an agent that decides."
      />

      <Card
        title="Agent workflow"
        subtitle={`Detection → Correlation → Investigation → Triage → Remediation → Verifier, then the deterministic policy gate. Backend: ${backend}.`}
        right={
          <Button variant="primary" onClick={run} disabled={running} className={running ? "running" : ""}>
            {running ? "Running…" : "Run workflow"}
          </Button>
        }
      >
        {error && <ErrorNote>{error}</ErrorNote>}
        {running && <Spinner label="Six agents working…" />}
        {!running && !result && <Empty>Run the workflow on {incidentId} to see the agent chain.</Empty>}

        {result && (
          <>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
              <Stat
                label="Triage"
                value={result.label ? <LabelBadge label={result.label} /> : "—"}
                hint={`${(result.confidence * 100).toFixed(0)}% confidence`}
              />
              <Stat
                label="Baseline"
                value={result.baseline ? result.baseline.label.replace("Positive", "") : "—"}
                hint={
                  result.baseline
                    ? `${(result.baseline.confidence * 100).toFixed(0)}% · ${
                        result.baseline.label === result.label ? "agrees" : "disagrees"
                      }`
                    : "unavailable"
                }
                tone={
                  result.baseline && result.baseline.label !== result.label ? "warn" : undefined
                }
              />
              <Stat
                label="Verifier"
                value={result.verifier?.verdict ?? "—"}
                tone={
                  result.verifier?.verdict === "accept"
                    ? "good"
                    : result.verifier?.verdict === "reject"
                      ? "bad"
                      : "warn"
                }
              />
              <Stat
                label="Latency"
                value={`${result.total_latency_ms}ms`}
                hint={
                  result.degraded_agents.length
                    ? `${result.degraded_agents.length} degraded`
                    : result.resampled_agents.length
                      ? `${result.resampled_agents.length} resampled`
                      : "all ok"
                }
                tone={
                  result.degraded_agents.length || result.resampled_agents.length
                    ? "warn"
                    : undefined
                }
              />
              <Stat
                label="Execution"
                value={result.execution_mode}
                hint={result.cache_status.replace("_", " ")}
                tone={
                  result.cache_status === "degraded"
                    ? "warn"
                    : result.cache_status === "hit"
                      ? "good"
                      : undefined
                }
              />
              <Stat
                label="Tokens"
                value={result.token_usage.total.toLocaleString()}
                hint={`${result.token_usage.input.toLocaleString()} in · ${result.token_usage.output.toLocaleString()} out`}
                tone={result.revision_fired ? "warn" : undefined}
              />
            </div>

            <dl className="mt-3 grid grid-cols-1 gap-x-4 gap-y-1.5 border-t border-line pt-3 text-2xs sm:grid-cols-3">
              <Meta label="Workflow">
                <span className="mono text-muted">{result.workflow_id}</span>
              </Meta>
              <Meta label="Evidence hash">
                <Hash value={result.evidence_hash} chars={14} />
              </Meta>
              <Meta label="Output hash">
                <Hash value={result.output_hash} chars={14} />
              </Meta>
            </dl>
            {Object.keys(result.model_profile).length > 0 && (
              <p className="mt-1.5 text-3xs text-faint">
                {Object.entries(result.model_profile)
                  .map(([key, value]) => `${key}: ${value}`)
                  .join(" · ")}
              </p>
            )}

            {result.errors.length > 0 && (
              <div className="mt-3 space-y-1.5">
                {result.errors.map((message, index) => (
                  <ErrorNote key={index}>{message}</ErrorNote>
                ))}
              </div>
            )}

            {result.correlation_info && (
              <div className="mt-4 rounded-xl bg-raised p-4">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="text-2xs font-medium uppercase tracking-wider text-faint">
                    Union-Find alert correlation
                  </span>
                  <span className="text-sm text-muted">
                    <span className="mono text-xl font-bold text-text">
                      {result.correlation_info.alert_count}
                    </span>{" "}
                    alerts →{" "}
                    <span className="mono text-xl font-bold text-primary">
                      {result.correlation_info.cluster_count}
                    </span>{" "}
                    clusters
                    {result.correlation_info.reduction > 0 && (
                      <span className="ml-2 font-semibold text-fp">
                        −{(result.correlation_info.reduction * 100).toFixed(0)}%
                      </span>
                    )}
                  </span>
                </div>
                {result.correlation_info.clusters.length > 0 && (
                  <div className="mt-2.5 flex flex-wrap gap-1.5">
                    {result.correlation_info.clusters.slice(0, 8).map((c) => (
                      <Badge key={c.cluster_id}>
                        {c.cluster_id} · {c.size} alert{c.size === 1 ? "" : "s"}
                        {c.linking_entities.length > 0 && (
                          <span className="opacity-60"> via {c.linking_entities[0]}</span>
                        )}
                      </Badge>
                    ))}
                  </div>
                )}
                <p className="mt-2 text-3xs text-faint">
                  Largest cluster: {result.correlation_info.largest_cluster} alert
                  {result.correlation_info.largest_cluster === 1 ? "" : "s"}.
                </p>
              </div>
            )}
          </>
        )}
      </Card>

      {result && stages.length > 0 && (
        <div className="grid gap-4 lg:grid-cols-[22rem_1fr] lg:items-start">
          {/* Sticky so the chain stays on screen while its outputs are read beside it. */}
          <Card
            title="Agent chain"
            subtitle="A degraded agent reads `fallback`, never `ok`."
            className="min-w-0 lg:sticky lg:top-24"
          >
            <div className="space-y-1.5">
              {stages.map(({ run, index }) => (
                <div key={index}>
                  {index === BASE_STAGES && (
                    <div className="my-2 border-t border-dashed border-line pt-2">
                      <p className="text-3xs leading-relaxed text-bp">
                        Revision pass (live only). A run that fires it has nine stages and an
                        output hash its replay cannot reproduce.
                      </p>
                    </div>
                  )}
                  <div
                    className={`interactive-card w-full rounded-lg ${
                      focused === index
                        ? "bg-primary-soft ring-1 ring-inset ring-primary-line"
                        : "bg-raised hover:bg-primary-soft"
                    }`}
                  >
                    <button
                      type="button"
                      aria-pressed={focused === index}
                      onClick={() => focusStage(index)}
                      className="w-full px-3 pb-1 pt-2.5 text-left"
                    >
                      <div className="flex items-center gap-2.5">
                        <span className="mono w-4 text-xs text-faint">{run.sequence}</span>
                        <span className="flex-1 text-xs font-semibold capitalize text-text">
                          {run.agent}
                        </span>
                        <span
                          className={`rounded-md px-1.5 py-0.5 text-3xs font-bold ${
                            run.status === "ok" ? "bg-fp-soft text-fp" : "bg-bp-soft text-bp"
                          }`}
                        >
                          {run.status}
                        </span>
                      </div>
                    </button>
                    <div className="flex items-center gap-3 px-3 pb-2.5 pl-9 text-3xs text-faint">
                      <span className="mono">{run.latency_ms}ms</span>
                      {run.prompt_tokens + run.completion_tokens > 0 && (
                        <span className="mono">{run.prompt_tokens + run.completion_tokens}t</span>
                      )}
                      {run.cached && <span className="text-info">cached</span>}
                      <span className="ml-auto">
                        <Hash value={run.output_hash} chars={10} />
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <div className="min-w-0 space-y-4">
            {stages.map(({ run, index, trace }) => (
              <AgentStageCard
                key={index}
                run={run}
                runIndex={index}
                trace={trace}
                result={result}
                focused={focused === index}
              />
            ))}
          </div>
        </div>
      )}

      {/* Scene 4. Full width, because "a human has to sign this" is a statement about the system,
          not a detail of one agent's output. */}
      {result?.gate && (
        <Card
          title="Policy gate"
          subtitle="Deterministic. Not a prompt, not advisory — an agent cannot argue past a dictionary lookup."
          right={
            <Badge tone={result.gate.requires_approval ? "high" : "low"}>
              {result.gate.requires_approval ? "HUMAN APPROVAL REQUIRED" : "AUTO-APPROVED"}
            </Badge>
          }
        >
          <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat
              label="Action risk"
              value={result.gate.action_risk || "—"}
              tone={result.gate.action_risk === "low" ? "good" : "warn"}
            />
            <Stat
              label="Auto-approved"
              value={result.gate.auto_approved ? "yes" : "no"}
              tone={result.gate.auto_approved ? "good" : undefined}
            />
            <Stat label="Checks" value={result.gate.checks.length} />
            <Stat
              label="Failed"
              value={result.gate.checks.filter((c) => !c.passed).length}
              tone={result.gate.checks.some((c) => !c.passed) ? "warn" : "good"}
            />
          </div>

          <div className="grid gap-5 lg:grid-cols-2">
            <div className="min-w-0">
              <ul className="divide-y divide-line">
                {result.gate.checks.map((c, i) => (
                  <CheckRow key={`${c.policy_id}-${i}`} check={c} />
                ))}
              </ul>
              {result.gate.reasons.length > 0 && (
                <ul className="mt-3 space-y-1">
                  {result.gate.reasons.map((r, i) => (
                    <li key={i} className="text-xs font-medium text-bp">
                      → {r}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {result.decision_id && (
              <div className="min-w-0 rounded-xl bg-raised p-4">
                {approved !== null ? (
                  <Note tone={approved ? "info" : "warn"}>
                    Recorded as <strong>{approved ? "approved" : "rejected"}</strong> by{" "}
                    <span className="mono">{analyst}</span>. The comment stays in the application
                    database; only its hash can be anchored. Open the <strong>Proof</strong> tab to
                    anchor and verify.
                  </Note>
                ) : (
                  <>
                    <div className="space-y-2.5">
                      <label className="block">
                        <span className="block text-2xs font-medium uppercase tracking-wider text-faint">
                          Analyst
                        </span>
                        <TextInput value={analyst} onChange={setAnalyst} className="mt-1 w-full" />
                      </label>
                      <label className="block">
                        <span className="block text-2xs font-medium uppercase tracking-wider text-faint">
                          Comment
                        </span>
                        <TextInput
                          value={comment}
                          onChange={setComment}
                          placeholder="Recorded off-chain; only its hash is anchored"
                          className="mt-1 w-full"
                        />
                      </label>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Button
                        variant="primary"
                        disabled={!!busy || !analyst}
                        onClick={() => decide(true)}
                      >
                        {busy === "approve" ? "Approving…" : "Approve"}
                      </Button>
                      <Button variant="danger" disabled={!!busy || !analyst} onClick={() => decide(false)}>
                        {busy === "reject" ? "Rejecting…" : "Reject"}
                      </Button>
                    </div>
                    <p className="mt-2.5 text-2xs leading-relaxed text-faint">
                      The approver is the transaction sender, not a name in a payload — a signature
                      rather than an assertion.
                    </p>
                  </>
                )}
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-3xs uppercase tracking-wider text-faint">{label}</dt>
      <dd className="mt-0.5 truncate">{children}</dd>
    </div>
  );
}
