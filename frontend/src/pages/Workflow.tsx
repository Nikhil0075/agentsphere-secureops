import { useState } from "react";
import { api, type ProofInfo, type WorkflowResponse } from "../lib/api";
import {
  Badge,
  Card,
  CheckRow,
  Empty,
  ErrorNote,
  Hash,
  LabelBadge,
  Spinner,
  Stat,
} from "../components/primitives";

const AGENTS = [
  "detection",
  "correlation",
  "investigation",
  "triage",
  "remediation",
  "verifier",
] as const;

/** Scenes 2, 4 and 5: agent collaboration, the human gate, and the on-chain proof. */
export function Workflow({
  incidentId,
  backend,
}: {
  incidentId: string;
  backend: string;
}) {
  const [result, setResult] = useState<WorkflowResponse | null>(null);
  const [proof, setProof] = useState<ProofInfo | null>(null);
  const [running, setRunning] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [analyst, setAnalyst] = useState("analyst@soc");
  const [comment, setComment] = useState("");

  const run = async () => {
    setRunning(true);
    setError("");
    setProof(null);
    setResult(null);
    try {
      setResult(await api.runWorkflow(incidentId, backend));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setRunning(false);
    }
  };

  const act = async (what: string, fn: () => Promise<ProofInfo>) => {
    setBusy(what);
    setError("");
    try {
      setProof(await fn());
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="space-y-4">
      <Card
        title="Agent workflow"
        subtitle={`Detection → Correlation → Investigation → Triage → Remediation → Verifier, then the policy gate. Backend: ${backend}.`}
        right={
          <button
            onClick={run}
            disabled={running}
            className={`rounded bg-accent px-3 py-1.5 text-xs font-semibold text-ink-950 transition hover:bg-accent/90 disabled:opacity-50 ${
              running ? "running" : ""
            }`}
          >
            {running ? "Running…" : "Run workflow"}
          </button>
        }
      >
        {error && <ErrorNote>{error}</ErrorNote>}
        {running && <Spinner label="Six agents working…" />}
        {!running && !result && (
          <Empty>Run the workflow on {incidentId} to see the agent chain.</Empty>
        )}

        {result && (
          <>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat
                label="Triage"
                value={result.label ? <LabelBadge label={result.label} /> : "—"}
                hint={`${(result.confidence * 100).toFixed(0)}% confidence`}
              />
              <Stat
                label="Baseline"
                value={result.baseline?.label.replace("Positive", "") ?? "—"}
                hint={
                  result.baseline
                    ? result.baseline.label === result.label
                      ? "agrees"
                      : "disagrees"
                    : undefined
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
                hint={result.degraded_agents.length ? `${result.degraded_agents.length} degraded` : "all ok"}
                tone={result.degraded_agents.length ? "warn" : undefined}
              />
            </div>

            {result.correlation_info && (
              <div className="mt-3 rounded border border-ink-800 bg-ink-850 p-3">
                <div className="flex items-baseline justify-between">
                  <span className="text-[11px] uppercase tracking-wide text-ink-400">
                    Union-Find alert correlation
                  </span>
                  <span className="text-xs text-ink-300">
                    <span className="mono text-base font-semibold text-ink-100">
                      {result.correlation_info.alert_count}
                    </span>{" "}
                    alerts →{" "}
                    <span className="mono text-base font-semibold text-accent">
                      {result.correlation_info.cluster_count}
                    </span>{" "}
                    clusters
                    {result.correlation_info.reduction > 0 && (
                      <span className="ml-1.5 text-fp">
                        −{(result.correlation_info.reduction * 100).toFixed(0)}%
                      </span>
                    )}
                  </span>
                </div>
                {result.correlation_info.clusters.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
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
              </div>
            )}

            <div className="mt-3 space-y-1.5">
              {AGENTS.map((name) => {
                const run = result.runs.find((r) => r.agent === name);
                const ok = run?.status === "ok";
                return (
                  <div
                    key={name}
                    className="flex items-center gap-3 rounded border border-ink-800 bg-ink-850 px-3 py-2"
                  >
                    <span className="mono w-5 text-xs text-ink-600">{run?.sequence ?? "·"}</span>
                    <span className="w-28 text-xs font-medium text-ink-200">{name}</span>
                    <span
                      className={`w-16 rounded px-1.5 py-0.5 text-center text-[10px] font-bold ${
                        ok ? "bg-fp/20 text-fp" : "bg-bp/20 text-bp"
                      }`}
                    >
                      {run?.status ?? "—"}
                    </span>
                    <span className="mono w-16 text-right text-xs text-ink-400">
                      {run ? `${run.latency_ms}ms` : ""}
                    </span>
                    <span className="mono w-14 text-right text-xs text-ink-600">
                      {run && run.prompt_tokens + run.completion_tokens > 0
                        ? `${run.prompt_tokens + run.completion_tokens}t`
                        : ""}
                    </span>
                    <span className="ml-auto">
                      <Hash value={run?.output_hash ?? ""} chars={14} />
                    </span>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </Card>

      {result?.triage && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Triage rationale" subtitle="Every claim cites specific evidence ids.">
            <p className="text-sm leading-relaxed text-ink-300">{result.triage.rationale}</p>
            <div className="mt-2 flex flex-wrap gap-1">
              {result.triage.supporting_evidence_ids.slice(0, 10).map((id) => (
                <span key={id} className="mono rounded bg-ink-800 px-1.5 py-0.5 text-[10px] text-ink-400">
                  {id}
                </span>
              ))}
            </div>
          </Card>

          {result.remediation && (
            <Card
              title="Recommended action"
              subtitle="Simulated. Nothing in this system touches a real device or account."
              right={<Badge tone={result.remediation.action_risk}>{result.remediation.action_risk} risk</Badge>}
            >
              <p className="mono text-sm font-semibold text-ink-100">
                {result.remediation.recommended_action}
              </p>
              <p className="mt-1.5 text-xs leading-relaxed text-ink-400">
                {result.remediation.justification}
              </p>
              <p className="mt-2 text-[11px] text-ink-600">
                <span className="text-ink-400">Rollback:</span> {result.remediation.rollback_plan}
              </p>
            </Card>
          )}
        </div>
      )}

      {result?.verifier && (
        <Card
          title="Independent verifier"
          subtitle="Structural checks run in code on every backend; the model's judgement is layered on top and cannot overturn them."
          right={
            <Badge tone={result.verifier.verdict}>{result.verifier.verdict.toUpperCase()}</Badge>
          }
        >
          {result.verifier.contradictions.length > 0 && (
            <ul className="mb-3 space-y-1">
              {result.verifier.contradictions.map((c, i) => (
                <li key={i} className="rounded border border-tp/25 bg-tp/10 px-2 py-1 text-xs text-tp">
                  {c}
                </li>
              ))}
            </ul>
          )}
          <ul className="divide-y divide-ink-850">
            {result.verifier.policy_checks.map((c, i) => (
              <CheckRow key={`${c.policy_id}-${i}`} check={c} />
            ))}
          </ul>
        </Card>
      )}

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
          <ul className="divide-y divide-ink-850">
            {result.gate.checks.map((c, i) => (
              <CheckRow key={`${c.policy_id}-${i}`} check={c} />
            ))}
          </ul>

          {result.gate.reasons.length > 0 && (
            <ul className="mt-2 space-y-1">
              {result.gate.reasons.map((r, i) => (
                <li key={i} className="text-xs text-bp">
                  → {r}
                </li>
              ))}
            </ul>
          )}

          {result.decision_id && (
            <div className="mt-4 rounded border border-ink-800 bg-ink-850 p-3">
              <div className="flex flex-wrap items-end gap-2">
                <label className="flex-1">
                  <span className="block text-[11px] uppercase tracking-wide text-ink-400">
                    Analyst
                  </span>
                  <input
                    value={analyst}
                    onChange={(e) => setAnalyst(e.target.value)}
                    className="mt-1 w-full rounded border border-ink-700 bg-ink-900 px-2 py-1 text-xs text-ink-200 focus:border-accent focus:outline-none"
                  />
                </label>
                <label className="flex-[2]">
                  <span className="block text-[11px] uppercase tracking-wide text-ink-400">
                    Comment
                  </span>
                  <input
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    placeholder="Recorded off-chain; only its hash is anchored"
                    className="mt-1 w-full rounded border border-ink-700 bg-ink-900 px-2 py-1 text-xs text-ink-200 placeholder:text-ink-600 focus:border-accent focus:outline-none"
                  />
                </label>
              </div>

              <div className="mt-2 flex flex-wrap gap-2">
                <button
                  disabled={!!busy || !analyst}
                  onClick={() => act("anchor", () => api.anchor(result.decision_id))}
                  className="rounded border border-ink-600 px-3 py-1.5 text-xs font-medium text-ink-200 hover:bg-ink-800 disabled:opacity-40"
                >
                  {busy === "anchor" ? "Anchoring…" : "Anchor proof on chain"}
                </button>
                <button
                  disabled={!!busy || !analyst}
                  onClick={() =>
                    act("approve", () => api.approve(result.decision_id, true, analyst, comment))
                  }
                  className="rounded bg-fp/90 px-3 py-1.5 text-xs font-semibold text-ink-950 hover:bg-fp disabled:opacity-40"
                >
                  {busy === "approve" ? "Approving…" : "Approve"}
                </button>
                <button
                  disabled={!!busy || !analyst}
                  onClick={() =>
                    act("reject", () => api.approve(result.decision_id, false, analyst, comment))
                  }
                  className="rounded bg-tp/90 px-3 py-1.5 text-xs font-semibold text-ink-950 hover:bg-tp disabled:opacity-40"
                >
                  {busy === "reject" ? "Rejecting…" : "Reject"}
                </button>
                <button
                  disabled={!!busy}
                  onClick={() => act("verify", () => api.verify(result.decision_id))}
                  className="rounded border border-ink-600 px-3 py-1.5 text-xs font-medium text-ink-200 hover:bg-ink-800 disabled:opacity-40"
                >
                  {busy === "verify" ? "Verifying…" : "Verify"}
                </button>
              </div>
            </div>
          )}
        </Card>
      )}

      {result && (
        <Card
          title="Decision integrity"
          subtitle="keccak256 over canonical JSON: sorted keys, no whitespace. The same inputs always produce the same digest."
          right={
            proof?.valid === true ? (
              <Badge tone="low">VALID</Badge>
            ) : proof?.valid === false ? (
              <Badge tone="high">TAMPERED</Badge>
            ) : null
          }
        >
          <dl className="space-y-1.5 text-xs">
            <div className="flex gap-3">
              <dt className="w-28 text-ink-400">Evidence hash</dt>
              <dd><Hash value={result.evidence_hash} chars={40} /></dd>
            </div>
            <div className="flex gap-3">
              <dt className="w-28 text-ink-400">Output hash</dt>
              <dd><Hash value={result.output_hash} chars={40} /></dd>
            </div>
            {result.decision_id && (
              <div className="flex gap-3">
                <dt className="w-28 text-ink-400">Decision</dt>
                <dd className="mono text-ink-300">{result.decision_id}</dd>
              </div>
            )}
          </dl>

          {proof && (
            <div className="mt-3 border-t border-ink-800 pt-3">
              {!proof.chain_available ? (
                <p className="text-xs text-bp">
                  No chain reachable — {proof.reason || "the proof panel degrades, nothing else"}.
                  The workflow, the gate and the hashes are unaffected.
                </p>
              ) : (
                <dl className="space-y-1.5 text-xs">
                  <div className="flex gap-3">
                    <dt className="w-28 text-ink-400">Transaction</dt>
                    <dd>
                      {proof.explorer_url ? (
                        <a
                          href={proof.explorer_url}
                          target="_blank"
                          rel="noreferrer"
                          className="mono text-accent hover:underline"
                        >
                          {proof.tx_hash.slice(0, 24)}…
                        </a>
                      ) : (
                        <Hash value={proof.tx_hash} chars={24} />
                      )}
                    </dd>
                  </div>
                  <div className="flex gap-3">
                    <dt className="w-28 text-ink-400">On-chain</dt>
                    <dd className="text-ink-300">
                      #{proof.onchain_decision_id ?? "—"} · {proof.onchain_state || "unknown"}
                      {proof.block_number ? ` · block ${proof.block_number}` : ""}
                    </dd>
                  </div>
                  <div className="flex gap-3">
                    <dt className="w-28 text-ink-400">Contract</dt>
                    <dd><Hash value={proof.contract_address} chars={24} /></dd>
                  </div>
                </dl>
              )}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
