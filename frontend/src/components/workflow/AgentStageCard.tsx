import type { AgentRun, AgentTrace, WorkflowResponse } from "../../lib/api";
import { Badge, Card, ErrorNote, Hash, Note } from "../primitives";
import { AgentOutput } from "./AgentOutput";

/**
 * One stage: what the agent was asked, what it produced, and how the call went.
 *
 * The input panel is the demo asset. A judge can open Detection's prompt and read for themselves
 * that no ground-truth label is in it — invariant 2 shown rather than asserted.
 */
export function AgentStageCard({
  run,
  runIndex,
  trace,
  result,
  focused,
}: {
  run: AgentRun;
  runIndex: number;
  trace: AgentTrace | null;
  result: WorkflowResponse;
  focused: boolean;
}) {
  const ok = run.status === "ok";
  const tokens = run.prompt_tokens + run.completion_tokens;

  return (
    <div
      id={`agent-stage-${runIndex}`}
      className={`rounded-2xl transition-shadow ${focused ? "ring-2 ring-primary-line" : ""}`}
    >
      <Card
        className="min-w-0"
        title={
          <span className="flex items-center gap-2">
            <span className="text-faint">{run.sequence}.</span>
            <span className="capitalize">{run.agent}</span>
          </span>
        }
        right={
          <span className="flex items-center gap-1.5">
            {run.cached && <Badge tone="info">cached</Badge>}
            {run.attempts > 1 && <Badge tone="medium">{run.attempts} attempts</Badge>}
            <Badge tone={ok ? "low" : "high"}>{run.status}</Badge>
          </span>
        }
      >
        {run.validation_error && <ErrorNote>{run.validation_error}</ErrorNote>}

        {trace && <InputPanel trace={trace} />}

        <div className="mt-3">
          <AgentOutput agent={run.agent} result={result} />
        </div>

        <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1.5 border-t border-line pt-3 sm:grid-cols-4">
          <Fact label="Model" value={run.model || "—"} />
          <Fact label="Backend" value={run.backend || "—"} />
          <Fact label="Latency" value={`${run.latency_ms.toLocaleString()}ms`} />
          <Fact label="Tokens" value={tokens ? `${run.prompt_tokens}/${run.completion_tokens}` : "—"} />
          <div className="col-span-2">
            <dt className="text-3xs uppercase tracking-wider text-faint">Output hash</dt>
            <dd className="mt-0.5">
              <Hash value={run.output_hash} chars={14} />
            </dd>
          </div>
          {run.trace_id && (
            <div className="col-span-2">
              <dt className="text-3xs uppercase tracking-wider text-faint">Trace</dt>
              <dd className="mt-0.5">
                <Hash value={run.trace_id} chars={14} />
              </dd>
            </div>
          )}
        </dl>
      </Card>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-3xs uppercase tracking-wider text-faint">{label}</dt>
      <dd className="mono truncate text-2xs text-muted" title={value}>
        {value}
      </dd>
    </div>
  );
}

function InputPanel({ trace }: { trace: AgentTrace }) {
  return (
    <details className="rounded-xl bg-raised">
      <summary className="cursor-pointer px-3 py-2 text-2xs font-semibold text-muted">
        Input — what this agent was asked ({trace.user_prompt.length.toLocaleString()} chars)
      </summary>
      <div className="space-y-3 px-3 pb-3">
        {trace.pre_decision ? (
          trace.label_free ? (
            <Note>
              Scanned for <span className="mono">TruePositive</span>,{" "}
              <span className="mono">BenignPositive</span> and{" "}
              <span className="mono">FalsePositive</span> — none present. This agent runs before any
              label-bearing prediction exists, and retrieval never returns a similar incident's
              label.
            </Note>
          ) : (
            // Should be unreachable; a failing test guards it. It looks alarming on purpose.
            <ErrorNote>
              A triage label string appears in a pre-decision prompt. This is a leak — the accuracy
              numbers from this run cannot be trusted.
            </ErrorNote>
          )
        ) : (
          <Note tone="warn">
            This prompt may contain a label string, and legitimately so: it carries the non-LLM
            baseline's <strong>prediction</strong> and the preceding agents' output, not the ground
            truth. The distinction is the invariant.
          </Note>
        )}

        <Pane title="System prompt" body={trace.system_prompt} />
        <Pane title="User prompt" body={trace.user_prompt} />

        <details>
          <summary className="cursor-pointer text-2xs text-faint">
            Structured context ({trace.context_keys.length} keys) — what the deterministic backend
            also sees
          </summary>
          <div className="mt-1.5">
            <Pane title="" body={trace.context_json} />
          </div>
        </details>

        {trace.truncated && (
          <p className="text-3xs text-faint">
            Truncated for display. The full prompt was sent to the model.
          </p>
        )}
      </div>
    </details>
  );
}

function Pane({ title, body }: { title: string; body: string }) {
  return (
    <div className="min-w-0">
      {title && (
        <div className="mb-1 text-3xs uppercase tracking-wider text-faint">{title}</div>
      )}
      <pre className="mono max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-surface p-2.5 text-2xs leading-relaxed text-muted">
        {body}
      </pre>
    </div>
  );
}
