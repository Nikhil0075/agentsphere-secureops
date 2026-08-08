import type { ProofInfo } from "../../lib/api";
import { Card, Hash, Note } from "../primitives";

/** Contract states in the order `DecisionProof` moves through them. */
const ORDER = ["Proposed", "Approved", "Finalized"] as const;

type StageTone = "done" | "current" | "blocked" | "pending";

const TONE_CLASS: Record<StageTone, string> = {
  done: "bg-fp-soft border-fp-line text-text",
  current: "bg-primary-soft border-primary-line text-text ring-2 ring-primary-line",
  blocked: "bg-bp-soft border-bp-line text-text",
  pending: "bg-raised border-line text-faint",
};

/**
 * The anchoring lifecycle as stages rather than a single "anchored: true".
 *
 * Where a decision *stops* is the interesting part: a medium or high-risk decision parked at
 * Approved-required is the policy gate holding, visible as a state on chain rather than as a claim
 * in the UI.
 */
export function AnchorLifecycle({ proof }: { proof: ProofInfo | null }) {
  const latest = proof?.attempts?.[proof.attempts.length - 1] ?? null;
  const state = proof?.onchain?.state || proof?.onchain_state || "";
  const risk = proof?.onchain?.risk ?? "";
  const reached = ORDER.indexOf(state as (typeof ORDER)[number]);
  const submitted = Boolean(proof?.tx_hash) || reached >= 0;
  // A rejection recorded locally counts, even with nothing on chain. Reading the verdict only from
  // the contract meant a rejected decision looked identical to an un-reviewed one, because an
  // un-anchored rejection has no transaction to carry it.
  const localApproval = proof?.approval ?? null;
  const locallyRejected = localApproval?.approved === false;
  const rejected = state === "Rejected" || locallyRejected;

  // An attempt with no transaction hash is a submission the chain refused. Distinguishing that
  // from "never tried" is the difference between a stalled rail nobody can explain and one that
  // names its own blocker.
  const attemptFailed = (proof?.attempts?.length ?? 0) > 0 && !proof?.tx_hash;

  // A non-low-risk decision sitting short of Approved is blocked by the contract, not stalled.
  const blockedByPolicy =
    submitted && !rejected && reached < 1 && Boolean(risk) && risk.toLowerCase() !== "low";

  const stages: { label: string; detail: React.ReactNode; tone: StageTone }[] = [
    {
      label: "Digest computed",
      detail: "keccak256 over canonical JSON, off chain",
      tone: proof?.output_hash ? "done" : "pending",
    },
    {
      label: "Submitted",
      detail: latest?.tx_hash ? (
        <Hash value={latest.tx_hash} chars={10} />
      ) : attemptFailed ? (
        <span className="text-tp">refused by the chain</span>
      ) : (
        "no transaction recorded"
      ),
      tone: attemptFailed ? "blocked" : submitted ? (reached >= 1 ? "done" : "current") : "pending",
    },
    {
      label: rejected ? "Rejected" : "Approved",
      detail: proof?.onchain?.approver ? (
        <Hash value={proof.onchain.approver} chars={10} />
      ) : localApproval ? (
        // Recorded here but not witnessed on chain — say which, rather than implying either.
        <span className={locallyRejected ? "text-tp" : "text-fp"}>
          {localApproval.approver} · recorded locally
        </span>
      ) : (
        "awaiting a named human"
      ),
      tone: rejected
        ? "blocked"
        : localApproval?.approved
          ? reached >= 2
            ? "done"
            : "current"
          : reached >= 1
            ? reached >= 2
              ? "done"
              : "current"
            : blockedByPolicy
              ? "blocked"
              : "pending",
    },
    {
      label: "Finalized",
      detail:
        state === "Finalized"
          ? "state committed on chain"
          : locallyRejected
            ? "a rejected decision is never finalised"
            : "blocked until approval is recorded",
      tone: state === "Finalized" ? "done" : locallyRejected ? "blocked" : "pending",
    },
  ];

  return (
    <Card
      title="Anchoring lifecycle"
      subtitle="Only hashes, identities and approval state cross the boundary. Raw evidence never does."
      right={
        proof?.network ? (
          <span className="mono text-2xs text-muted">
            {proof.network}
            {proof.chain_id ? ` · chainId ${proof.chain_id}` : ""}
          </span>
        ) : null
      }
    >
      <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {stages.map((stage, index) => (
          <li
            key={stage.label}
            className={`min-w-0 rounded-xl border px-3 py-3 ${TONE_CLASS[stage.tone]}`}
          >
            <div className="text-3xs font-semibold uppercase tracking-wider text-faint">
              Step {index + 1}
            </div>
            <div className="mt-1 text-sm font-semibold">{stage.label}</div>
            <div className="mt-1 truncate text-2xs text-muted">{stage.detail}</div>
          </li>
        ))}
      </ol>

      {locallyRejected && (
        <Note tone="warn">
          <strong>Rejected by {localApproval?.approver}</strong>
          {localApproval?.recorded_at ? ` on ${localApproval.recorded_at}` : ""}. The rejection and
          its comment live in the application database; only{" "}
          <code className="mono text-2xs">keccak256(comment, approver)</code> is anchorable, and a
          rejected decision is never finalised — <code className="mono text-2xs">finalizeDecision</code>{" "}
          reverts <code className="mono text-2xs">DecisionWasRejected</code>. The digests below stay
          verifiable regardless: rejecting a decision does not erase the record of what was decided.
        </Note>
      )}
      {attemptFailed && (
        <Note tone="warn">
          The rail stops at <strong>Submitted</strong> because the transaction never landed, not
          because the policy gate held it. See the reason on the right — a refused submission is an
          infrastructure problem, and the digests below are unaffected by it.
        </Note>
      )}
      {blockedByPolicy && (
        <Note tone="warn">
          This decision is <strong>{risk}</strong> risk, so{" "}
          <code className="mono text-2xs">finalizeDecision</code> reverts with{" "}
          <code className="mono text-2xs">ApprovalRequired</code> until a human approval is
          recorded. The contract refused — not the application layer.
        </Note>
      )}
      {(proof?.attempts?.length ?? 0) > 1 && (
        <p className="mt-3 text-2xs leading-relaxed text-faint">
          {proof?.attempts.length} anchor attempts recorded. A retry after a network failure writes
          another row rather than overwriting the first, so the history stays honest about what
          happened at the venue.
        </p>
      )}
    </Card>
  );
}
