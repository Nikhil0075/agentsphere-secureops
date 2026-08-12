import { useEffect, useMemo, useRef, useState } from "react";
import type { IntegrityInfo, ProofInfo } from "../../lib/api";
import { useReducedMotion } from "../charts";
import { Card, Note } from "../primitives";

/** Contract states in the order `DecisionProof` moves through them. */
const ORDER = ["proposed", "approved", "finalized"] as const;

/** How long each stage holds during a walkthrough. Slow enough to narrate over. */
const PLAY_MS = 2200;

type Tone = "done" | "current" | "blocked" | "pending";

/**
 * Light-on-dark status colours.
 *
 * The severity tokens (`text-tp`, `text-fp`) were contrast-tuned against white and are unreadable
 * on `#101421`, so this panel carries its own set rather than reusing them at the wrong luminance.
 */
const TONE = {
  done: { dot: "bg-emerald-400", text: "text-emerald-300", ring: "border-emerald-400/40" },
  current: { dot: "bg-brand", text: "text-brand", ring: "border-brand/60" },
  blocked: { dot: "bg-rose-400", text: "text-rose-300", ring: "border-rose-400/40" },
  pending: { dot: "bg-white/30", text: "text-white/55", ring: "border-white/10" },
} as const;

export interface AnchorState {
  latest: ProofInfo["attempts"][number] | null;
  state: string;
  risk: string;
  reached: number;
  submitted: boolean;
  localApproval: ProofInfo["approval"];
  locallyRejected: boolean;
  rejected: boolean;
  attemptFailed: boolean;
  blockedByPolicy: boolean;
}

/**
 * Everything the panel needs to know about where a decision stopped.
 *
 * Lifted verbatim from the former `AnchorLifecycle` rather than re-derived: each branch here
 * encodes a bug that was found and fixed once already, and `frontend/tests/proof.test.tsx` guards
 * them. Exported so those distinctions can be tested directly rather than only through the DOM.
 */
export function deriveAnchorState(proof: ProofInfo | null): AnchorState {
  const latest = proof?.attempts?.[proof.attempts.length - 1] ?? null;
  // The Python chain client returns Solidity enum names in lowercase. Normalise mocked/legacy
  // capitalised values too so a genuinely finalized decision does not appear stuck at Submitted.
  const state = (proof?.onchain?.state || proof?.onchain_state || "").toLowerCase();
  const risk = proof?.onchain?.risk ?? "";
  const reached = ORDER.indexOf(state as (typeof ORDER)[number]);
  const submitted = Boolean(proof?.tx_hash) || reached >= 0;
  // A rejection recorded locally counts, even with nothing on chain. Reading the verdict only from
  // the contract meant a rejected decision looked identical to an un-reviewed one, because an
  // un-anchored rejection has no transaction to carry it.
  const localApproval = proof?.approval ?? null;
  const locallyRejected = localApproval?.approved === false;
  const rejected = state === "rejected" || locallyRejected;

  // An attempt that never produced a transaction is a submission the chain refused. Distinguishing
  // that from "never tried" is the difference between a stalled rail nobody can explain and one
  // that names its own blocker. A content-addressed recovery is *not* a refusal, which is why this
  // reads `anchored` rather than `tx_hash`.
  const attemptFailed =
    (proof?.attempts?.length ?? 0) > 0 &&
    !proof?.anchored &&
    latest?.onchain_state === "unanchored";

  // A non-low-risk decision sitting short of Approved is blocked by the contract, not stalled.
  const blockedByPolicy =
    submitted && !rejected && reached < 1 && Boolean(risk) && risk.toLowerCase() !== "low";

  return {
    latest,
    state,
    risk,
    reached,
    submitted,
    localApproval,
    locallyRejected,
    rejected,
    attemptFailed,
    blockedByPolicy,
  };
}

/** Split a 0x-prefixed digest into its bytes. Returns [] for anything that is not one. */
function toBytes(hex: string): string[] {
  const body = (hex || "").replace(/^0x/, "");
  if (body.length < 2) return [];
  return body.match(/.{1,2}/g) ?? [];
}

/** How many bytes differ between two digests. 0 when either is absent. */
function countDiffering(a: string, b: string): number {
  const left = toBytes(a);
  const right = toBytes(b);
  if (!left.length || !right.length) return 0;
  return left.filter((byte, index) => right[index] !== undefined && right[index] !== byte).length;
}

/**
 * A 32-byte digest drawn as 32 bytes.
 *
 * The point of the whole screen is that a digest is a fixed-size fingerprint of a much larger
 * record, and that altering the record moves it. A truncated `0x8f3a…c41d` cannot show that; a
 * grid can. When `against` is supplied the differing bytes are marked, which is what turns the
 * word TAMPERED into something a judge can see from the back of the room.
 */
function ByteGrid({
  value,
  against,
  label,
}: {
  value: string;
  against?: string;
  label: string;
}) {
  const bytes = toBytes(value);
  const other = toBytes(against ?? "");
  const differing = against ? bytes.filter((b, i) => other[i] !== undefined && other[i] !== b).length : 0;

  if (!bytes.length) {
    return (
      <div>
        <div className="text-3xs uppercase tracking-[0.14em] text-white/55">{label}</div>
        <p className="mono mt-1 text-2xs text-white/55">not computed</p>
      </div>
    );
  }

  return (
    <div className="min-w-0">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3">
        <span className="text-3xs uppercase tracking-[0.14em] text-white/55">{label}</span>
        <span className="mono text-3xs text-white/55">
          {bytes.length} bytes
          {against ? ` · ${differing} differ` : ""}
        </span>
      </div>
      <div
        className="mt-1.5 grid grid-cols-8 gap-[3px] sm:grid-cols-16"
        role="img"
        aria-label={
          against
            ? `${label}: ${bytes.length} bytes, ${differing} differing from the anchored digest`
            : `${label}: ${bytes.length} bytes`
        }
      >
        {bytes.map((byte, index) => {
          const changed = against ? other[index] !== undefined && other[index] !== byte : false;
          return (
            <span
              key={`${index}-${byte}`}
              data-changed={changed ? "true" : undefined}
              className={`mono rounded-xs px-1 py-0.5 text-center text-4xs leading-tight ${
                changed
                  ? "bg-rose-500/30 text-rose-200 ring-1 ring-rose-400/50"
                  : "bg-white/[0.06] text-white/60"
              }`}
            >
              {byte}
            </span>
          );
        })}
      </div>
    </div>
  );
}

/** A short labelled value inside a stage detail. */
function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-3xs uppercase tracking-[0.14em] text-white/55">{label}</dt>
      <dd className="mono mt-0.5 truncate text-xs text-white/85">{children}</dd>
    </div>
  );
}

const DASH = <span className="text-white/30">—</span>;

/**
 * The path a decision takes from a database row to a slot in contract storage.
 *
 * Replaces the former four-box `AnchorLifecycle`, which showed only the on-chain half and left the
 * more interesting question — *what actually crosses the boundary, and in what form* — to be
 * assembled from three other cards. Six stages, a hard boundary marker in the middle, and every
 * value drawn from the payloads the page already holds. Where a value is unknown it renders as a
 * dash: there are no placeholder block hashes and no invented neighbouring blocks, because a
 * fabricated chain on this particular screen would undermine the one claim it exists to make.
 */
export function AnchorJourney({
  proof,
  integrity,
}: {
  proof: ProofInfo | null;
  integrity: IntegrityInfo | null;
}) {
  const reduced = useReducedMotion();
  const [selected, setSelected] = useState(0);
  const [playing, setPlaying] = useState(false);
  const timer = useRef<number | null>(null);

  const anchor = useMemo(() => deriveAnchorState(proof), [proof]);
  const { latest, state, risk, reached, submitted, localApproval, locallyRejected } = anchor;
  const { rejected, attemptFailed, blockedByPolicy } = anchor;

  const tampered = integrity?.valid === false;
  const hasDigest = Boolean(integrity?.recomputed_output_hash || proof?.output_hash);
  const anchoredDigest = integrity?.anchored_output_hash ?? "";
  const differing = countDiffering(anchoredDigest, integrity?.recomputed_output_hash ?? "");

  const stages = [
    {
      key: "record",
      short: "Stored record",
      status: integrity?.incident_id || "not found",
      title: "The decision as it lives in SQLite",
      tone: (integrity?.found ? "done" : "pending") as Tone,
      source: "app/db/session.py · agent_runs.output_json, evidence.payload_json",
      body: (
        <>
          <dl className="grid gap-3 sm:grid-cols-2">
            <Fact label="Incident">{integrity?.incident_id || DASH}</Fact>
            <Fact label="Workflow">{integrity?.workflow_id || DASH}</Fact>
          </dl>
          <p className="mt-3 text-2xs leading-relaxed text-white/60">
            Six agent outputs and every evidence row the chain reasoned over. This is the record an
            operator with database access could edit — which is the entire reason the rest of this
            journey exists.
          </p>
        </>
      ),
    },
    {
      key: "canonical",
      short: "Canonicalised",
      status: "sorted keys, no whitespace",
      title: "One serialisation, used by writer and verifier alike",
      tone: (integrity?.found ? "done" : "pending") as Tone,
      source: "app/db/session.py · canonical_evidence_payload",
      body: (
        <p className="text-2xs leading-relaxed text-white/70">
          Sorted keys, no whitespace. Both the code that anchors and the code that later verifies
          call the <span className="mono text-brand">same</span> serialiser — two serialisations
          differing by a single space would make every proof read as tampered forever, so there is
          deliberately only one.
        </p>
      ),
    },
    {
      key: "digest",
      short: "keccak256",
      // "matching" would claim a comparison that has not happened: an unanchored decision has a
      // recomputed digest and nothing to check it against.
      status: tampered
        ? `${differing} of 32 bytes differ`
        : !hasDigest
          ? "not computed"
          : anchoredDigest
            ? "32 bytes, matching"
            : "32 bytes, not yet anchored",
      title: tampered
        ? "The digest moved — the record was altered"
        : anchoredDigest
          ? "Two 32-byte digests, still agreeing"
          : "A 32-byte digest, not yet anchored",
      tone: (tampered ? "blocked" : hasDigest ? "done" : "pending") as Tone,
      source: "app/services/integrity.py · recomputed every time, never read from a stored column",
      body: (
        <>
          <div className="space-y-3">
            <ByteGrid label="Anchored output digest" value={anchoredDigest} />
            <ByteGrid
              label="Recomputed from the record now"
              value={integrity?.recomputed_output_hash ?? ""}
              // Only a comparison when there is something to compare against.
              against={anchoredDigest || undefined}
            />
          </div>
          <p className="mt-3 text-2xs leading-relaxed text-white/60">
            {tampered ? (
              <>
                The marked bytes are the difference. Nothing on chain was touched — the record was
                altered underneath a digest its operator does not control.
              </>
            ) : !anchoredDigest ? (
              <>
                Nothing is anchored yet, so there is nothing to compare this against. Anchor the
                decision to fix these 32 bytes somewhere this application cannot reach.
              </>
            ) : (
              <>
                A fixed 32 bytes regardless of how large the record is. Change one character of one
                agent output and roughly half of these bytes move.
              </>
            )}
          </p>
        </>
      ),
    },
    {
      key: "transaction",
      short: "Transaction",
      status: latest?.tx_hash ? (
        `${latest.tx_hash.slice(0, 10)}…`
      ) : proof?.anchored && proof.onchain_decision_id ? (
        <span className="text-emerald-300">existing decision #{proof.onchain_decision_id}</span>
      ) : attemptFailed ? (
        <span className="text-rose-300">refused by the chain</span>
      ) : (
        "no transaction recorded"
      ),
      title: attemptFailed ? "The chain refused the submission" : "Signed by the agent's own key",
      tone: (attemptFailed ? "blocked" : submitted ? "done" : "pending") as Tone,
      source: "contracts/DecisionProof.sol · submitDecision, onlyActiveAgent",
      body: (
        <>
          <dl className="grid gap-3 sm:grid-cols-2">
            <Fact label="Signed by">{proof?.agent_address || DASH}</Fact>
            <Fact label="Transaction">
              {latest?.tx_hash ? (
                proof?.explorer_url ? (
                  <a
                    className="text-brand underline decoration-brand/40 underline-offset-2 hover:decoration-brand"
                    href={proof.explorer_url}
                    target="_blank"
                    rel="noreferrer noopener"
                  >
                    {latest.tx_hash}
                  </a>
                ) : (
                  latest.tx_hash
                )
              ) : proof?.anchored && proof.onchain_decision_id ? (
                <span className="text-emerald-300">existing decision #{proof.onchain_decision_id}</span>
              ) : attemptFailed ? (
                <span className="text-rose-300">refused by the chain</span>
              ) : (
                DASH
              )}
            </Fact>
          </dl>
          <p className="mt-3 text-2xs leading-relaxed text-white/60">
            Each agent role signs with its own key, so the decision carries the identity of the
            agent that made it. A caller the registry does not list is rejected by the contract
            itself, not by this application.
          </p>
          {attemptFailed && proof?.reason && (
            <p className="mono mt-2 break-words rounded-md bg-rose-500/10 px-2.5 py-2 text-3xs leading-relaxed text-rose-200 ring-1 ring-rose-400/30">
              {proof.reason}
            </p>
          )}
        </>
      ),
    },
    {
      key: "block",
      short: "Block",
      status: proof?.block_number
        ? `block ${proof.block_number.toLocaleString()}`
        : "not in a block",
      title: proof?.recovered
        ? "Included in a block by the original submission"
        : "Included in a Sepolia block",
      // Green whenever these digests are in a block, whoever submitted them. Grey reads as "not on
      // chain", which is exactly what a recovered decision is not.
      tone: (proof?.block_number || proof?.anchored ? "done" : "pending") as Tone,
      source: "app/blockchain/client.py · receipt.blockNumber, receipt.gasUsed",
      body: (
        <>
          <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Fact label="Block">
              {proof?.block_number ? proof.block_number.toLocaleString() : DASH}
            </Fact>
            <Fact label="Gas used">{proof?.gas_used ? proof.gas_used.toLocaleString() : DASH}</Fact>
            <Fact label="Network">{proof?.network || DASH}</Fact>
            <Fact label="Chain id">{proof?.chain_id ?? DASH}</Fact>
          </dl>
          <p className="mt-3 text-2xs leading-relaxed text-white/60">
            Once included, the digest is replicated across every node on the network. Removing it
            would mean rewriting the block and every block after it, which is a cost no operator of
            this application can pay.
          </p>
        </>
      ),
    },
    {
      key: "slot",
      short: "Decision slot",
      status:
        state === "finalized"
          ? "state committed on chain"
          : locallyRejected
            ? "a rejected decision is never finalised"
            : blockedByPolicy
              ? "approval required by the contract"
              : "blocked until approval is recorded",
      title: rejected ? "Rejected — and never finalisable" : "One struct in contract storage",
      tone: (rejected
        ? "blocked"
        : state === "finalized"
          ? "done"
          : blockedByPolicy
            ? "blocked"
            : reached >= 0
              ? "current"
              : "pending") as Tone,
      source: "contracts/DecisionProof.sol · mapping(uint256 => Decision) _decisions",
      body: (
        <>
          <dl className="grid gap-3 sm:grid-cols-2">
            <Fact label="Decision id">
              {proof?.onchain_decision_id !== null && proof?.onchain_decision_id !== undefined
                ? `#${proof.onchain_decision_id}`
                : DASH}
            </Fact>
            <Fact label="Approver">
              {proof?.onchain?.approver ? (
                proof.onchain.approver
              ) : localApproval ? (
                <span className={locallyRejected ? "text-rose-300" : "text-emerald-300"}>
                  {localApproval.approver} · recorded locally
                </span>
              ) : (
                DASH
              )}
            </Fact>
          </dl>

          {/* The contract's own state machine, as the last leg of the journey rather than as a
              second strip elsewhere on the page. */}
          <ol className="mt-3 flex flex-wrap items-center gap-1.5">
            {(rejected ? ["Proposed", "Rejected"] : ["Proposed", "Approved", "Finalized"]).map(
              (name, index) => {
                const active = rejected
                  ? index === 0
                    ? submitted
                    : true
                  : reached >= index;
                const isBlock = rejected && index === 1;
                return (
                  <li key={name} className="flex items-center gap-1.5">
                    {index > 0 && <span aria-hidden="true" className="h-px w-3 bg-white/20" />}
                    <span
                      className={`mono rounded-full px-2 py-0.5 text-3xs ${
                        isBlock
                          ? "bg-rose-500/20 text-rose-200 ring-1 ring-rose-400/40"
                          : active
                            ? "bg-emerald-400/15 text-emerald-300 ring-1 ring-emerald-400/30"
                            : "bg-white/[0.06] text-white/55"
                      }`}
                    >
                      {name}
                    </span>
                  </li>
                );
              },
            )}
          </ol>

          <p className="mt-3 text-2xs leading-relaxed text-white/60">
            {state === "finalized"
              ? "state committed on chain"
              : locallyRejected
                ? "a rejected decision is never finalised"
                : blockedByPolicy
                  ? `This decision is ${risk} risk, so finalizeDecision reverts with ApprovalRequired until a human approval is recorded.`
                  : "blocked until approval is recorded"}
          </p>
        </>
      ),
    },
  ];

  const active = stages[Math.min(selected, stages.length - 1)];

  // Autoplay. Stops at the last stage and never loops -- a timer that keeps moving while someone
  // is mid-sentence is a liability on stage.
  useEffect(() => {
    if (!playing || reduced) return;
    if (selected >= stages.length - 1) {
      setPlaying(false);
      return;
    }
    timer.current = window.setTimeout(() => setSelected((n) => n + 1), PLAY_MS);
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [playing, reduced, selected, stages.length]);

  const pick = (index: number) => {
    setPlaying(false);
    setSelected(index);
  };

  return (
    <Card pad={false}>
      <div className="overflow-hidden rounded-2xl bg-header">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-header-line px-5 py-4">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-white">
              How this decision is stored and anchored
            </h2>
            <p className="mt-0.5 text-2xs text-white/60">
              Six stages. Only the 32-byte digests cross the boundary — never evidence, prompts or
              rationale.
            </p>
          </div>
          <button
            type="button"
            onClick={() => {
              if (playing) return setPlaying(false);
              setSelected(0);
              setPlaying(true);
            }}
            aria-label={playing ? "Pause the walkthrough" : "Play the walkthrough"}
            disabled={reduced}
            title={reduced ? "Disabled while the system requests reduced motion" : undefined}
            className="shrink-0 rounded-md border border-brand/40 px-3 py-1.5 text-2xs font-semibold text-brand transition-colors hover:bg-brand/10 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {playing ? "❚❚ Pause" : "▶ Play walkthrough"}
          </button>
        </div>

        {/* The rail. Horizontally scrollable on narrow screens so it never widens the page. */}
        <ol className="flex items-stretch gap-0 overflow-x-auto px-5 py-4">
          {stages.map((stage, index) => {
            const tone = TONE[stage.tone];
            const current = index === selected;
            return (
              <li key={stage.key} className="flex shrink-0 items-center">
                {/* The boundary. Everything left of it is off chain. */}
                {index === 3 && (
                  <span className="mx-2 flex shrink-0 flex-col items-center gap-1 px-1">
                    <span aria-hidden="true" className="h-8 w-px bg-brand/50" />
                    <span className="text-4xs uppercase tracking-[0.14em] text-brand/70">
                      boundary
                    </span>
                    <span aria-hidden="true" className="h-8 w-px bg-brand/50" />
                  </span>
                )}
                {index > 0 && index !== 3 && (
                  <span aria-hidden="true" className="h-px w-4 shrink-0 bg-white/15 sm:w-6" />
                )}
                <button
                  type="button"
                  onClick={() => pick(index)}
                  aria-current={current ? "step" : undefined}
                  // Explicit, rather than the concatenation of the label and the status line --
                  // a screen reader should announce the stage, not read a digest byte count as
                  // part of the control's name.
                  aria-label={`Stage ${index + 1}: ${stage.short}`}
                  className={`w-[10.5rem] rounded-lg border px-3 py-2.5 text-left transition-colors ${
                    current
                      ? `bg-white/[0.08] ${tone.ring}`
                      : "border-white/10 hover:bg-white/[0.05]"
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${tone.dot}`} />
                    <span className="text-4xs uppercase tracking-[0.14em] text-white/55">
                      Stage {index + 1}
                    </span>
                  </span>
                  <span className={`mt-1 block text-xs font-semibold ${current ? "text-white" : tone.text}`}>
                    {stage.short}
                  </span>
                  {/* The state each stage reached, on the rail rather than behind a click. A judge
                      should be able to read where a decision stopped without touching anything. */}
                  <span className="mono mt-0.5 block break-words text-4xs leading-snug text-white/55">
                    {stage.status}
                  </span>
                </button>
              </li>
            );
          })}
        </ol>

        <div
          aria-live="polite"
          className="border-t border-header-line px-5 py-4"
        >
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
            <h3 className="text-sm font-semibold text-white">{active.title}</h3>
            <span className="mono text-4xs text-white/35">
              stage {selected + 1} of {stages.length}
            </span>
          </div>
          <p className="mono mt-1 break-words text-3xs text-brand/80">{active.source}</p>
          <div className="mt-3">{active.body}</div>
        </div>
      </div>

      {/* Conditions worth stating in full, kept outside the dark panel so the wording matches the
          rest of the page. Rendered only when there is one, or the padding leaves a bare white
          strip under the panel on the ordinary path. */}
      <div
        className={
          locallyRejected || attemptFailed || blockedByPolicy || (proof?.attempts?.length ?? 0) > 1
            ? "px-5 pb-5"
            : "hidden"
        }
      >
        {locallyRejected && (
          <Note tone="warn">
            <strong>Rejected by {localApproval?.approver}</strong>
            {localApproval?.recorded_at ? ` on ${localApproval.recorded_at}` : ""}. The rejection and
            its comment live in the application database; only{" "}
            <code className="mono text-2xs">keccak256(comment, approver)</code> is anchorable, and a
            rejected decision is never finalised —{" "}
            <code className="mono text-2xs">finalizeDecision</code> reverts{" "}
            <code className="mono text-2xs">DecisionWasRejected</code>. The digests stay verifiable
            regardless: rejecting a decision does not erase the record of what was decided.
          </Note>
        )}
        {attemptFailed && (
          <Note tone="warn">
            The journey stops at <strong>Transaction</strong> because it never landed, not because
            the policy gate held it. A refused submission is an infrastructure problem, and the
            digests are unaffected by it.
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
            {proof?.attempts.length} anchor attempts recorded. A retry after a network failure
            writes another row rather than overwriting the first, so the history stays honest about
            what happened at the venue.
          </p>
        )}
      </div>
    </Card>
  );
}
