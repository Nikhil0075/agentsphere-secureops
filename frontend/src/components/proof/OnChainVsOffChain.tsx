import type { ProofInfo } from "../../lib/api";
import { Card, Hash } from "../primitives";

/** Every field of the `Decision` struct, in declaration order. */
const STRUCT_FIELDS: { key: keyof NonNullable<ProofInfo["onchain"]>; label: string; hash?: boolean }[] = [
  { key: "incident_id", label: "incidentId" },
  { key: "evidence_hash", label: "evidenceHash", hash: true },
  { key: "output_hash", label: "outputHash", hash: true },
  { key: "label", label: "label" },
  { key: "risk", label: "risk" },
  { key: "state", label: "state" },
  { key: "agent", label: "agent", hash: true },
  { key: "approver", label: "approver", hash: true },
  { key: "comment_hash", label: "commentHash", hash: true },
  { key: "submitted_at", label: "submittedAt" },
  { key: "decided_at", label: "decidedAt" },
  { key: "finalized_at", label: "finalizedAt" },
];

const NEVER_ANCHORED = [
  "Raw evidence rows from the incident",
  "Every agent's system and user prompt",
  "The triage rationale and its cited evidence ids",
  "The remediation justification and rollback plan",
  "Retrieved similar incidents and their summaries",
  "The approver's comment text — only keccak256(comment, approver) is anchored",
];

/**
 * What crosses the boundary, and what cannot.
 *
 * The left column is the contract's storage, field for field. The right is what stays in SQLite.
 * The distinction is the answer to "aren't you putting security data on a public chain?" — the
 * contract has no function that could accept an evidence row even if a caller wanted to send one.
 */
export function OnChainVsOffChain({ proof }: { proof: ProofInfo | null }) {
  const onchain = proof?.onchain ?? null;

  return (
    <Card
      title="What goes on chain, and what never leaves SQLite"
      subtitle="The left column is the contract's entire storage for a decision."
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="min-w-0">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-fp">On chain</h3>
          <dl className="mt-2 space-y-1.5">
            {STRUCT_FIELDS.map((field) => {
              const value = onchain ? onchain[field.key] : null;
              return (
                <div key={field.label} className="flex items-baseline justify-between gap-3">
                  <dt className="mono shrink-0 text-2xs text-muted">{field.label}</dt>
                  <dd className="min-w-0 truncate text-right text-2xs">
                    {value === null || value === undefined || value === "" || value === 0 ? (
                      <span className="text-faint">—</span>
                    ) : field.hash ? (
                      <Hash value={String(value)} chars={10} />
                    ) : (
                      <span className="mono text-text">{String(value)}</span>
                    )}
                  </dd>
                </div>
              );
            })}
          </dl>
          {!onchain && (
            <p className="mt-2 text-2xs leading-relaxed text-faint">
              Field names shown from the contract ABI. Press “Confirm against the contract” to fill
              them with live values.
            </p>
          )}
        </div>

        <div className="min-w-0">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-tp">
            Never leaves SQLite
          </h3>
          <ul className="mt-2 space-y-1.5">
            {NEVER_ANCHORED.map((item) => (
              <li key={item} className="flex gap-2 text-2xs leading-relaxed text-muted">
                <span aria-hidden="true" className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-tp" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-2xs leading-relaxed text-faint">
            This is not a policy choice that could be relaxed later. There is no function on{" "}
            <code className="mono">DecisionProof</code> that accepts anything but an incident id,
            two 32-byte hashes, a label and a risk level — the storage for the rest does not exist.
          </p>
        </div>
      </div>
    </Card>
  );
}
