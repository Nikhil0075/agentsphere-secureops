import type { IntegrityInfo } from "../../lib/api";
import { Card, Hash } from "../primitives";

export interface TamperChange {
  field: string;
  before: string;
  after: string;
}

/**
 * Scene 5's moment, made legible.
 *
 * The edit and its consequence sit on one line: the field an insider changed, and the digest that
 * stopped matching because of it. Colour carries the meaning (struck-through grey → red), so the
 * room reads it before anyone finishes the sentence.
 */
export function TamperDiff({
  change,
  integrity,
}: {
  change: TamperChange;
  integrity: IntegrityInfo | null;
}) {
  const outputBroken = integrity?.output_valid === false;
  const evidenceBroken = integrity?.evidence_valid === false;

  return (
    <Card pad={false} className="border border-tp-line">
      <div className="grid gap-4 rounded-2xl bg-tp-soft px-5 py-4 lg:grid-cols-[1.1fr_1fr]">
        <div className="min-w-0">
          <div className="text-2xs font-semibold uppercase tracking-wider text-tp">
            Stored record edited
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <code className="mono rounded bg-surface px-1.5 py-0.5 text-2xs text-muted">
              {change.field}
            </code>
            <span className="mono rounded bg-raised px-2 py-1 text-xs text-muted line-through">
              {change.before || "—"}
            </span>
            <span aria-hidden="true" className="text-muted">
              →
            </span>
            <span className="mono rounded bg-tp px-2 py-1 text-xs font-bold text-white">
              {change.after || "—"}
            </span>
          </div>
          <p className="mt-2 text-2xs leading-relaxed text-muted">
            Exactly what an insider with database access would do: one{" "}
            <code className="mono">UPDATE</code> against{" "}
            <code className="mono">agent_runs.output_json</code>. No hash column was touched and no
            transaction was sent — which is precisely why it is detectable.
          </p>
        </div>

        <div className="min-w-0 rounded-xl bg-surface/70 p-3">
          <div className="text-2xs font-semibold uppercase tracking-wider text-faint">
            Recomputed digests
          </div>
          <dl className="mt-2 space-y-2">
            <DigestRow
              label="Agent output"
              anchored={integrity?.anchored_output_hash ?? ""}
              recomputed={integrity?.recomputed_output_hash ?? ""}
              broken={outputBroken}
            />
            <DigestRow
              label="Evidence"
              anchored={integrity?.anchored_evidence_hash ?? ""}
              recomputed={integrity?.recomputed_evidence_hash ?? ""}
              broken={evidenceBroken}
            />
          </dl>
        </div>
      </div>
    </Card>
  );
}

function DigestRow({
  label,
  anchored,
  recomputed,
  broken,
}: {
  label: string;
  anchored: string;
  recomputed: string;
  broken: boolean;
}) {
  return (
    <div>
      <dt className="text-3xs uppercase tracking-wider text-faint">
        {label}
        {broken && <span className="ml-1.5 font-semibold text-tp">diverged</span>}
      </dt>
      <dd className="mt-0.5 space-y-0.5">
        <div className="flex items-baseline gap-2">
          <span className="w-[4.5rem] shrink-0 text-3xs text-faint">anchored</span>
          <Hash value={anchored} chars={12} />
        </div>
        <div className="flex items-baseline gap-2">
          <span className="w-[4.5rem] shrink-0 text-3xs text-faint">now</span>
          <span className={broken ? "font-semibold text-tp" : ""}>
            <Hash value={recomputed} chars={12} />
          </span>
        </div>
      </dd>
    </div>
  );
}
