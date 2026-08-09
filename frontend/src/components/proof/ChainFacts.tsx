import type { IntegrityInfo, ProofInfo } from "../../lib/api";
import { Button, Card, Hash, Note, Stat } from "../primitives";

/**
 * The concrete chain facts: network, block, gas, contract addresses, transaction.
 *
 * The explorer link uses `proof.explorer_url` from the API. It used to be built in the page from a
 * hardcoded Sepolia host, which silently produced a wrong link on any other network — the URL is
 * derived server-side from the chain id that was actually used.
 */
export function ChainFacts({
  proof,
  integrity,
  onConfirm,
  confirming,
}: {
  proof: ProofInfo | null;
  integrity: IntegrityInfo | null;
  onConfirm: () => void;
  confirming: boolean;
}) {
  // Only a real contract read may be reported as a contract verdict.
  //
  // `integrity.onchain_valid` is computed by comparing against the *locally recorded* proof row,
  // and it reads `true` on a decision whose on-chain state is still "unanchored" — nothing was
  // ever asked. Rendering that as "Contract says match" claims an independent confirmation the
  // system did not obtain, which is the one thing this screen must never do.
  const asked = Boolean(proof?.chain_checked);
  // The explicit `check_chain=true` proof response already contains the result of the contract's
  // verify call. Keep the integrity value as a compatibility fallback for older API responses.
  const confirmedValid = proof?.valid ?? integrity?.onchain_valid;
  const contractSays = !asked
    ? "not asked"
    : confirmedValid === null || confirmedValid === undefined
      ? "no answer"
      : confirmedValid
        ? "match"
        : "no match";

  // Why the anchor did not happen.
  //
  // `ProofInfo.reason` has always carried the chain's own words -- "insufficient funds for gas",
  // "no key for agent role", a decoded Solidity revert -- and this screen used to drop it, leaving
  // a column of em-dashes and no way to tell a failed anchor from one that was never attempted.
  // A wallet that has run out of test ETH is a five-second fix once you can see it, and an
  // afternoon of confusion when you cannot.
  const attempted = (proof?.attempts?.length ?? 0) > 0;
  const failed = attempted && !proof?.anchored;
  const outOfGas = /insufficient funds/i.test(proof?.reason ?? "");

  return (
    <Card
      title="On chain"
      subtitle="Digests, identity and approval state. Never evidence."
      right={
        proof?.chain_checked ? (
          <span className="text-2xs text-fp">contract read</span>
        ) : (
          <span className="text-2xs text-faint">local only</span>
        )
      }
    >
      {failed && (
        <div className="mb-3 rounded-md border border-tp-line bg-tp-soft px-3 py-2.5">
          <p className="text-xs font-semibold text-tp">
            {outOfGas ? "Anchor rejected: the signing wallet is out of test ETH" : "Anchor failed"}
          </p>
          <p className="mono mt-1 break-words text-2xs leading-relaxed text-tp/85">
            {proof?.reason || "no reason reported"}
          </p>
          {outOfGas && proof?.agent_address && (
            <p className="mt-1.5 text-2xs leading-relaxed text-muted">
              Fund <span className="mono">{proof.agent_address}</span> on {proof.network || "the network"} and press
              anchor again. Nothing else about the decision is affected — the digests are already
              computed and the record is intact.
            </p>
          )}
        </div>
      )}

      <div className="grid grid-cols-2 gap-2">
        <Stat label="Network" value={proof?.network || "—"} hint={proof?.chain_id ? `chainId ${proof.chain_id}` : undefined} />
        <Stat label="Decision" value={proof?.onchain_decision_id ? `#${proof.onchain_decision_id}` : "—"} />
        <Stat label="Block" value={proof?.block_number ? proof.block_number.toLocaleString() : "—"} />
        <Stat label="Gas used" value={proof?.gas_used ? proof.gas_used.toLocaleString() : "—"} />
        <Stat
          label="Contract says"
          value={contractSays}
          tone={
            !asked
              ? undefined
              : confirmedValid === false
                ? "bad"
                : confirmedValid === true
                  ? "good"
                  : undefined
          }
          hint={asked ? undefined : "press confirm to ask"}
        />
        <Stat label="State" value={proof?.onchain_state || "—"} />
      </div>

      <dl className="mt-3 space-y-2 border-t border-line pt-3 text-xs">
        <Row label="DecisionProof" value={proof?.contract_address} />
        <Row label="AgentRegistry" value={proof?.registry_address} />
        <Row label="Submitted by" value={proof?.agent_address} />
      </dl>

      {proof?.tx_hash && (
        <div className="mt-3">
          <div className="text-2xs uppercase tracking-wider text-faint">Transaction</div>
          {proof.explorer_url ? (
            <a
              href={proof.explorer_url}
              target="_blank"
              rel="noreferrer"
              className="mono break-all text-xs text-primary hover:underline"
            >
              {proof.tx_hash}
            </a>
          ) : (
            // No explorer is known for this chain id. A wrong link is worse than none.
            <span className="mono break-all text-xs text-muted">{proof.tx_hash}</span>
          )}
        </div>
      )}

      <div className="mt-4 border-t border-line pt-3">
        <Button disabled={confirming} onClick={onConfirm}>
          {confirming ? "Asking the contract…" : "Confirm against the contract"}
        </Button>
        <p className="mt-2 text-2xs leading-relaxed text-faint">
          The only control on this screen that opens a network connection. Everything else on the
          page is recomputed locally, which is why it loads instantly with the venue wifi down.
        </p>
      </div>

      {integrity && !integrity.chain_available && proof?.chain_checked && (
        <Note>
          No chain reachable — comparing against the locally recorded proof instead. The workflow,
          the gate and the digests are unaffected; only the independent confirmation is missing.
        </Note>
      )}
    </Card>
  );
}

function Row({ label, value }: { label: string; value?: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="shrink-0 text-2xs uppercase tracking-wider text-faint">{label}</dt>
      <dd className="min-w-0 text-right">
        {value ? <Hash value={value} chars={14} /> : <span className="text-faint">—</span>}
      </dd>
    </div>
  );
}
