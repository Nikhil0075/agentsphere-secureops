import type { ProofInfo } from "../../lib/api";
import { Card, Empty } from "../primitives";

/**
 * Where to go and check this yourself.
 *
 * The page previously offered exactly one outbound link, and only when *this* application had
 * landed a transaction of its own. That is the narrower case: `submitDecision` is
 * duplicate-protected, so a retry, an API restart or a lost RPC response resolves the decision by
 * fingerprint against a proof that is already on chain — anchored, verifiable, and with no
 * transaction hash of ours to show for it. The link block then rendered nothing at all, which
 * reads as "there is nothing on chain" when the opposite is true.
 *
 * Every link is built from `explorer_base`, which the API derives from the chain id it actually
 * used. Nothing here hardcodes a host: a link to the wrong network's explorer is worse than no
 * link, and only the server knows which network was involved.
 */
export function ExplorerLinks({ proof }: { proof: ProofInfo | null }) {
  const base = proof?.explorer_base ?? "";
  const anchored = Boolean(proof?.anchored);
  const attempted = (proof?.attempts?.length ?? 0) > 0;

  // Nothing has been attempted yet: the section would be a row of dead labels.
  if (!attempted && !anchored) {
    return (
      <Card
        title="On the explorer"
        subtitle="Public links to the anchored record, once there is one."
      >
        <Empty>
          Press <span className="font-medium text-muted">Anchor proof on chain</span> above. The
          links appear here as soon as the decision is on chain, and stay correct on every
          re-anchor.
        </Empty>
      </Card>
    );
  }

  const links: { label: string; value: string; href: string; note?: string }[] = [];

  if (proof?.tx_hash) {
    links.push({
      label: "Transaction",
      value: proof.tx_hash,
      href: proof.explorer_url || (base ? `${base}/tx/${proof.tx_hash}` : ""),
      note: "the submission this application sent",
    });
  }
  if (proof?.contract_address) {
    links.push({
      label: "DecisionProof",
      value: proof.contract_address,
      href: base ? `${base}/address/${proof.contract_address}` : "",
      note:
        proof.onchain_decision_id !== null && proof.onchain_decision_id !== undefined
          ? `holds decision #${proof.onchain_decision_id}`
          : "the contract holding this decision",
    });
  }
  if (proof?.registry_address) {
    links.push({
      label: "AgentRegistry",
      value: proof.registry_address,
      href: base ? `${base}/address/${proof.registry_address}` : "",
      note: "the contract that decides who may submit",
    });
  }
  if (proof?.agent_address) {
    links.push({
      label: "Submitting agent",
      value: proof.agent_address,
      href: base ? `${base}/address/${proof.agent_address}` : "",
      note: "the wallet that signed, or would have",
    });
  }

  return (
    <Card
      title="On the explorer"
      subtitle="Every link below is public. Check any of it without taking this screen's word for it."
      right={
        proof?.network ? (
          <span className="mono text-2xs text-muted">
            {proof.network}
            {proof.chain_id ? ` · chainId ${proof.chain_id}` : ""}
          </span>
        ) : null
      }
    >
      {anchored && !proof?.tx_hash && (
        // The recovery path, stated rather than left as an absence.
        <p className="mb-3 rounded-md border border-info-line bg-info-soft px-3 py-2 text-2xs leading-relaxed text-muted">
          This decision was already on chain, so no new transaction was sent — the contract is
          duplicate-protected and resolved it by fingerprint. There is no transaction of ours to
          link, but the anchored record below is the same record, and re-anchoring will keep
          resolving to it rather than paying to write it twice.
        </p>
      )}

      <dl className="space-y-2.5">
        {links.map((link) => (
          <div key={link.label} className="min-w-0">
            <dt className="flex flex-wrap items-baseline gap-x-2">
              <span className="text-2xs font-semibold uppercase tracking-wider text-faint">
                {link.label}
              </span>
              {link.note && <span className="text-2xs text-faint">{link.note}</span>}
            </dt>
            <dd className="mt-0.5 min-w-0">
              {link.href ? (
                <a
                  href={link.href}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="mono break-all text-xs text-primary hover:underline"
                >
                  {link.value}
                </a>
              ) : (
                // No explorer is known for this chain id. A wrong link is worse than none.
                <span className="mono break-all text-xs text-muted">{link.value}</span>
              )}
            </dd>
          </div>
        ))}
      </dl>

      {!base && (
        <p className="mt-3 text-2xs leading-relaxed text-faint">
          No public explorer is known for chain id {proof?.chain_id ?? "—"}, so the addresses are
          shown without links rather than pointed at the wrong network.
        </p>
      )}
    </Card>
  );
}
