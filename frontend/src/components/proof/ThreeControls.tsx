import type { IntegrityInfo, ProofInfo } from "../../lib/api";
import { Badge, Card } from "../primitives";

/**
 * The three things a database cannot do, each named with the mechanism that enforces it.
 *
 * This is the answer to "why a blockchain and not an append-only table?", and it is deliberately
 * concrete: every row cites the Solidity error or the Python module that does the work, so a judge
 * can go and read it rather than take the claim on trust.
 */
export function ThreeControls({
  proof,
  integrity,
}: {
  proof: ProofInfo | null;
  integrity: IntegrityInfo | null;
}) {
  const anchored = Boolean(integrity?.anchored_output_hash);
  const tampered = integrity?.valid === false;

  const controls = [
    {
      title: "Reject an unauthorised writer at the storage layer",
      mechanism: "AgentRegistry.isActive → UnauthorisedAgent(msg.sender)",
      body: (
        <>
          <code className="mono text-2xs">submitDecision</code> carries{" "}
          <code className="mono text-2xs">onlyActiveAgent</code>, so a caller the registry does
          not list is refused by the contract itself. A database enforces access control through
          software administered by the same party that operates the database; here the check runs
          somewhere that party does not control.
        </>
      ),
      status: proof?.registry_address
        ? { label: `${Object.keys(proof.registered_agents).length || "—"} registered`, tone: "low" }
        : { label: "no registry", tone: "neutral" },
    },
    {
      title: "Block finalisation of a high-risk action without a human",
      mechanism: "finalizeDecision → ApprovalRequired(decisionId)",
      body: (
        <>
          <code className="mono text-2xs">
            if (d.risk != Risk.Low &amp;&amp; d.state != State.Approved) revert
            ApprovalRequired(decisionId)
          </code>
          . The rule sits in the contract, not in the application layer — so it is not something the
          operator can patch out between the demo and production.
        </>
      ),
      status:
        proof?.onchain?.state === "Finalized"
          ? { label: "finalised", tone: "low" }
          : proof?.onchain_state
            ? { label: proof.onchain_state, tone: "medium" }
            : { label: "not anchored", tone: "neutral" },
    },
    {
      title: "Detect tampering by the party operating the storage",
      mechanism: "services/integrity.py recomputes; it never reads a stored hash column",
      body: (
        <>
          Both digests are rebuilt from{" "}
          <code className="mono text-2xs">agent_runs.output_json</code> and{" "}
          <code className="mono text-2xs">evidence.payload_json</code> every time. An earlier
          version compared the stored hash column against the chain — both sides came from the same
          write, so editing an agent output verified clean. The operator controls this table and
          controls nothing about the anchored digest.
        </>
      ),
      status: !anchored
        ? { label: "not anchored", tone: "neutral" }
        : tampered
          ? { label: "tampering detected", tone: "high" }
          : { label: "digests match", tone: "low" },
    },
  ] as const;

  return (
    <Card
      title="What the chain buys that a database cannot"
      subtitle="Three controls, each enforced somewhere the operator of this application does not control."
    >
      <div className="grid gap-3 lg:grid-cols-3">
        {controls.map((control, index) => (
          <div key={control.title} className="min-w-0 rounded-xl bg-raised p-4">
            <div className="flex items-start justify-between gap-2">
              <span className="text-2xs font-semibold text-faint">0{index + 1}</span>
              <Badge tone={control.status.tone}>{control.status.label}</Badge>
            </div>
            <h3 className="mt-2 text-sm font-semibold leading-snug text-text">{control.title}</h3>
            <p className="mono mt-1.5 break-words text-3xs leading-relaxed text-primary">
              {control.mechanism}
            </p>
            <p className="mt-2 text-2xs leading-relaxed text-muted">{control.body}</p>
          </div>
        ))}
      </div>
    </Card>
  );
}
