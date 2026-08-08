import type { DatasetInfo, ProofInfo } from "../../lib/api";
import { Badge, Card, Empty, Hash } from "../primitives";

/**
 * Who is permitted to write, and who actually signed this decision.
 *
 * The addresses come from the deployment record rather than from the chain, so this panel renders
 * with the network down. That is the point of showing it here at all: permissioning is a property
 * of the deployment, not something the running application asserts about itself.
 */
export function AgentRegistryPanel({
  proof,
  chain,
}: {
  proof: ProofInfo | null;
  chain?: DatasetInfo["chain"];
}) {
  const agents = {
    ...(chain?.agents ?? {}),
    ...(proof?.registered_agents ?? {}),
  };
  const roles = Object.entries(agents);
  const signer = (proof?.agent_address || "").toLowerCase();

  return (
    <Card
      title="Permissioned agent registry"
      subtitle="A caller the registry does not list is refused by the contract, not by this application."
      right={roles.length ? <Badge tone="info">{roles.length} registered</Badge> : null}
    >
      {roles.length === 0 ? (
        <Empty>
          No registry recorded. Deploy the contracts (<span className="mono">npm run deploy:sepolia</span>
          ) to populate it.
        </Empty>
      ) : (
        <ul className="space-y-1.5">
          {roles.map(([role, address]) => {
            const signed = Boolean(signer) && address.toLowerCase() === signer;
            return (
              <li
                key={role}
                className={`flex flex-wrap items-center justify-between gap-2 rounded-lg px-2.5 py-2 ${
                  signed ? "bg-primary-soft" : "bg-raised"
                }`}
              >
                <span className="text-xs font-medium text-text">{role}</span>
                <span className="flex items-center gap-2">
                  {signed && <Badge tone="low">signed this decision</Badge>}
                  <Hash value={address} chars={12} />
                </span>
              </li>
            );
          })}
        </ul>
      )}

      <p className="mt-3 text-2xs leading-relaxed text-faint">
        <code className="mono">submitDecision</code> and{" "}
        <code className="mono">finalizeDecision</code> both carry{" "}
        <code className="mono">onlyActiveAgent</code>, which reverts{" "}
        <code className="mono">UnauthorisedAgent(msg.sender)</code> unless{" "}
        <code className="mono">registry.isActive(msg.sender)</code>. Revoking an agent takes effect
        immediately for every future write, and no key held by this application can undo it.
      </p>
    </Card>
  );
}
