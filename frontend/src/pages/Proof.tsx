import { useCallback, useEffect, useState } from "react";
import { api, type DatasetInfo, type IntegrityInfo, type ProofInfo } from "../lib/api";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNote,
  HashPair,
  PageIntro,
  Spinner,
} from "../components/primitives";
import { AgentRegistryPanel } from "../components/proof/AgentRegistryPanel";
import { AnchorJourney } from "../components/proof/AnchorJourney";
import { ChainFacts } from "../components/proof/ChainFacts";
import { ExplorerLinks } from "../components/proof/ExplorerLinks";
import { OnChainVsOffChain } from "../components/proof/OnChainVsOffChain";
import { TamperDiff, type TamperChange } from "../components/proof/TamperDiff";
import { ThreeControls } from "../components/proof/ThreeControls";

/**
 * Scene 5 — the tamper-detection moment, and the argument for the chain.
 *
 * Two sources, both zero-RPC on mount. `api.verify` recomputes both digests from stored data and
 * owns the verdict; `api.proof` reports what is known about the anchor — block, gas, addresses,
 * attempts — without opening a connection. Reaching the contract is a single explicit button,
 * because `AppState.chain()` reconnects per call and a page that connects on render puts a public
 * testnet on the demo's critical path.
 *
 * Nothing here reads back a stored hash column for the verdict. That is what makes TAMPERED mean
 * something rather than being a flag the same writer could have set.
 */
export function Proof({
  decisionId,
  chain,
  onGoToWorkflow,
}: {
  decisionId: string | null;
  chain?: DatasetInfo["chain"];
  onGoToWorkflow: () => void;
}) {
  const [integrity, setIntegrity] = useState<IntegrityInfo | null>(null);
  const [proof, setProof] = useState<ProofInfo | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [lastChange, setLastChange] = useState<TamperChange | null>(null);

  const refresh = useCallback(async () => {
    if (!decisionId) return;
    const [next, info] = await Promise.all([api.verify(decisionId), api.proof(decisionId)]);
    setIntegrity(next);
    setProof(info);
  }, [decisionId]);

  useEffect(() => {
    if (!decisionId) {
      setIntegrity(null);
      setProof(null);
      setLastChange(null);
      return;
    }
    setBusy("verify");
    setError("");
    Promise.all([api.verify(decisionId), api.proof(decisionId)])
      .then(([next, info]) => {
        setIntegrity(next);
        setProof(info);
      })
      .catch((e) => setError(e.message))
      .finally(() => setBusy(""));
  }, [decisionId]);

  const act = async (
    what: string,
    fn: () => Promise<unknown>,
    refreshAfter = true,
  ) => {
    setBusy(what);
    setError("");
    try {
      await fn();
      if (refreshAfter) await refresh();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  };

  if (!decisionId) {
    return (
      <div className="space-y-4">
        <PageIntro
          eyebrow="Scene 5 · Integrity proof"
          title="Make tampering visible, not merely detectable."
          description="Anchor the completed decision, compare recomputed digests, then demonstrate exactly what changes when stored evidence is altered."
        />
        <Card title="Decision proof" subtitle="Anchored digests, and what happens when the record changes underneath them.">
          <Empty>
            No decision yet. Run the agent workflow on an incident first — it produces the decision
            this screen anchors and verifies.
          </Empty>
          <div className="flex justify-center">
            <Button variant="primary" onClick={onGoToWorkflow}>
              Go to the workflow
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  const valid = integrity?.valid;
  const anchored = Boolean(integrity?.anchored_output_hash);

  return (
    <div className="space-y-4">
      <PageIntro
        eyebrow="Scene 5 · Integrity proof"
        title="Make tampering visible, not merely detectable."
        description="Local digest recomputation shows the exact mismatch; live contract confirmation remains here as a deliberate, decision-level action."
      />

      {/* The verdict. Largest thing on the page on purpose — it is what the room should read. */}
      <Card pad={false}>
        <div
          className={`rounded-2xl px-6 py-7 ${
            valid === true ? "bg-fp-soft" : valid === false ? "bg-tp-soft" : "bg-raised"
          }`}
        >
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="text-2xs font-medium uppercase tracking-wider text-muted">
                Decision integrity
              </div>
              <div
                className={`mt-1 text-4xl font-bold tracking-tight ${
                  valid === true ? "text-fp" : valid === false ? "text-tp" : "text-muted"
                }`}
              >
                {valid === true ? "VALID" : valid === false ? "TAMPERED" : "NOT ANCHORED"}
              </div>
              <p className="mono mt-1.5 truncate text-xs text-muted">{decisionId}</p>
              {(integrity?.incident_id || integrity?.workflow_id) && (
                <p className="mono mt-0.5 truncate text-2xs text-faint">
                  {integrity.incident_id} · {integrity.workflow_id}
                </p>
              )}
            </div>

            <div className="max-w-md text-xs leading-relaxed text-muted">
              {valid === false ? (
                <>
                  The stored {integrity?.tampered.join(" and ")} no longer hashes to the anchored
                  proof. <strong className="text-tp">Nothing on chain was touched</strong> — the
                  record was altered underneath it, and that is detectable precisely because the
                  operator of this database does not control the digest.
                </>
              ) : valid === true ? (
                <>
                  Digests recomputed from the stored agent outputs and evidence rows still match
                  what was anchored. Nothing here reads back a saved hash column — the comparison
                  is done from the underlying data every time.
                </>
              ) : (
                <>Anchor the decision to create a digest to verify against.</>
              )}
            </div>
          </div>
        </div>
      </Card>

      {error && <ErrorNote>{error}</ErrorNote>}
      {busy === "verify" && !integrity && <Spinner label="Verifying…" />}

      {lastChange && <TamperDiff change={lastChange} integrity={integrity} />}

      <AnchorJourney proof={proof} integrity={integrity} />

      <div className="grid gap-4 lg:grid-cols-[1.6fr_1fr]">
        <div className="min-w-0 space-y-4">
        <Card
          className="min-w-0"
          title="keccak256 over canonical JSON"
          subtitle="Sorted keys, no whitespace. Anchored on the left, recomputed from stored data on the right — when they differ, the difference is the evidence."
          right={integrity?.tamper_active ? <Badge tone="high">record altered</Badge> : null}
        >
          <HashPair
            label="Evidence"
            anchored={integrity?.anchored_evidence_hash ?? ""}
            recomputed={integrity?.recomputed_evidence_hash ?? ""}
            valid={integrity?.evidence_valid ?? null}
          />
          <HashPair
            label="Agent output"
            anchored={integrity?.anchored_output_hash ?? ""}
            recomputed={integrity?.recomputed_output_hash ?? ""}
            valid={integrity?.output_valid ?? null}
          />

          <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-line pt-4">
            {!anchored && (
              <Button
                variant="primary"
                disabled={!!busy}
                onClick={() =>
                  act("anchor", async () => {
                    // The anchor response carries block, gas and the on-chain id. It used to be
                    // discarded and the page re-fetched; keeping it makes those appear at once.
                    setProof(await api.anchor(decisionId));
                  })
                }
              >
                {busy === "anchor" ? "Anchoring…" : "Anchor proof on chain"}
              </Button>
            )}
            <Button disabled={!!busy} onClick={() => act("verify", refresh)}>
              {busy === "verify" ? "Verifying…" : "Re-verify"}
            </Button>
            <span className="mx-1 h-5 w-px bg-line" />
            <Button
              variant="danger"
              disabled={!!busy || !anchored}
              onClick={() =>
                act("tamper", async () => {
                  const r = await api.tamper(decisionId, "triage");
                  setLastChange({ field: r.field, before: r.before, after: r.after });
                })
              }
            >
              {busy === "tamper" ? "Editing…" : "Edit the stored triage label"}
            </Button>
            <Button
              disabled={!!busy}
              onClick={() =>
                act("restore", async () => {
                  await api.restore(decisionId);
                  setLastChange(null);
                })
              }
            >
              {busy === "restore" ? "Restoring…" : "Restore"}
            </Button>
          </div>
          <p className="mt-2 text-2xs leading-relaxed text-faint">
            The tamper button does what an insider with database access would do — it edits
            <span className="mono"> agent_runs.output_json</span> and nothing else.
          </p>
        </Card>

        {/* Directly under the digests, because "go and check it yourself" is the natural next
            question once someone has seen the two hashes agree. */}
        <ExplorerLinks proof={proof} />
        </div>

        <div className="min-w-0">
          <ChainFacts
            proof={proof}
            integrity={integrity}
            confirming={busy === "confirm"}
            onConfirm={() =>
              act("confirm", async () => {
                // Keep the explicit RPC response. The generic post-action refresh calls the
                // zero-RPC proof route and used to overwrite `chain_checked: true` immediately,
                // making the button appear to do nothing even after a successful contract read.
                setProof(await api.proof(decisionId, { check_chain: true }));
              }, false)
            }
          />
        </div>
      </div>

      <ThreeControls proof={proof} integrity={integrity} />

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="min-w-0">
          <OnChainVsOffChain proof={proof} />
        </div>
        <div className="min-w-0">
          <AgentRegistryPanel proof={proof} chain={chain} />
        </div>
      </div>
    </div>
  );
}
