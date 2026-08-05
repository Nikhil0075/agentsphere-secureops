# Demo script

Six scenes, mapped to §12.1 of the master plan. Roughly seven minutes at a steady pace, which
leaves room in most pitch slots for the questions in §12.3.

## Before you start

```bash
python scripts/start.py --check     # every row must read ok
python scripts/rehearse.py          # must be 16/16
```

Run both from a cold start. If either is red, fix that before rehearsing the narration.

Set the backend selector to **deterministic** unless the venue network is known-good. It needs no
key, no network, and runs in under a second — and every number it produces is real, not canned.
Switching to `cache` replays actual gpt-4o-mini responses with byte-identical hashes, which is the
better choice if a judge asks to see real model output without waiting 22 seconds for it.

---

## Scene 1 — Alert overload (45s)

**Show:** the Queue tab.

> Five thousand real incidents from Microsoft's GUIDE dataset. 591,340 pieces of evidence. This is
> not synthetic — these are real analyst-labelled security incidents, and the queue is ordered by a
> max-heap over a normalised risk score, so the top of the list is where an analyst should start.

Point at the risk column and the label column. Note that the ground-truth label is shown to *us*
and never to the agents.

## Scene 2 — Agents collaborate (90s)

**Show:** click an incident, then Workflow → Run workflow.

> Six specialised agents, not one chatbot. Each has a bounded role and a frozen JSON contract, and
> each output is hashed as it is produced.

While it runs, point at the correlation strip:

> Union-Find just collapsed these alerts into clusters by shared account, device, IP or file hash.
> Path compression *and* union by rank — both, which is what the near-constant bound actually
> requires.

## Scene 3 — The result is inspectable (60s)

**Show:** the triage card and the agent timeline.

> Every claim cites specific evidence ids. The similar incidents came from BM25 and vector search
> fused with reciprocal rank fusion — and the retrieved incidents never carry their labels, because
> that would leak the answer into the prompt and make every metric here meaningless.

Point at the baseline stat:

> A LightGBM classifier runs alongside and its prediction is shown next to the agents'. Right now
> the baseline is the *better* classifier. We report that rather than hiding it — what the agent
> layer adds is explanation and control, not accuracy.

## Scene 4 — Human authority (60s)

**Show:** the policy gate card.

> This is not an LLM. It is a dictionary lookup and a set of thresholds, and an agent cannot argue
> its way past it. This action is medium-risk, so it requires a named human approver — two policies
> failed independently, and either one alone would have been enough.

## Scene 5 — Proof, then tamper (120s) ← **the moment**

**Show:** Anchor proof on chain, then the integrity card.

> That's a real transaction on Sepolia. The contract stores digests, an agent identity and approval
> state — never evidence, never prompts. Anchored and recomputed digests match.

Then press **Edit the stored triage label**.

> I just did what an insider with database access would do: changed the stored decision. No hash
> column updated, nothing on chain touched.

Let the panel land on **TAMPERED**.

> The recomputed digest no longer matches what was anchored, and the contract agrees. This is the
> thing a database cannot do — whoever operates the database also controls its audit log. Here the
> operator controls the record and controls *nothing* about the digest.

Press **Restore** so the next run is clean.

## Scene 6 — Measured, not claimed (60s)

**Show:** the Metrics tab.

> Baseline versus agents on the same incidents. Verifier rejection and escalation rates. The share
> of anchored decisions that still verify — recomputed live, not a counter. And the entity graph's
> worst hub at degree 1,025, which is why traversal is capped: an uncapped search from that node
> returns most of the graph and freezes the demo.

---

## If something breaks

| Symptom | Do this |
|---|---|
| Workflow is slow or errors | Switch the backend selector to **deterministic**. No network, sub-second. |
| Proof panel says no chain reachable | Say so plainly: "the testnet is unreachable, so the panel degrades — the workflow, the gate and the digests are unaffected." That is the designed behaviour, not a failure. |
| Tamper shows VALID | You are on a decision that was never anchored. Press **Anchor proof on chain** first. |
| Frontend blank | `python scripts/start.py --check`, then restart. |

Keep a terminal open on `python scripts/run_demo.py --incident <id> --anchor`. It produces the same
result without the browser, and it has walked through the whole flow before.

## The questions that actually get asked

Short answers; the long ones are in §12.3 of the master plan.

- **Why a blockchain and not an append-only database?** Three things a database cannot do: reject
  an unauthorised writer at the storage layer, block finalisation of a high-risk action without a
  human, and detect tampering by the party who operates the storage. All three are demonstrable
  above.
- **What if the LLM is wrong?** The Verifier's structural checks run in code on every backend, the
  gate is deterministic, and all remediation is simulated. Measured: on 40 live incidents the model
  wanted to reject 40 of them; the structural layer converted that to 39 escalations and 1
  rejection, because "I am uneasy" is not a rejection.
- **Is this just an LLM wrapper?** The non-LLM baseline, the policy engine, Union-Find, the capped
  BFS, Dijkstra on −log(confidence) and the contract-level authorisation are all outside the model.
- **How much was built during the hackathon?** All of it; the commit history covers the build
  window. Prior work is a conceptual framing, disclosed in the README.
- **What are the limitations?** Offer them before being asked — the README lists them, including
  that the agents currently classify worse than the baseline.
