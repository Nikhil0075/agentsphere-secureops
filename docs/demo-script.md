# Demo script

Six scenes, mapped to §12.1 of the master plan. Roughly seven minutes at a steady pace, which
leaves room in most pitch slots for the questions in §12.3.

## Before you start

```bash
python scripts/start.py --check     # every row must read ok
python scripts/rehearse.py          # must be 17/17
```

Run both from a cold start. If either is red, fix that before rehearsing the narration.

Leave the backend selector on **replay**, the default. It reads validated `gpt-5.6-terra` /
`gpt-5.6-sol` responses from `artifacts/llm_cache/` with byte-identical hashes and **makes no
network call at all** — a miss is a visible error, never a silent live call. Every one of the six
demo cases is prewarmed and replay-verified to return in under a second, which matters because
live stages take 3–25 seconds each.

**deterministic** is the fallback if the cache is cold: no key, no network, sub-second, and every
number it produces is real rather than canned — but Triage defers to the baseline by design, so do
not quote its accuracy as the agents'. **live** is for a judge who asks to watch a real call; be
ready for the wait, and say plainly that a live run is not bit-reproducible.

If `start.py --check` flags the replay row, run `python scripts/prewarm_replay.py` (it makes paid
calls) and `python scripts/cache_admin.py --audit` to see what is actually in the cache.

## The demo arc

Six curated cases, walked in order with **Next demo**. Between them they cover all three labels,
four attack categories, the full risk range, baseline agreement and disagreement, and both a
tampered and an untampered proof path. `Run demo` on Home opens case 1.

| # | incident | truth | baseline | risk | the beat |
|---|---|---|---|---|---|
| 1 | INC-020335f5c65e | TruePositive | agrees, 0.86 | 0.70 | the opener, and the decision anchored, tampered and restored in Scene 5 |
| 2 | INC-0837694b8b09 | TruePositive | agrees, 0.96 | 0.56 | 21 alerts collapse to 10 clusters — alert fatigue, measured |
| 3 | INC-0874da0f54ed | TruePositive | **wrong**, calls it benign | 0.50 | the agents get this one wrong too — and the gate still refuses to auto-close it |
| 4 | INC-03c330695cea | BenignPositive | agrees, 0.94 | 0.45 | real activity, authorised — not every detection is an attack |
| 5 | INC-0abdb2a523a5 | FalsePositive | agrees, 0.95 | 0.37 | the queue noise this system exists to suppress |
| 6 | INC-1010bda7f63d | FalsePositive | agrees, 0.62 | 0.30 | the bottom of the risk range, in a fourth category |

These six are a *presentation* set, hand-picked for coverage. If asked: no reported number is
computed over them — accuracy runs on the 1,004-incident validation split, and correlation and
rehearsal numbers run on all 30 showcase cases.

---

## Scene 1 — Alert overload (45s)

**Show:** the Queue tab.

> Five thousand real incidents from Microsoft's GUIDE dataset. 591,340 pieces of evidence. This is
> not synthetic — these are real analyst-labelled security incidents, and the queue is ordered by a
> max-heap over a normalised risk score, so the top of the list is where an analyst should start.

Point at the risk column and the label column. Note that the ground-truth label is shown to *us*
and never to the agents.

Then switch to the **Demo arc (6)** tab, which is where the rest of the narration lives. The three
tabs are worth one sentence if a judge asks: all 5,000 tickets, the 30-case showcase pool, and the
six-case arc laid on top of it.

## Scene 2 — Agents collaborate (90s)

**Show:** case 1, then Workflow → Run workflow. (`Run demo` on Home opens it directly.)

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

## Scene 3b — A real provenance graph (optional, 45s)

Skip this if you are tight on time; it is a depth answer, not a story beat. Worth showing to a
judge who asks how the graph work generalises.

**Show:** open **Explore → Provenance Lab** (or use **Compare shipped graph** from Incident). The
first matching WitFoo incident is selected automatically. Use **Back to Incident** when finished.

Provenance is deliberately outside the primary Queue → Incident → Workflow → Proof → Metrics
sequence. It proves graph-layer portability, but WitFoo's threat labels do not contribute to the
GUIDE decision or its accuracy metrics, so placing it between Proof and Metrics would imply a
causal role it does not have.

> Everything so far ran on Microsoft GUIDE, which is tabular — we *build* the entity graph from
> evidence rows. This is WitFoo Precinct6, which ships one: 35,133 nodes, 634,190 labelled edges.

Point at the confidence stat.

> The traversal code is the same code — the blast radius and the Dijkstra attack path are
> unchanged. What differs is where the confidence comes from. On GUIDE those weights are hand-set
> and we say so. Here they come from the dataset, and this path is 100% grounded in them.

Point at the amber note at the top.

> And these labels are threat assessments, not the analyst triage verdicts GUIDE carries. They are
> excluded from every accuracy number we report. Different judgements should not be averaged
> together just because both are called labels.

## Scene 4 — Human authority (60s)

**Show:** Queue → **Next demo** to case 3, run the workflow, then the policy gate card.

Case 3 is the one worth spending time on, and the honest framing is stronger than the flattering
one. The ground truth is a true positive; the baseline calls it benign at 0.38; **the agents also
call it benign.** Say that out loud — a judge who finds it themselves after you have claimed the
agents caught it will not believe the rest of the demo.

> Everything upstream of this card got this incident wrong. What the system does not do is act on
> it. This is not an LLM — it is a dictionary lookup and a set of thresholds, and an agent cannot
> argue its way past it. Confidence sits below the auto-approval floor and the verifier escalated,
> so two policies failed independently and either one alone would have blocked it. The incident
> goes to a human, which is exactly what should happen to a case the models find genuinely
> ambiguous.

That is the argument for the deterministic gate in one screen: the value is not that the models
are always right, it is that being wrong does not become an action.

If time is short, cases 4–6 can be walked in about twenty seconds with **Next demo**, purely to
show the spread: a benign positive that is real-but-authorised, and two false positives at the
bottom of the risk range. It is the same six agents and the same gate reaching different answers.

## Scene 5 — Proof, then tamper (120s) ← **the moment**

**Show:** go back to **case 1**, then the **Proof** tab, then press **Anchor proof on chain**.

Case 1 is the one `scripts/rehearse.py` exercises for tamper/restore, so this is the exact
decision the rehearsal proved rather than a different one that merely resembles it.

This scene has its own tab now — it used to sit at the bottom of the Workflow scroll, which meant
the strongest beat in the pitch arrived after a scroll past everything else. The verdict is the
largest thing on the screen and the two digests sit side by side, so the room reads the evidence
rather than a badge.

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
> of successfully anchored decisions that still verify — recomputed locally, not a counter and
> with zero Sepolia calls. Live contract confirmation stays on the single-decision Proof screen.
> And the entity graph's
> worst hub at degree 1,025, which is why traversal is capped: an uncapped search from that node
> returns most of the graph and freezes the demo.

---

## If something breaks

| Symptom | Do this |
|---|---|
| Workflow is slow or errors | Switch the backend selector to **deterministic**. No network, sub-second. |
| `start.py --check` flags **demo replay** | `python scripts/prewarm_replay.py` (paid). `python scripts/cache_admin.py --audit` says what is actually in the cache. |
| `start.py --check` flags **demo arc** | `python scripts/prepare_data.py` — the arc columns are missing or a role went unresolved. |
| A stage says it degraded on replay | That entry failed validation and was evicted; re-run `prewarm_replay.py` to resample just that stage. |
| Proof panel says no chain reachable | Say so plainly: "the testnet is unreachable, so the panel degrades — the workflow, the gate and the digests are unaffected." That is the designed behaviour, not a failure. |
| Tamper shows VALID | You are on a decision that was never anchored. Press **Anchor proof on chain** first. |
| Proof tab says "no decision yet" | Run the workflow first — Proof reads the decision that run produced. The button on that screen takes you there. |
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
- **Is it deterministic? Would it say the same thing twice?** Be precise, because the honest
  answer is more interesting. The demo runs on validated replay: byte-identical cached responses,
  zero network calls, six cases in about a second, and a test that fails if any stage misses the
  cache. Live is *not* bit-reproducible and cannot be — these are reasoning models with no
  temperature, top_p or seed to pin. So we measured it rather than claiming it:
  `scripts/measure_variance.py` runs the same incidents repeatedly with the cache suppressed in
  both directions and reports how often the triage label and the gate outcome actually move.
- **What stops an agent inventing evidence?** Every citation is checked against the incident's own
  evidence bundle before the output is accepted, and the same goes for entity values, remediation
  actions, similar-incident ids and MITRE technique ids. It fires in practice: during preparation
  the live model emitted `[""]` and then `[":"]` into a triage evidence bundle, and both were
  rejected rather than reaching the decision. A rejected response is also evicted from the cache,
  so a bad generation cannot be replayed forever.
- **What are the limitations?** Offer them before being asked — the README lists them, including
  that the agents currently classify worse than the baseline, and that on demo case 3 the agents
  get the answer wrong and the gate is what stops it becoming an action.
