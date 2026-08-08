# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A permissioned workforce of six AI agents that triages security incidents from the Microsoft GUIDE
dataset and anchors each decision as tamper-evident proof on Ethereum Sepolia. Built for the NTU
InnovateX Hackathon 2026. **Phase 0 is feature frozen** — critical bugs and presentation blockers
only.

All remediation is **simulated**. Nothing isolates a device, disables an account, or touches a real
system.

## Commands

The venv is project-local. Paths below are Windows (`\.venv\Scripts\`); on Linux/macOS use
`.venv/bin/`.

```bash
python scripts/start.py --check      # preflight: names the fixing command for anything missing
python scripts/start.py --setup      # build all artifacts, then run API (8000) + UI (5173)
```

| Task | Command |
|---|---|
| Full test suite | `.venv/Scripts/python -m pytest tests/` |
| One file | `.venv/Scripts/python -m pytest tests/test_workflow.py` |
| One test | `.venv/Scripts/python -m pytest tests/test_workflow.py::test_agents_run_in_contract_order` |
| Contract tests | `cd contracts && npx hardhat test` |
| Frontend typecheck | `npm --prefix frontend run typecheck` |
| Frontend build | `npm --prefix frontend run build` |

Data pipeline, in order. Every one works offline with no API key:

```bash
python scripts/prepare_data.py --source fixture -n 200   # or --source guide
python scripts/init_db.py
python scripts/train_baseline.py
python scripts/build_index.py
python scripts/run_demo.py --backend deterministic
```

Verification harnesses that must stay green:

```bash
python scripts/rehearse.py     # 17/17 end-to-end cases; run 3x cold before demoing
python scripts/evaluate.py --split val --limit 200
python scripts/cache_admin.py --audit         # what is in the replay cache, and what is servable
python scripts/prewarm_replay.py              # warms + replay-verifies the six demo cases (paid)
python scripts/measure_variance.py --dry-run  # live run-to-run variance; --confirm to spend
```

Chain work: `cd contracts && npx hardhat node` (local), `npm run deploy:sepolia` (needs a funded
`DEPLOYER_PRIVATE_KEY` in `.env`; `scripts/gen_wallet.py` generates a burner).

WitFoo provenance (optional, ~442 MB): `python scripts/download_witfoo.py && python scripts/build_witfoo_graph.py`.

There is no linter configured. `pyproject.toml` holds only pytest config.

## Architecture

Data flows one way, and every stage is reachable from the CLI and the API through **the same
code** — there is no API-only path, so `scripts/run_demo.py` and the browser exercise identical
logic.

```
GUIDE csv → prepare_data → Parquet → { baseline model, hybrid index, entity graph }
                                            ↓
        six-agent chain → deterministic policy gate → SQLite → keccak256 digests → Sepolia
```

**`app/data/`** — GUIDE is evidence-level (one row = one piece of evidence; rows roll into alerts,
alerts into incidents). `schema.py` is the single column contract; everything downstream speaks its
canonical names, never raw GUIDE names. That indirection is what lets `fixture.py` (synthetic) and
`guide_loader.py` (real, 2.4 GB, chunked) be interchangeable via `DATA_SOURCE`.

**`app/agents/`** — six agents on contracts frozen on Day 2 (`schemas.py`). `base.Agent` gives every
agent retry, strict validation, a conservative fallback, and honest status reporting. Agents never
see ground truth.

**`app/orchestration/workflow.py`** — an explicit typed state machine, deliberately **not**
LangGraph: the chain is linear, and presenting a topological sort of a straight line as
orchestration collapses under one question. Nodes are written so a future fan-out could swap the
driver.

**`app/policies/engine.py`** — the deterministic gate. Dictionary lookups and thresholds, no LLM.
This is the honest answer to "is this just an LLM wrapper?".

**`app/graph/`** — GUIDE ships no graph, so `build.py` constructs one from evidence co-occurrence
*within an alert* (not within an incident — a 1,313-row incident would otherwise produce a
near-complete graph). `traverse.py` does depth-capped BFS and Dijkstra. `witfoo_graph.py` builds
the **same** `EntityGraph` from WitFoo's shipped provenance data, so traversal runs on both
unmodified.

**`app/blockchain/` + `contracts/`** — `AgentRegistry` (who may submit) and `DecisionProof`
(digests, approval, finalisation). Only hashes, identities and approval state go on chain; raw
evidence, prompts and rationales never leave SQLite.

**`app/api/` + `frontend/`** — FastAPI reusing the frozen agent schemas as response models, so
`/openapi.json` describes the real contracts. Vite proxies `/api` to 8000.

Frontend conventions worth knowing before editing a page:

- Charts are Recharts, wrapped by `components/charts.tsx`. **Never inline a hex** — colours come
  from the `@theme` custom properties via `useThemeTokens()`, which carries a fallback map because
  jsdom returns `""` and Recharts would silently render `fill=""`. Every series takes
  `isAnimationActive={!reducedMotion}`; the global CSS reduced-motion block does not reach
  JavaScript animation.
- **Every grid cell containing a chart needs `min-w-0`**, or CSS grid's automatic minimum sizing
  lets a `ResponsiveContainer` push the page wider than the viewport.
- `Metrics` and `Provenance` are `React.lazy` — they are the only Recharts consumers, and splitting
  them keeps the initial bundle at ~282 kB instead of ~713 kB, which matters when the venue network
  is unusable.

## Invariants — break these and something silently lies

These are load-bearing, non-obvious, and each has a test that will fail. Read the test before
changing the behaviour.

1. **Agent contracts are frozen.** `tests/test_schemas_frozen.py` compares against
   `artifacts/schemas/`. A change invalidates every prompt, validator and stored output hash. It
   can be deliberate; it cannot be silent.

2. **No label reaches a pre-decision agent.** Detection → Triage must never see any label string.
   Remediation and Verifier legitimately consume Triage's *prediction*. Retrieval must never return
   a similar incident's label — that would leak the answer and void every metric.

3. **The Verifier's structural checks run on every backend.** `VerifierAgent.reconcile()` applies
   them to model output too. Measured: left to itself the live model rejected 40/40 real incidents
   citing "evidence gaps". A verifier that rejects everything is as useless as one that accepts
   everything. The model may escalate freely but may only *reject* where a structural check failed.

4. **Integrity verification recomputes; it never reads a stored hash column.** `services/integrity.py`
   rebuilds digests from `agent_runs.output_json` and `evidence.payload_json`. An earlier version
   compared the stored column to the chain — both sides came from the same write, so editing an
   agent output verified clean. `test_the_check_never_reads_the_stored_hash_column` guards this.

5. **One serialiser for evidence payloads.** `db.session.canonical_evidence_payload` is used by
   both the writer and the verifier. Two serialisations differing by one space would make every
   proof read as tampered forever.

6. **WitFoo threat labels are not GUIDE triage verdicts.** benign/suspicious/malicious vs
   TruePositive/BenignPositive/FalsePositive. Mapping them corrupts every accuracy number.
   `test_witfoo_never_enters_the_guide_metrics_path` parses the WitFoo modules with `ast` and fails
   if a triage label appears as a code literal.

7. **Dijkstra uses `cost = −log(confidence)`, not `1 − confidence`.** The linear cost prefers paths
   with one very weak link. Confidence is clamped to `MIN_CONFIDENCE` first so the cost stays
   finite. The counterexample is an executable test.

8. **Traversal never expands *through* a hub.** Worst real hub: `process:6` at degree 1,025 (GUIDE),
   `ip:100.64.70.227` at 1,252 (WitFoo). An uncapped BFS returns most of the graph and freezes the
   demo.

9. **A degraded agent is recorded as `fallback`, never `ok`.** A silent fallback corrupts the
   metrics; a marked one is a measurable degradation.

10. **Replay is hermetic.** `ReplayClient` never constructs a live client unless
    `allow_live_fill=True`, and with filling off it drops even an explicitly injected one. A miss
    raises `CacheMiss`; it does not become a silent paid call. Only `scripts/prewarm_replay.py`
    and `scripts/measure_variance.py` opt in. This existed the other way round and it was the
    single worst demo hazard in the repo: `.env` has a real key, so any cache miss mid-demo became
    an 8–25 second live call that could return a label nobody rehearsed.
    `test_replay_is_hermetic_even_with_a_key_present` guards it.

11. **The replay cache is provenance-stamped, and untrustworthy entries are misses.** An entry
    without a matching `prompt_version` and `model` is not served. Neither is one with zero latency
    alongside real token counts — no network call completes in under a millisecond, so that is a
    test double's signature. Two such entries were found sitting in `artifacts/llm_cache/`.
    Writing to the production cache from pytest now raises. `test_the_production_cache_is_not_writable_from_tests`
    and `test_replay_rejects_a_cache_entry_without_a_prompt_version` guard it.

12. **Three things are called "demo" and they are not the same.** `split == "demo"` is a
    hash-band holdout (~10% of the corpus, used by evaluation). `is_showcase` is the 30-case pool
    (graph build, rehearsal, the 3–60 evidence-band disclosure). `demo_rank` 1..6 is the
    presentation arc, a strict subset of the pool, narration order only, and **never a metric
    denominator**. See `app/data/demo_arc.py`. Ranks are never compacted: if a role cannot be
    resolved its rank stays unused, so `demo_rank == 3` always means the same beat.

## Gotchas that have already bitten

- **The Windows console is cp1252.** Non-ASCII in script output (`→`, `—`, `…`) raises
  `UnicodeEncodeError` mid-run. Script stdout must be ASCII. Web UI text is fine.
- **Never derive a database id from content.** `proof_id` from a block number and `tamper_id` from
  a run id both collided on the retry path — the exact paths a demo exercises. Use `uuid4`.
- **The deterministic backend's metrics measure plumbing, not reasoning.** Deterministic Triage
  defers to the baseline by design, so agents score *identically* to it (macro F1 0.7065, 0.0%
  disagreement). Only `--backend openai` produces a meaningful comparison, and there the agents are
  **worse** than the baseline (0.4084 vs 0.4669 macro F1). Report that, don't bury it.
- **API tests stub the chain to unavailable** (`offline_chain` fixture). Once a real deployment
  exists, unstubbed tests hit a public Sepolia RPC on every request — 4s became 55s and failed
  whenever the endpoint blipped.
- **The tamper mutation must actually change the value.** Writing a fixed target no-ops when the
  field already holds it, and the panel shows VALID at the moment it should show TAMPERED.
- **An agent starved of the evidence it is asked to reason about does not fail loudly — it
  escalates.** The Verifier's prompt rendered `len(cited)` instead of the evidence ids, and carried
  no evidence content at all, so it was asked to certify citations it could not see. It said so on
  every incident and escalated: **97.5% escalation live against 5.0% deterministic**, on incidents
  whose structural checks all passed, which drove gate auto-approval to exactly 0. `reconcile()`
  then clamps the model's REJECT to ESCALATE, which converts a blanket-rejection pathology into a
  blanket-escalation one — the symptom reads as conservatism rather than as a bug. Triage had the
  milder form: ids listed, contents withheld, so it hedged and never cleared POL-004's 0.80
  confidence floor. `build_evidence_block`'s docstring had said all along that it exists "so an
  agent can cite it and the Verifier can check the citation later"; it was simply never wired in.
  `test_the_verifier_is_shown_the_evidence_ids_it_must_check` and its two siblings guard this.
- **Correlation used to manufacture the gaps that made the chain escalate.** `_missing` emitted one
  entry per *absent* entity type, all seven checked against every incident. Measured on the
  5,000-incident corpus that is a mean of **5.26 fabricated gaps each**: 53.2% of incidents carry
  one entity type or none, and exactly 5 carry all seven. GUIDE is evidence-level, so a row holds
  only the fields its source product emits — a mailbox alert has no file hash and never will.
  The damage compounded: `missing_information` is rendered into the Investigation, Triage,
  Remediation *and* Verifier prompts, the field caps at 15 so real gaps were crowded out, and the
  Verifier flags high confidence above `GAP_TOLERANCE = 3`. A normally-shaped incident therefore
  arrived at the gate already described to four agents as full of holes, and the resulting
  escalation read as caution rather than as a bug. Sparse is normal; empty is a gap. The real
  gaps that remain are: nothing to pivot on, a single uncorroborated entity type, no chronology,
  and no shared entity linking the alerts. Mean is now 0.53.
  `test_absent_entity_types_are_not_reported_as_gaps` guards it.
- **`integrity.onchain_valid` is not a contract verdict.** It is computed by comparing against the
  *locally recorded* proof row, and it reads `true` on a decision whose on-chain state is still
  `unanchored` — nothing was ever asked. `ProofInfo.chain_checked` is the flag that says whether an
  RPC actually happened, and the UI must gate any "the contract says…" wording on it. Rendering the
  local comparison as a contract confirmation claims independent verification the system does not
  have. `frontend/tests/proof.test.tsx` guards it.
- **`CREATE TABLE IF NOT EXISTS` will not add a column to an existing database.** New columns go in
  `schema.sql` *and* `db.session._ADDITIVE_COLUMNS`, which `init_db` applies with `ALTER TABLE`.
  Re-run `python scripts/init_db.py` once after pulling a schema change. It is additive only — a
  rename or a retype needs a rebuilt database.
- **Agent prompts are surfaced on the Workflow screen, and `label_free` is scoped to the *user*
  prompt.** Triage's role names all three labels because it is choosing between them; that static
  text is identical for every incident and cannot carry an answer, so scanning the system prompt
  would report a leak on a prompt that has none. Only detection/correlation/investigation are
  `pre_decision`, and for those `label_free` must be true.
- **The live triage revision makes a live run's `output_hash` differ from its replay's.**
  `_revise_rejected_live_triage` is gated on `backend == "live"` and appends three stages, so a
  live run that fires it has nine agent runs and a different hash than the six-stage replay. That
  is by design, not a replay bug; `WorkflowResult.revision_fired` reports it and
  `prewarm_replay.py` records it per incident.
- **A tool must never accept a parameter it does not honour.** `get_graph_context` used to take
  `max_hops` and `hub_degree`, clamp them, echo them back as `requested_*`, and return the
  identical precomputed slice either way — inviting the model to report having widened a search it
  never widened. It now takes nothing.
- **`max_retries=0` on the OpenAI client is load-bearing.** SDK-internal retries are invisible to
  `AgentRunRecord.attempts`, so a "45 second timeout" silently became 135 seconds while the record
  still claimed one attempt. Retrying belongs to `base.Agent.run`, where it is counted. Likewise
  `llm_timeout_seconds` was read into the client and never passed to anything until the explicit
  `AsyncOpenAI` client plus the wall-clock guard were wired in.
- **"Next demo" used to walk the visible page.** It iterated the paginated table rows, so at the
  default page size it could never reach later cases and a filter could drop cases out of the walk.
  The arc is now fetched into its own state with no dependency on filters, sorting or paging.
- **WitFoo's Hub configs are broken.** Its YAML declares three JSONL files as `parquet`, so
  `datasets.load_dataset` fails. Ingest is plain HTTP + JSONL. This is the dataset's bug, not ours.

## Reporting numbers

Every figure quoted about a dataset is read from that dataset's own metadata at runtime, never
hard-coded. Counts that don't reconcile get their parts shown rather than a bare smaller number —
see `scripts/build_witfoo_graph.py`, where 16,586 activity nodes + 16,503 incident-link-only +
2,044 isolated = the declared 35,133.

Selection bias gets disclosed wherever a number appears: the showcase set is filtered to a 3–60
evidence band, so agreement rates on it are not representative. The six-case presentation arc is a
further hand-picked subset and is **never** a denominator — evaluation runs on `--split val`,
correlation and rehearsal run on all 30 showcase cases.

Determinism claims get the same treatment. Replay and deterministic mode are reproducible and
tested as such. Live is not, and cannot be: the routed reasoning models expose no temperature,
top_p or seed. Say the measured variance (`scripts/measure_variance.py` →
`artifacts/metrics/variance.json`), not "the agents are deterministic".
