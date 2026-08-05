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
python scripts/rehearse.py     # 16/16 end-to-end cases; run 3x cold before demoing
python scripts/evaluate.py --split val --limit 200
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
- **WitFoo's Hub configs are broken.** Its YAML declares three JSONL files as `parquet`, so
  `datasets.load_dataset` fails. Ingest is plain HTTP + JSONL. This is the dataset's bug, not ours.

## Reporting numbers

Every figure quoted about a dataset is read from that dataset's own metadata at runtime, never
hard-coded. Counts that don't reconcile get their parts shown rather than a bare smaller number —
see `scripts/build_witfoo_graph.py`, where 16,586 activity nodes + 16,503 incident-link-only +
2,044 isolated = the declared 35,133.

Selection bias gets disclosed wherever a number appears: the showcase set is filtered to a 3–60
evidence band, so agreement rates on it are not representative.
