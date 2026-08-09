# AgentSphere SecureOps

A permissioned workforce of AI agents that investigates security incidents, triages them against
real Microsoft SOC data, and anchors every decision as tamper-evident on-chain proof — with humans
holding the switch on anything dangerous.

**NTU InnovateX Hackathon 2026** — Track 2, Web3 Applications, AI Agents and Real-World Use Cases.

> All remediation in this system is **simulated**. Nothing here isolates a device, disables an
> account or takes any action against a real system.

---

## Status

**Phase 0 complete — feature frozen.** From here: critical bugs and presentation blockers only.

| Day | Scope | State |
|---|---|---|
| 1 (4 Aug) | Repo, dataset pipeline, incident summaries, SQLite | done |
| 2 (5 Aug) | Baseline classifier, frozen agent contracts, risk queue, policy gate | done |
| 3 (6 Aug) | Entity graph, Union-Find correlation, orchestrator, first four agents | done |
| 4 (7 Aug) | BM25 + FAISS + RRF retrieval, BFS/Dijkstra, Remediation and Verifier agents | done |
| 5 (8 Aug) | Solidity contracts, **deployed to Sepolia**, on-chain approval | done |
| — | FastAPI backend + React frontend, replacing Streamlit | done |
| 6 (9 Aug) | Real digest recomputation, tamper demo, proof metrics, one-command start | done |
| 7 (10 Aug) | Rehearsal sweep, diagrams, README | done |

Architecture and flow diagrams: **[docs/architecture.md](docs/architecture.md)**.

## Deployed contracts (Sepolia, chainId 11155111)

| Contract | Address |
|---|---|
| `AgentRegistry` | [`0x62CE1b8765b678947A39aA90c15D33C3328476cc`](https://sepolia.etherscan.io/address/0x62CE1b8765b678947A39aA90c15D33C3328476cc) |
| `DecisionProof` | [`0xB849e1c8ba0147Eb8cC0b7E44caA6F013B150578`](https://sepolia.etherscan.io/address/0xB849e1c8ba0147Eb8cC0b7E44caA6F013B150578) |

Six agent identities are registered on-chain, each with its role and an active flag. The three
claims a database cannot make, all verified against this deployment:

| Claim | Evidence |
|---|---|
| A high-risk action cannot finalise without a human | [decision #2](https://sepolia.etherscan.io/tx/0xae72f69c054647236b6a4faf6d792f9f354bf6f8ae501430ba9e6a224f847a16) submitted, then `finalizeDecision` **reverted with `ApprovalRequired`** |
| Approval unblocks it, and the approver is a signature | [decision #3](https://sepolia.etherscan.io/tx/0x796ecbd17358f4eb39dfc54cab1df755e39eb72d4479cc63382a8804b9b33b3d) submitted → approved → finalised, approver recorded as `msg.sender` |
| An unauthorised agent is rejected by the contract | an unregistered address calling `submitDecision` reverts with `UnauthorisedAgent` |
| Tampering is detectable | `verify()` returns `true` for the anchored digests and `false` for an edited output |

Gas: ~201k–218k per `submitDecision`. The deployer is a throwaway key holding only test gas.

## Measured results

Real numbers on real Microsoft GUIDE data, not projections. Reproduce them with the commands
below.

| Measurement | Value |
|---|---|
| Working set | 5,000 incidents / 591,340 evidence rows from `GUIDE_Train.csv` |
| Baseline (LightGBM 4.7.0) | accuracy **0.7072**, macro F1 **0.6774**, TP recall **0.6092** on 1,004 held-out incidents |
| Entity graph | 96,351 nodes, 26,194 edges; worst hub `process:6` at degree 1,025 |
| Alert correlation | 870 alerts → 276 clusters (−68%) on one incident; collapses on 18/30 showcase cases |
| Retrieval index | 5,000 documents, 384-dim, builds in 14.6 s; no API call at query time |
| Agent chain, offline | six agents, 0 degraded runs, sub-millisecond per agent |
| Agent chain, live (gpt-5.6-terra/sol) | 6/6 agents valid, 3–25 s per stage, 45–105 s end to end |
| Replay | all six demo cases at a full cache hit, **zero network calls**, 145–320 ms each |
| Live variance, measured | **decision stability 0.50** — 1 of 2 incidents held its label and gate outcome across 3 runs; 3 distinct output hashes per incident either way |
| On-chain anchoring | decision submitted in ~218k gas; `verify()` VALID; high-risk finalisation reverts |
| Tamper detection | edit a stored output → recomputed digest diverges → Sepolia `verify()` returns false |
| Rehearsal sweep | **17/17** cases pass (`scripts/rehearse.py`), 10/10 incidents triaged correctly |
| WitFoo provenance | 634,190 edges parsed — **reconciles exactly** with the dataset's metadata; 33.8% carry dataset confidence |
| Tests | **420 Python + 29 Solidity** |

### Four honesty notes

**The agent chain does not beat the baseline on classification.** Measured on 40 validation
incidents against a live model: agents macro F1 **0.4084** vs baseline **0.4669** — the agents
are *worse* by 0.06. The sample is small (9 TP, 4 FP), so it is not conclusive, but it is
certainly not evidence that the agent layer improves triage accuracy. What the agent layer
provides is evidence-grounded explanation, policy enforcement and an audit trail; the LightGBM
baseline remains the stronger classifier and the system reports both side by side rather than
quoting whichever is flattering.

**A live run is not repeatable, and we measured how much.** Three live runs each of two demo
incidents, cache suppressed in both directions (`scripts/measure_variance.py`): one incident held
its label all three times; the other returned **TruePositive, FalsePositive and BenignPositive on
three consecutive runs of identical input**, at confidences of 0.36–0.38. Every run produced a
distinct `output_hash`. That is the real behaviour of a reasoning model with no seed to pin, and
the reason the demo runs on validated replay rather than live.

Two things did hold, and they are the point. Union-Find correlation returned the same cluster count
every time — that layer is ours and it is deterministic. And the policy gate demanded a human on
**every** run of both incidents, including all three contradictory ones. That measurement also
exposed an over-broad verifier prompt: it treated ordinary sparsity as a contradiction and became
an all-escalate switch. Prompt version `2026-08-09` replaces that behaviour with four named semantic
checks, retains seven structural checks in code, and adds a bounded low-risk dual-agreement path.
The corrected live profile must pass a fresh same-set evaluation before promotion; the old numbers
are evidence about the old prompt, not a claim about the new one.

**The deterministic backend's metrics measure plumbing, not reasoning.** On that backend the
agents score *identically* to the baseline (macro F1 0.7065, 0.0% disagreement) because
deterministic Triage defers to it by design. Only the `openai` backend produces a meaningful
agents-vs-baseline comparison.

**Three selection caveats.** The showcase set is filtered to a 3–60 evidence band, so agreement
rates on it are a biased sample. The six-case *presentation arc* is a further hand-picked subset
of that set, chosen for narrative coverage — three labels, four categories, both baseline
agreement and disagreement, risk 0.70 down to 0.30 — and **no number quoted anywhere is computed
over it**: evaluation runs on `--split val`, and correlation and rehearsal numbers run on all 30
showcase cases. And `hour_of_day` ranks as the baseline's top feature, which is more likely a
temporal artefact of the dataset than a security signal — worth pruning before the numbers are
quoted anywhere.

## Quick start

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Linux/macOS: .venv/bin/python
cp .env.example .env
```

One command brings everything up, building any missing artifact first:

```bash
python scripts/start.py --setup
```

It runs a preflight, names the command that fixes anything missing, then starts the API on 8000
and the UI on 5173 and stops both together. `--check` runs the preflight and starts nothing.
Deliberately not docker-compose: the demo runs from a laptop on venue wifi, where a container
build is one more thing that can fail ten minutes before presenting.

Then, with no dataset download and no API key:

```bash
.venv/Scripts/python scripts/prepare_data.py --source fixture -n 200 --verify-determinism
.venv/Scripts/python scripts/profile_data.py
.venv/Scripts/python scripts/init_db.py
.venv/Scripts/python scripts/train_baseline.py
.venv/Scripts/python scripts/build_index.py
.venv/Scripts/python scripts/run_demo.py --backend deterministic
```

Every one of those commands works offline. That is deliberate: the demo cannot depend on venue
wifi or a live API.

### Running the interface

Two processes — a FastAPI backend and the Vite dev server:

```bash
.venv/Scripts/python -m uvicorn app.api.main:app --port 8000
```

```bash
npm --prefix frontend install && npm --prefix frontend run dev
```

The UI is then at `http://localhost:5173`; Vite proxies `/api` to port 8000, so there is no CORS
setup and no base URL to get wrong at demo time. Interactive API docs are at
`http://localhost:8000/docs`.

### The trust layer

```bash
cd contracts && npm install && npx hardhat test
```

To run against a local chain, in three terminals:

```bash
cd contracts && npx hardhat node
```

```bash
cd contracts && npx hardhat run scripts/deploy.ts --network localhost
```

```bash
.venv/Scripts/python scripts/run_demo.py --anchor
```

That last command submits the decision, then attempts to finalise it — and on a medium- or
high-risk action the *contract* refuses, which is the control being demonstrated.

For a public testnet, generate a throwaway deployer and fund it from a faucet:

```bash
.venv/Scripts/python scripts/gen_wallet.py
```

Then `cd contracts && npm run deploy:sepolia`. The key it writes to `.env` holds nothing but test
gas; never reuse it for anything real.

### Using the real dataset

```bash
.venv/Scripts/python scripts/download_data.py          # Microsoft GUIDE via kagglehub, several GB
.venv/Scripts/python scripts/prepare_data.py --source guide -n 5000
```

`scripts/download_data.py` records the download location, so `--source guide` needs no further
configuration. Kaggle credentials, if prompted for, go in `~/.kaggle/kaggle.json` or
`KAGGLE_USERNAME`/`KAGGLE_KEY`.

### Using a live LLM

Live execution uses the OpenAI Agents SDK and its Responses API. Set `LLM_BACKEND=live` and
`OPENAI_API_KEY` in `.env`; supporting agents route to `gpt-5.6-terra`, while Triage and Verifier
route to `gpt-5.6-sol`. To prepare the presentation-safe default, inspect the paid request
envelope first, then choose an explicit hard stage budget:

```bash
.venv/Scripts/python scripts/prewarm_replay.py --dry-run
.venv/Scripts/python scripts/prewarm_replay.py --max-live-stages 36
```

The command refuses to construct a live client without `--max-live-stages`. Cache hits consume no
budget; agent retries do. A small value such as `6` supports incremental warming without allowing
an accidental full sweep.

Then set `LLM_BACKEND=replay`. Validated responses are read from `artifacts/llm_cache/` with **no
outbound call under any circumstances** — replay is hermetic, and a miss degrades visibly to the
deterministic stage rather than becoming a silent live call. The policy gate blocks autonomous
finalisation whenever any stage degraded. Live fill is opt-in and belongs to
`prewarm_replay.py` alone. Compatibility aliases `openai` and `cache` remain accepted.

Agents SDK trace export is disabled by default so local or restricted networks do not leave a
background exporter retrying after successful API responses. Set `AGENT_TRACING_ENABLED=true` to
opt in. Trace payload values remain redacted unless `AGENT_TRACE_INCLUDE_SENSITIVE=true` is also
set explicitly.

Inspect the replay cache with `python scripts/cache_admin.py --audit`. It reports what is servable
under the active profile, and flags entries that are dead (written before prompt versioning, so
their keys can never be hit) or suspect (zero latency alongside real token counts — the fingerprint
of a test double, not of a live response). Pruning moves files to `artifacts/llm_cache/.pruned/`
rather than deleting them.

### Determinism

Worth being precise about, because "AI agents" and "reproducible" are not usually said together.

- **Replay is reproducible.** Byte-identical cached responses, zero network calls, and each of the
  six demo cases replays in under a second at a full cache hit. `tests/test_determinism.py`
  enforces that, including against the manifest's recorded `output_hash`.
- **Deterministic mode is reproducible.** Pure Python rules over real evidence, no key, no network.
- **Live is *not* bit-reproducible, and cannot be made so.** The routed models are reasoning models
  that expose no `temperature`, `top_p` or seed to pin — `LLM_TEMPERATURE` and `LLM_TOP_P` exist
  and are sent when set, but the active models reject them. Separately, a schema or grounding
  retry re-sends an identical prompt, which is a resample; such runs are reported as
  `resampled_agents` rather than passed off as clean first-attempt successes.

So the honest claim is not "the model always says the same thing" but "the presentation path never
asks it twice, and we measured what happens when you do":

```bash
python scripts/measure_variance.py --dry-run
```

It runs the same incidents N times live with the cache suppressed in both directions — reads
always miss, so no run replays another, and writes never land, so a sweep can never become the
source of what the demo replays. It reports per-field divergence and, above all,
**decision stability**: the fraction of incidents whose triage label *and* gate outcome held
across every run. Results land in `artifacts/metrics/variance.json`.

## Architecture

```
evidence rows ─┬─> incident rollup ──> baseline classifier ──┐
               └─> entity graph ──> Union-Find correlation ──┤
                                                             v
   Detection ─> Correlation ─> Investigation ─> Triage ─> Remediation ─> Verifier
                                                             │
                                          policy gate ───────┤
                                    (low risk: auto | high risk: human approval)
                                                             v
                          keccak256 over canonical JSON ─> on-chain proof (Day 5)
```

Sensitive evidence never leaves the application database. Only hashes, agent identities, approval
records and decision proofs are anchored on-chain — which is what makes the audit trail
tamper-evident without exposing the data.

| Layer | Implementation |
|---|---|
| Interface | React 19 + TypeScript + Tailwind (Vite) |
| API | FastAPI, reusing the frozen agent schemas as its response models |
| Orchestration | Explicit typed state machine over a shared `WorkflowState` |
| Dataset | Parquet + pandas, deterministic hash-based splits |
| Baseline | LightGBM (falls back to sklearn `HistGradientBoosting`) |
| Retrieval | BM25 (`rank_bm25`) + FAISS `IndexFlatIP`, fused by RRF (k=60), then a metadata re-rank |
| Graph | Adjacency dicts; Union-Find, depth-capped BFS, Dijkstra over −log(confidence) |
| Agents | Structured-output prompts, strict Pydantic validation, hermetic replay for reproducibility |
| Policy | Deterministic gate over a YAML catalogue — not an LLM, and it has the final word |
| Storage | SQLite |
| Proof | keccak256 over canonicalised JSON; `AgentRegistry` + `DecisionProof` on an EVM chain |

The API reuses the frozen agent contracts as its response models rather than declaring parallel
DTOs, so `/openapi.json` describes the real agent outputs and the frontend's types cannot drift
from what the agents are validated against.

## Layout

```
app/
  agents/         prompts, frozen output schemas, LLM client, the six agents
  api/            FastAPI routes, response models, process-wide state
  orchestration/  workflow state machine
  graph/          entity graph, Union-Find, BFS/Dijkstra traversal, edge confidence
  policies/       risk scoring, priority queue, action catalogue, approval rules
  retrieval/      BM25, vectors + FAISS, RRF fusion and metadata re-rank
  blockchain/     canonical JSON + keccak256, web3 contract client
  services/       baseline scoring, decision and approval persistence
  data/           schema contract, GUIDE loader, fixture generator, summaries
  db/             SQLite schema and access
contracts/        AgentRegistry.sol, DecisionProof.sol, Hardhat tests, deploy script
frontend/         React + TypeScript + Tailwind (Vite)
scripts/          prepare_data, build_index, train_baseline, evaluate, run_demo, gen_wallet
artifacts/        models, metrics, frozen schemas, graph stats, retrieval index, LLM cache
tests/            data, schema-freeze, policy, graph, traversal, retrieval, workflow,
                  agents, hashing, blockchain client, API
```

## Datasets and attribution

- **Microsoft GUIDE** (Kaggle, `Microsoft/microsoft-security-incident-prediction`) — the primary
  benchmark. Released alongside Microsoft's Copilot Guided Response research
  ([arXiv:2407.09017](https://arxiv.org/abs/2407.09017)). Carries analyst-derived ground-truth
  triage labels across exactly the three classes this system predicts. Record counts are quoted
  from the dataset card at time of submission, not from press coverage.
- **WitFoo Precinct6** (Hugging Face, `witfoo/precinct6-cybersecurity`, **Apache-2.0**) — a
  provenance graph the dataset *ships*, used for graph visualisation, event correlation and the
  scale narrative. Every figure below is read from the dataset's own metadata files at runtime
  (`app/data/witfoo.py::load_metadata`), never hard-coded:

  | | Value | Source file |
  |---|---|---|
  | Provenance graph | 35,133 nodes / 634,190 edges | `graph/metadata.json` |
  | Edge threat labels | benign 390,948 · suspicious 44,517 · malicious 198,725 | `graph/metadata.json` |
  | Signals | 2,100,363 rows, 33 columns | `signals/metadata.json` |

  Earlier planning cited 100M / 114M / 84M records from press coverage and vendor material. **None
  of those match this repository**, and none are used here.

- **Synthetic fixture** (`app/data/fixture.py`) — schema-faithful generated data used for offline
  development and the no-credentials demo path. Clearly labelled as synthetic wherever it appears;
  no metric reported as a headline number is computed on it.

### A bug in the WitFoo dataset you will hit immediately

The dataset's own YAML declares `graph/nodes.jsonl`, `graph/edges.jsonl` and
`graph/incidents.jsonl` as `parquet`. They are **JSONL**. `datasets.load_dataset` and the
Hugging Face datasets-server both fail on all three with *"Parquet magic bytes not found in
footer"*; only the `signals` config loads. The files themselves are fine, so
`scripts/download_witfoo.py` fetches them over plain HTTP and parses them as JSONL. This is not a
workaround for anything on our side — it is a metadata error in the published dataset.

### Licences

| Component | Licence |
|---|---|
| This repository | MIT |
| Microsoft GUIDE | per the Kaggle dataset page; used for research and evaluation, redistributed nowhere — `scripts/download_data.py` fetches it to a local cache |
| `rank_bm25`, `faiss-cpu`, `scikit-learn`, `LightGBM`, `pandas`, `FastAPI`, `pydantic` | Apache-2.0, MIT or BSD-3-Clause as published |
| `web3.py`, `eth-hash`, `eth-account` | MIT |
| Hardhat, ethers v6 | MIT |
| React, Vite, Tailwind | MIT |
| MITRE ATT&CK technique ids and names | © The MITRE Corporation, used per the ATT&CK terms of use |

No dataset content is committed to this repository. `data/` holds a README and nothing else.

## Limitations

Stated up front rather than defended under questioning:

- **The agent chain does not improve classification accuracy** over the LightGBM baseline on the
  sample measured — it is worse by 0.06 macro F1. Its contribution is explanation, policy
  enforcement and auditability.
- **WitFoo labels are not GUIDE labels and are excluded from every accuracy metric.** GUIDE's
  TruePositive/BenignPositive/FalsePositive are analyst *triage verdicts*; WitFoo's
  benign/suspicious/malicious are *threat assessments*, and its `disposition` reads `Unprocessed`
  on most edges. Mapping one onto the other would be a category error, so nothing does —
  `tests/test_witfoo.py::test_witfoo_never_enters_the_guide_metrics_path` parses the WitFoo
  modules and fails if a triage label ever appears as a code literal in them.
- Only **33.8%** of WitFoo edges carry a dataset confidence score; the rest fall back to a
  hand-set prior, and the API reports the split per attack path rather than implying the whole
  chain is grounded.
- Ground-truth labels are analyst-derived and imperfect.
- GUIDE's median incident carries **one** evidence row, which limits how much correlation and
  graph traversal can demonstrate on a typical case. The showcase set is filtered to incidents
  with enough evidence to be worth showing, and that filtering is disclosed wherever its numbers
  appear. The six-case demo arc laid on top of it is presentation-only and is never a denominator.
- Live agent runs are not bit-reproducible: the routed reasoning models expose no sampling seed.
  The demo therefore runs on validated replay, and the live variance is measured
  (`scripts/measure_variance.py`) rather than assumed away.
- No live SIEM or SOAR integration.
- All remediation is simulated.
- On-chain proofs land on a public testnet, not mainnet.
- Risk-score weights, verifier thresholds and edge-confidence weights are hand-set and
  sanity-checked. They are not learned, and are not described as learned.
- The evidence digest covers the evidence rows the Correlation agent bundled. Evidence outside
  that bundle is not pinned by the proof.
- No Merkle tree. §8.2 of the plan is explicit that shipping none beats shipping a broken one; a
  plain bundle hash is sufficient at this scale.
- Contract source is not Etherscan-verified (needs a free API key); addresses and ABIs are in this
  README and in `artifacts/chain/`.

## Prior work

AgentSphere SecureOps builds on an earlier conceptual framing by the team for permissioned AI agent
workforces with on-chain identity. All software in this repository — agent orchestration, dataset
pipeline, baseline model, retrieval layer, policy engine, smart contracts and interface — was
written new for this hackathon. Third-party open-source libraries and public datasets are used
under their respective licences.
