# AgentSphere SecureOps

A permissioned workforce of AI agents that investigates security incidents, triages them against
real Microsoft SOC data, and anchors every decision as tamper-evident on-chain proof — with humans
holding the switch on anything dangerous.

**NTU InnovateX Hackathon 2026** — Track 2, Web3 Applications, AI Agents and Real-World Use Cases.

> All remediation in this system is **simulated**. Nothing here isolates a device, disables an
> account or takes any action against a real system.

---

## Status

Phase 0 build, days 1–5 of 7. See the master plan for the full schedule.

| Day | Scope | State |
|---|---|---|
| 1 (4 Aug) | Repo, dataset pipeline, incident summaries, SQLite | done |
| 2 (5 Aug) | Baseline classifier, frozen agent contracts, risk queue, policy gate | done |
| 3 (6 Aug) | Entity graph, Union-Find correlation, orchestrator, first four agents | done |
| 4 (7 Aug) | BM25 + FAISS + RRF retrieval, BFS/Dijkstra, Remediation and Verifier agents | done |
| 5 (8 Aug) | Solidity contracts, deployment, on-chain approval | done (local; testnet awaiting faucet funding) |
| — | FastAPI backend + React frontend, replacing Streamlit | done |
| 6–7 (9–10 Aug) | Tamper demo, metrics polish, freeze | not started |

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
| Agent chain, live (gpt-4o-mini) | 6/6 agents valid on first attempt, ~22 s end to end |
| Cache replay | byte-identical output hashes to the live run, zero network |
| On-chain anchoring | decision submitted in ~218k gas; `verify()` VALID; high-risk finalisation reverts |
| Tests | **276 Python + 29 Solidity** |

### Three honesty notes

**The agent chain does not beat the baseline on classification.** Measured on 40 validation
incidents against live gpt-4o-mini: agents macro F1 **0.4084** vs baseline **0.4669** — the agents
are *worse* by 0.06. The sample is small (9 TP, 4 FP), so it is not conclusive, but it is
certainly not evidence that the agent layer improves triage accuracy. What the agent layer
provides is evidence-grounded explanation, policy enforcement and an audit trail; the LightGBM
baseline remains the stronger classifier and the system reports both side by side rather than
quoting whichever is flattering.

**The deterministic backend's metrics measure plumbing, not reasoning.** On that backend the
agents score *identically* to the baseline (macro F1 0.7065, 0.0% disagreement) because
deterministic Triage defers to it by design. Only the `openai` backend produces a meaningful
agents-vs-baseline comparison.

**Two selection caveats.** The showcase set is filtered to a 3–60 evidence band, so agreement
rates on it are a biased sample. And `hour_of_day` ranks as the baseline's top feature, which is
more likely a temporal artefact of the dataset than a security signal — worth pruning before the
numbers are quoted anywhere.

## Quick start

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Linux/macOS: .venv/bin/python
cp .env.example .env
```

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

Set `LLM_BACKEND=openai` and `OPENAI_API_KEY` in `.env`. Responses are cached to
`artifacts/llm_cache/`, so a run can be replayed later with `LLM_BACKEND=cache` — no network, same
outputs.

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
| Agents | Structured-output prompts, strict Pydantic validation, temperature 0 |
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
- **Synthetic fixture** (`app/data/fixture.py`) — schema-faithful generated data used for offline
  development and the no-credentials demo path. Clearly labelled as synthetic wherever it appears;
  no metric reported as a headline number is computed on it.

## Limitations

Stated up front rather than defended under questioning:

- Ground-truth labels are analyst-derived and imperfect.
- No live SIEM or SOAR integration.
- All remediation is simulated.
- On-chain proofs land on a public testnet, not mainnet.
- Risk-score weights are hand-set and sanity-checked against the validation split. They are not
  learned, and are not described as learned.

## Prior work

AgentSphere SecureOps builds on an earlier conceptual framing by the team for permissioned AI agent
workforces with on-chain identity. All software in this repository — agent orchestration, dataset
pipeline, baseline model, retrieval layer, policy engine, smart contracts and interface — was
written new for this hackathon. Third-party open-source libraries and public datasets are used
under their respective licences.
