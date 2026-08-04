# AgentSphere SecureOps

A permissioned workforce of AI agents that investigates security incidents, triages them against
real Microsoft SOC data, and anchors every decision as tamper-evident on-chain proof — with humans
holding the switch on anything dangerous.

**NTU InnovateX Hackathon 2026** — Track 2, Web3 Applications, AI Agents and Real-World Use Cases.

> All remediation in this system is **simulated**. Nothing here isolates a device, disables an
> account or takes any action against a real system.

---

## Status

Phase 0 build, days 1–3 of 7. See `docs/` and the master plan for the full schedule.

| Day | Scope | State |
|---|---|---|
| 1 (4 Aug) | Repo, dataset pipeline, incident summaries, SQLite | done |
| 2 (5 Aug) | Baseline classifier, frozen agent contracts, risk queue, policy gate, queue UI | done |
| 3 (6 Aug) | Entity graph, Union-Find correlation, orchestrator, first four agents | done |
| 4 (7 Aug) | BM25 + FAISS + RRF retrieval, BFS/Dijkstra, Remediation and Verifier agents | not started |
| 5 (8 Aug) | Solidity contracts, testnet deployment, on-chain approval | not started |
| 6–7 (9–10 Aug) | Proof verification UI, metrics dashboard, freeze | not started |

## Measured results so far

Real numbers on real Microsoft GUIDE data, not projections. Reproduce them with the commands
below.

| Measurement | Value |
|---|---|
| Working set | 5,000 incidents / 591,340 evidence rows from `GUIDE_Train.csv` |
| Baseline (LightGBM 4.7.0) | accuracy **0.7072**, macro F1 **0.6774**, TP recall **0.6092** on 1,004 held-out incidents |
| Entity graph | 96,351 nodes, 26,194 edges; worst hub `process:6` at degree 1,025 |
| Alert correlation | collapses on 18/30 showcase incidents; largest observed 1,313 alerts → 764 clusters (-42%) |
| Agent chain, offline | 30/30 showcase incidents complete, 0 degraded runs, <1 ms/agent |
| Agent chain, live (gpt-4o-mini) | 4/4 agents valid on first attempt, ~22 s end to end |
| Cache replay | byte-identical output hashes to the live run, zero network |
| Tests | 135 passing |

Two honesty notes. The 87% agreement the demo runner reports across showcase incidents is **not**
a headline metric — the showcase set is deliberately filtered to a 3–60 evidence band, which is a
biased sample. And `hour_of_day` ranks as the baseline's top feature, which is more likely a
temporal artefact of the dataset than a security signal; it is worth pruning before the numbers
are quoted anywhere.

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
.venv/Scripts/python scripts/run_demo.py --backend deterministic
.venv/Scripts/python -m streamlit run app/ui/main.py
```

Every one of those commands works offline. That is deliberate: the demo cannot depend on venue
wifi or a live API.

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
| Interface | Streamlit |
| Orchestration | Explicit typed state machine over a shared `WorkflowState` |
| Dataset | Parquet + pandas, deterministic hash-based splits |
| Baseline | LightGBM (falls back to sklearn `HistGradientBoosting`) |
| Agents | Structured-output prompts, strict Pydantic validation, temperature 0 |
| Storage | SQLite |
| Proof | keccak256 over canonicalised JSON; Solidity on a public EVM testnet (Day 5) |

## Layout

```
app/
  agents/         prompts, frozen output schemas, LLM client, the six agents
  orchestration/  workflow state machine
  graph/          entity graph, Union-Find, alert correlation
  policies/       risk scoring, priority queue, action catalogue, approval rules
  retrieval/      similar-incident lookup (hybrid BM25 + vector on Day 4)
  blockchain/     canonical JSON + keccak256; contract client on Day 5
  data/           schema contract, GUIDE loader, fixture generator, summaries
  db/             SQLite schema and access
  ui/             Streamlit application
contracts/        Solidity, tests, deployment (Day 5)
scripts/          prepare_data, profile_data, init_db, train_baseline, run_demo
artifacts/        models, metrics, frozen schemas, graph stats, LLM cache
tests/            data, schema-freeze, policy, graph, workflow, hashing
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
