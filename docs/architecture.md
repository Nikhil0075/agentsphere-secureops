# AgentSphere SecureOps — architecture

These diagrams use Mermaid so they render on GitHub and remain editable. The central boundary is
simple: evidence, prompts, and rationales stay off chain; only digests, identities, and approval
state cross into the public proof layer.

## 1. System architecture

```mermaid
flowchart TB
    subgraph dataLayer["Data layer"]
        guide[("Microsoft GUIDE<br/>5,000 incidents<br/>591,340 evidence rows")]
        prep["prepare_data.py<br/>sentinel masking and deterministic splits"]
        parquet[("Parquet<br/>incidents and evidence")]
        guide --> prep --> parquet
    end

    subgraph analysisLayer["Deterministic analysis"]
        baseline["LightGBM baseline<br/>independent comparison point"]
        retrieval["Hybrid retrieval<br/>BM25 + vectors + RRF k=60"]
        entityGraph["Entity graph<br/>Union-Find, capped BFS, Dijkstra"]
        parquet --> baseline
        parquet --> retrieval
        parquet --> entityGraph
    end

    subgraph agentLayer["Bounded agent workflow"]
        mode{"Execution mode"}
        replay["Validated replay<br/>default demo path"]
        live["OpenAI Agents SDK<br/>typed Agent + Runner"]
        offline["Deterministic fallback"]
        pipeline["Detection → Correlation → Investigation<br/>→ Triage → Remediation → Verifier"]
        mode --> replay --> pipeline
        mode --> live --> pipeline
        mode --> offline --> pipeline
    end

    subgraph controlLayer["Deterministic controls"]
        guardrails["Schema and grounding guardrails<br/>bounded retry, then marked fallback"]
        gate["Policy gate<br/>POL-001..006 — never an LLM"]
        human["Human approval<br/>for unsafe or uncertain outcomes"]
        guardrails --> gate --> human
    end

    subgraph appLayer["Application"]
        api["FastAPI"]
        ui["React workspace<br/>Queue → Incident → Workflow → Proof → Metrics"]
        sqlite[("SQLite<br/>evidence, runs, decisions, approvals, proofs")]
        api <--> ui
        api <--> sqlite
    end

    subgraph chainLayer["Public proof layer — Sepolia"]
        registry["AgentRegistry<br/>authorised submitters"]
        proof["DecisionProof<br/>digests, approval, finalisation"]
        registry --- proof
    end

    baseline --> pipeline
    retrieval --> pipeline
    entityGraph --> pipeline
    pipeline --> guardrails
    pipeline --> sqlite
    gate --> sqlite
    sqlite -.->|keccak256 digests only<br/>never evidence or prompts| proof
    human --> proof
    proof --> api

    classDef chainStyle fill:#1a2332,stroke:#4a9eff,color:#e6edf3
    classDef controlStyle fill:#2a1f1a,stroke:#ff9e4a,color:#e6edf3
    class registry,proof chainStyle
    class guardrails,gate,human controlStyle
```

The six stages are deliberately orchestrated in a fixed order. The SDK does not receive an
unrestricted controller role, raw dataset labels, or write tools. Retrieval and graph tools are
read-only and bounded, and every model output must satisfy its Pydantic contract.

## 2. End-to-end decision flow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    participant API as FastAPI workflow
    participant Context as Deterministic context
    participant SDK as Agents SDK / replay
    participant Judge as Triage + Verifier judges
    participant Gate as Policy gate
    participant Chain as DecisionProof

    Analyst->>API: Run selected incident
    API->>Context: Build evidence bundle and baseline prediction
    Context->>Context: Union-Find correlation
    Context->>Context: Hybrid retrieval and bounded graph traversal
    Context-->>API: Grounded, label-free context

    API->>SDK: Detection
    SDK-->>API: Typed detection output
    API->>SDK: Correlation
    SDK-->>API: Typed correlation output
    API->>SDK: Investigation
    SDK-->>API: Typed investigation output
    API->>Judge: Triage
    Judge-->>API: Label, confidence, citations
    API->>SDK: Remediation
    SDK-->>API: Simulated action and rollback
    API->>Judge: Independent verification
    Judge-->>API: SEM-001..004 verdict

    alt Schema or grounding failure
        API->>SDK: One bounded retry
        alt Retry still invalid or live unavailable
            API->>API: Deterministic fallback and mark degraded stage
        end
    end

    API->>Gate: Outputs, baseline, verifier, degraded stages
    alt Safe low-risk outcome
        Gate-->>API: Auto-approved
    else Approval required
        Gate-->>Analyst: Name the failed policy checks
        Analyst->>API: Approve or reject with analyst identity
    end

    API->>Chain: submitDecision(incidentId, evidenceHash, outputHash, label, risk)
    alt Fingerprint already exists
        Chain-->>API: Recover existing decision id
    else New fingerprint
        Chain-->>API: Transaction receipt and decision id
    end

    alt Low risk with no required approval
        API->>Chain: finalizeDecision
    else Human approval already exists or arrives later
        API->>Chain: approveDecision
        API->>Chain: finalizeDecision
    else Medium or high risk without approval
        Chain-->>API: ApprovalRequired, state remains proposed
    end

    Chain-->>API: Proposed, rejected, or finalized state
    API-->>Analyst: Persist state for zero-RPC reload
```

Replay is the default demonstration mode. A validated cache hit makes no OpenAI request; a cache
miss can run live only when explicitly configured. Every fallback is visible in `degraded_agents`
and forces human review.

## 3. Tamper detection

Verification recomputes both digests from the underlying evidence and agent-run rows. It never
trusts a saved “valid” flag or merely reads back the hash stored beside the decision.

```mermaid
flowchart LR
    subgraph anchored["1. Anchor the original decision"]
        original["agent_runs.output_json"] -->|keccak256| originalHash["0x0ebe21e8..."]
        originalHash --> sepolia["DecisionProof on Sepolia"]
        sepolia --> valid["VALID"]
    end

    subgraph edit["2. Insider edits SQLite"]
        update["UPDATE agent_runs<br/>SET output_json = ..."]
        boundary["The operator controls SQLite<br/>but not the anchored digest"]
        update -.- boundary
    end

    subgraph verify["3. Recompute and compare"]
        changed["changed output_json"] -->|keccak256| changedHash["0xe59d6005..."]
        changedHash --> comparison{"Matches the<br/>anchored digest?"}
        unchanged["0x0ebe21e8...<br/>unchanged on chain"] --> comparison
        comparison -->|No| tampered["TAMPERED"]
        comparison -->|Yes| stillValid["VALID"]
    end

    anchored --> edit --> verify

    classDef bad fill:#3a1a1a,stroke:#ff6b6b,color:#ffd7d7
    classDef good fill:#1a3a2a,stroke:#4ade80,color:#d7ffe7
    class tampered bad
    class valid,stillValid good
```

The demo round trip is therefore observable and reversible:
`VALID → edit stored output → TAMPERED → restore original output → VALID`.

## 4. Two datasets, one traversal layer

GUIDE is tabular, so AgentSphere constructs an entity graph. WitFoo Precinct6 ships a graph. Both
are adapted to the same `EntityGraph` interface, allowing the capped BFS and confidence-weighted
Dijkstra implementations to run unchanged.

```mermaid
flowchart TB
    subgraph guideGraph["Microsoft GUIDE — constructed graph"]
        guideRows[("591,340 evidence rows")]
        cooccurrence["Co-occurrence edges<br/>within correlated alerts"]
        guideTotals["96,351 nodes<br/>26,194 edges"]
        guideConfidence["confidence.py<br/>documented hand-set weights"]
        guideRows --> cooccurrence --> guideTotals
    end

    subgraph witfooGraph["WitFoo Precinct6 — shipped graph"]
        witfooEdges[("634,190 labelled edges")]
        canonicalTypes["Map source node types to<br/>the canonical entity vocabulary"]
        witfooTotals["35,133 declared nodes<br/>16,586 on activity edges"]
        witfooConfidence["Dataset confidence<br/>label confidence + suspicion score"]
        witfooEdges --> canonicalTypes --> witfooTotals
    end

    traversal["Shared traversal layer<br/>depth-capped BFS<br/>Dijkstra on -log(confidence)<br/>DFS lineage"]
    outputs["Blast radius<br/>most probable path<br/>lineage report"]

    guideTotals --> traversal
    witfooTotals --> traversal
    guideConfidence -.->|confidence function| traversal
    witfooConfidence -.->|confidence function| traversal
    traversal --> outputs

    classDef shipped fill:#1a2a32,stroke:#4ad0ff,color:#e6edf3
    class witfooEdges,witfooTotals,witfooConfidence shipped
```

WitFoo’s node total needs its parts shown, or 16,586 looks like data was dropped:

| Node population | Count |
|---|---:|
| Declared by the dataset | 35,133 |
| On activity edges — the traversal graph | 16,586 |
| Only on `INCIDENT_LINK` edges — incident membership, no observed activity | 16,503 |
| On no edge at all | 2,044 |

`INCIDENT_LINK` edges are excluded from traversal intentionally. Traversing them would allow a path
to jump between otherwise unrelated entities through a shared incident record and misreport that
administrative membership as an attack path.

## 5. Proof lifecycle and idempotent recovery

```mermaid
stateDiagram-v2
    [*] --> Proposed: submitDecision
    Proposed --> Finalized: low-risk finalizeDecision
    Proposed --> Approved: approveDecision(true)
    Proposed --> Rejected: approveDecision(false)
    Approved --> Finalized: finalizeDecision
    Rejected --> Rejected: finalization blocked

    note right of Proposed
        Medium and high risk remain here
        until a human approval is recorded.
    end note

    note left of Finalized
        A repeated fingerprint recovers the
        existing decision id instead of sending
        a reverting duplicate transaction.
    end note
```

Approval and anchoring may happen in either order. The API reconciles an approval recorded before
anchoring, persists the witnessed contract state, and keeps normal Proof-page reloads network-free.
The explicit **Confirm against the contract** action performs the live read and preserves that
response instead of overwriting it with the local-only view.

## 6. What is deliberately not on chain

| Stays in SQLite | Goes on chain |
|---|---|
| Raw evidence rows and entity values | `keccak256` digest of the evidence bundle |
| Agent prompts and full structured outputs | `keccak256` digest of the assembled outputs |
| Analyst comment text | `keccak256` digest of the comment |
| Incident summaries and rationales | Incident id, label, and risk level |
| Retrieval results and graph context | Agent address, approver address, and timestamps |

This boundary is enforced by the `DecisionProof` ABI: the contract has no function capable of
accepting a raw evidence row, prompt, rationale, or analyst comment.
