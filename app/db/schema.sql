-- AgentSphere SecureOps application database (SQLite for the demo; PostgreSQL if time allows).
--
-- Raw security evidence lives here and only here. The chain (Day 5) receives hashes, agent
-- identities, approval state and timestamps — never the contents of these tables. That split is
-- the architecture principle in §4.3 and it is enforced by what the contract accepts, not by
-- convention.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS incidents (
    incident_id       TEXT PRIMARY KEY,
    org_id            TEXT,
    incident_ref      TEXT,
    label             TEXT,              -- ground truth; never shown to an agent
    split             TEXT,
    first_seen        TEXT,
    last_seen         TEXT,
    alert_count       INTEGER NOT NULL DEFAULT 0,
    evidence_count    INTEGER NOT NULL DEFAULT 0,
    top_category      TEXT,
    top_detector      TEXT,
    top_alert_title   TEXT,
    mitre_techniques  TEXT,
    summary           TEXT,
    risk_score        REAL,
    status            TEXT NOT NULL DEFAULT 'new',   -- new|running|triaged|awaiting_approval|closed
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_risk ON incidents(risk_score DESC);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id    TEXT PRIMARY KEY,
    incident_id    TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    alert_id       TEXT,
    timestamp      TEXT,
    entity_type    TEXT,
    evidence_role  TEXT,
    payload_json   TEXT NOT NULL          -- the full canonical evidence row
);

CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_alert ON evidence(alert_id);

-- One row per agent invocation. This is the observability record (§6 "Observability") and the
-- source of the workflow timeline in the UI.
CREATE TABLE IF NOT EXISTS agent_runs (
    run_id           TEXT PRIMARY KEY,
    workflow_id      TEXT NOT NULL,
    incident_id      TEXT NOT NULL,
    agent            TEXT NOT NULL,      -- detection|correlation|investigation|triage|remediation|verifier
    sequence         INTEGER NOT NULL,
    backend          TEXT,               -- openai|cache|deterministic
    model            TEXT,
    status           TEXT NOT NULL,      -- ok|invalid_output|timeout|error|fallback
    attempts         INTEGER NOT NULL DEFAULT 1,
    latency_ms       INTEGER,
    prompt_tokens    INTEGER,
    completion_tokens INTEGER,
    validation_error TEXT,
    output_json      TEXT,
    output_hash      TEXT,               -- keccak256 over canonical JSON
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_workflow ON agent_runs(workflow_id, sequence);
CREATE INDEX IF NOT EXISTS idx_agent_runs_incident ON agent_runs(incident_id);

-- The decision a workflow arrived at. One per completed workflow.
CREATE TABLE IF NOT EXISTS decisions (
    decision_id     TEXT PRIMARY KEY,
    workflow_id     TEXT NOT NULL,
    incident_id     TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    label           TEXT,               -- TruePositive|BenignPositive|FalsePositive
    confidence      REAL,
    baseline_label  TEXT,               -- non-LLM comparison point
    baseline_confidence REAL,
    recommended_action TEXT,
    action_risk     TEXT,               -- low|medium|high
    requires_approval INTEGER NOT NULL DEFAULT 0,
    verifier_verdict TEXT,              -- accept|reject|escalate
    state           TEXT NOT NULL DEFAULT 'proposed', -- proposed|approved|rejected|finalized
    evidence_hash   TEXT,
    output_hash     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_decisions_incident ON decisions(incident_id);
CREATE INDEX IF NOT EXISTS idx_decisions_state ON decisions(state);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id   TEXT PRIMARY KEY,
    decision_id   TEXT NOT NULL REFERENCES decisions(decision_id) ON DELETE CASCADE,
    approver      TEXT NOT NULL,
    approved      INTEGER NOT NULL,
    comment       TEXT,
    comment_hash  TEXT,
    signature     TEXT,                 -- populated Day 5
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_approvals_decision ON approvals(decision_id);

-- Created now, populated on Day 5. Cheaper than migrating a live database mid-build.
CREATE TABLE IF NOT EXISTS blockchain_proofs (
    proof_id        TEXT PRIMARY KEY,
    decision_id     TEXT NOT NULL REFERENCES decisions(decision_id) ON DELETE CASCADE,
    chain_id        INTEGER,
    contract_address TEXT,
    tx_hash         TEXT,
    block_number    INTEGER,
    agent_address   TEXT,
    evidence_hash   TEXT,
    output_hash     TEXT,
    onchain_state   TEXT,               -- submitted|approved|finalized
    anchored_at     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_proofs_decision ON blockchain_proofs(decision_id);
