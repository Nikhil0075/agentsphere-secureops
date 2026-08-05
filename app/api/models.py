"""API response models.

These reuse the frozen agent contracts from :mod:`app.agents.schemas` directly rather than
redeclaring them. A parallel set of DTOs would drift from the contracts the moment either changed,
and the whole point of freezing them was that they cannot drift. The consequence is that
``/openapi.json`` describes the real agent outputs, so the frontend's types are generated from the
same source of truth the agents are validated against.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.agents.schemas import (
    AgentRunRecord,
    BaselinePrediction,
    CorrelationOutput,
    DetectionOutput,
    InvestigationOutput,
    PolicyCheck,
    RemediationOutput,
    TriageOutput,
    VerifierOutput,
)


class DatasetInfo(BaseModel):
    source: str
    incidents: int
    evidence_rows: int
    labels: dict[str, int]
    splits: dict[str, int]
    sentinels_masked: list[str] = Field(default_factory=list)
    index_available: bool = False
    llm_backend: str = ""
    chain: dict = Field(default_factory=dict)


class IncidentSummary(BaseModel):
    """Queue row. Carries the ground-truth label because this is the analyst-facing API, not an
    agent-facing one — agents never read from here."""

    incident_id: str
    label: str
    split: str
    risk_score: float
    alert_count: int
    evidence_count: int
    top_category: str = ""
    top_detector: str = ""
    top_alert_title: str = ""
    max_suspicion_level: str = ""
    mitre_techniques: str = ""
    first_seen: str = ""
    is_showcase: bool = False
    baseline_label: str = ""
    baseline_confidence: float = 0.0


class IncidentDetail(IncidentSummary):
    summary: str = ""
    entity_counts: dict[str, int] = Field(default_factory=dict)
    threat_families: str = ""
    duration_minutes: float = 0.0


class EvidenceRow(BaseModel):
    evidence_id: str
    alert_id: str = ""
    timestamp: str = ""
    entity_type: str = ""
    evidence_role: str = ""
    suspicion_level: str = ""
    last_verdict: str = ""
    fields: dict[str, str] = Field(default_factory=dict)


class SimilarIncident(BaseModel):
    incident_id: str
    score: float
    why: str
    summary: str = ""


class ClusterInfo(BaseModel):
    cluster_id: str
    size: int
    evidence_count: int
    linking_entities: list[str] = Field(default_factory=list)


class CorrelationInfo(BaseModel):
    alert_count: int
    cluster_count: int
    reduction: float
    largest_cluster: int
    clusters: list[ClusterInfo] = Field(default_factory=list)


class BlastRadiusInfo(BaseModel):
    seeds: list[str] = Field(default_factory=list)
    impacted_by_type: dict[str, list[str]] = Field(default_factory=dict)
    total_nodes: int = 0
    hubs_blocked: list[str] = Field(default_factory=list)
    truncated: bool = False


class AttackPathInfo(BaseModel):
    path: list[str] = Field(default_factory=list)
    hops: int = 0
    probability: float = 0.0
    edge_confidences: list[float] = Field(default_factory=list)
    weakest_link: float = 0.0


class GraphInfo(BaseModel):
    blast_radius: BlastRadiusInfo
    attack_path: AttackPathInfo | None = None
    node_count: int = 0
    edge_count: int = 0


class GateInfo(BaseModel):
    requires_approval: bool
    auto_approved: bool
    action_risk: str
    reasons: list[str] = Field(default_factory=list)
    checks: list[PolicyCheck] = Field(default_factory=list)


class WorkflowRequest(BaseModel):
    incident_id: str
    backend: str | None = Field(
        default=None, description="deterministic | openai | cache; defaults to LLM_BACKEND"
    )
    persist: bool = True


class WorkflowResponse(BaseModel):
    workflow_id: str
    incident_id: str
    decision_id: str = ""
    label: str = ""
    confidence: float = 0.0
    requires_approval: bool = True

    baseline: BaselinePrediction | None = None
    detection: DetectionOutput | None = None
    correlation: CorrelationOutput | None = None
    investigation: InvestigationOutput | None = None
    triage: TriageOutput | None = None
    remediation: RemediationOutput | None = None
    verifier: VerifierOutput | None = None

    gate: GateInfo | None = None
    correlation_info: CorrelationInfo | None = None
    runs: list[AgentRunRecord] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    evidence_hash: str = ""
    output_hash: str = ""
    total_latency_ms: int = 0
    degraded_agents: list[str] = Field(default_factory=list)


class ApprovalRequest(BaseModel):
    approved: bool
    analyst: str = Field(min_length=1, max_length=120)
    comment: str = Field(default="", max_length=1000)


class ProofInfo(BaseModel):
    decision_id: str
    found: bool = False
    anchored: bool = False
    evidence_hash: str = ""
    output_hash: str = ""
    tx_hash: str = ""
    block_number: int | None = None
    chain_id: int | None = None
    contract_address: str = ""
    onchain_decision_id: int | None = None
    onchain_state: str = ""
    explorer_url: str = ""
    valid: bool | None = None
    chain_available: bool = False
    reason: str = ""


class IntegrityInfo(BaseModel):
    """The result of recomputing both digests from stored data.

    ``anchored_*`` is what the chain recorded; ``recomputed_*`` is what the data hashes to *now*.
    They diverge exactly when the off-chain record has been altered since anchoring.
    """

    decision_id: str
    found: bool = False
    workflow_id: str = ""
    incident_id: str = ""

    anchored_evidence_hash: str = ""
    anchored_output_hash: str = ""
    recomputed_evidence_hash: str = ""
    recomputed_output_hash: str = ""

    evidence_valid: bool | None = None
    output_valid: bool | None = None
    onchain_valid: bool | None = None
    valid: bool | None = None

    tampered: list[str] = Field(default_factory=list)
    tamper_active: bool = False
    chain_available: bool = False
    tx_hash: str = ""
    onchain_decision_id: int | None = None
    detail: str = ""


class TamperRequest(BaseModel):
    agent: str = Field(default="triage", max_length=40)


class TamperResult(BaseModel):
    decision_id: str
    agent: str
    field: str
    before: str
    after: str
    integrity: IntegrityInfo


class MetricsResponse(BaseModel):
    baseline: dict = Field(default_factory=dict)
    evaluation: dict = Field(default_factory=dict)
    graph: dict = Field(default_factory=dict)
    index: dict = Field(default_factory=dict)
