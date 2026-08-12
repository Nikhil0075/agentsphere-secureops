"""API response models.

These reuse the frozen agent contracts from :mod:`app.agents.schemas` directly rather than
redeclaring them. A parallel set of DTOs would drift from the contracts the moment either changed,
and the whole point of freezing them was that they cannot drift. The consequence is that
``/openapi.json`` describes the real agent outputs, so the frontend's types are generated from the
same source of truth the agents are validated against.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.agents.llm import normalize_mode

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


class DemoArcInfo(BaseModel):
    """State of the six-case presentation arc, read from the dataset manifest.

    Presentation only. No metric is ever computed over these six incidents — see
    :mod:`app.data.demo_arc` for why the arc, the showcase pool and the ``demo`` split are three
    different things.
    """

    size: int = 0
    expected: int = 6
    complete: bool = False
    roles: list[str] = Field(default_factory=list)


class DatasetInfo(BaseModel):
    source: str
    incidents: int
    evidence_rows: int
    labels: dict[str, int]
    splits: dict[str, int]
    showcase_incidents: int = 0
    demo_arc: DemoArcInfo = Field(default_factory=DemoArcInfo)
    sentinels_masked: list[str] = Field(default_factory=list)
    index_available: bool = False
    llm_backend: str = ""
    execution_mode: Literal["replay", "live", "deterministic"] = "replay"
    model_profile: dict[str, str] = Field(default_factory=dict)
    replay_entries: int = 0
    chain: dict = Field(default_factory=dict)
    witfoo: dict = Field(default_factory=dict)


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
    #: Position in the six-case narration order, or None for the other 4,994 incidents. A row with
    #: a rank is always also ``is_showcase``; the reverse does not hold.
    demo_rank: int | None = None
    demo_role: str = ""
    baseline_label: str = ""
    baseline_confidence: float = 0.0


class IncidentDetail(IncidentSummary):
    summary: str = ""
    entity_counts: dict[str, int] = Field(default_factory=dict)
    threat_families: str = ""
    duration_minutes: float = 0.0


class QueueFacets(BaseModel):
    categories: list[str] = Field(default_factory=list)
    suspicions: list[str] = Field(default_factory=list)


class IncidentPage(BaseModel):
    items: list[IncidentSummary] = Field(default_factory=list)
    total: int
    limit: int
    offset: int
    sort_by: str
    sort_dir: Literal["asc", "desc"]
    facets: QueueFacets = Field(default_factory=QueueFacets)


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
    mode: Literal["replay", "live", "deterministic"] | None = Field(
        default=None, description="Preferred execution mode; defaults to LLM_BACKEND"
    )
    backend: str | None = Field(
        default=None,
        description="Compatibility alias: deterministic | openai | cache",
    )
    persist: bool = True

    @model_validator(mode="after")
    def compatible_execution_mode(self):
        if self.mode and self.backend and self.mode != normalize_mode(self.backend):
            raise ValueError("mode and backend select different execution modes")
        return self

    def resolved_mode(self) -> str:
        return normalize_mode(self.mode or self.backend)


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
    #: One entry per agent run, in run order. See :class:`AgentTrace`.
    traces: list[AgentTrace] = Field(default_factory=list)
    degraded_agents: list[str] = Field(default_factory=list)
    #: Agents that succeeded only on a retry. The retry re-sends an identical prompt, so on a
    #: live model this is a resample: two runs of the same incident can diverge here without
    #: either being degraded.
    resampled_agents: list[str] = Field(default_factory=list)
    #: True when the live-only triage correction pass ran. Such a run has nine agent runs and a
    #: different output_hash than its replay, which has six.
    revision_fired: bool = False
    execution_mode: Literal["replay", "live", "deterministic"] = "deterministic"
    model_profile: dict[str, str] = Field(default_factory=dict)
    cache_status: Literal["hit", "miss_filled", "bypassed", "degraded"] = "bypassed"
    trace_id: str = ""
    token_usage: dict[str, int] = Field(default_factory=dict)
    retry_count: int = 0


class ApprovalRequest(BaseModel):
    approved: bool
    analyst: str = Field(min_length=1, max_length=120)
    comment: str = Field(default="", max_length=1000)


class AgentTrace(BaseModel):
    """What an agent was actually asked, and what it was allowed to see.

    Carried on the API response rather than on ``AgentRunRecord``: that record renders into
    ``artifacts/schemas/workflow_state.schema.json`` via ``scripts/freeze_schemas.py``, so a new
    field there breaks ``tests/test_schemas_frozen.py``. The agent contracts are frozen; this model
    is not, which makes it the right home.

    ``label_free`` is the point of the whole thing. For a ``pre_decision`` agent it must be true —
    that is invariant 2 made readable on screen rather than asserted in a docstring. Triage and
    after are not pre-decision: they legitimately receive the baseline's *prediction*, which is a
    model output rather than the ground-truth label.
    """

    run_index: int
    agent: str
    sequence: int = 0
    status: str = ""
    system_prompt: str = ""
    user_prompt: str = ""
    context_json: str = ""
    context_keys: list[str] = Field(default_factory=list)
    truncated: bool = False
    pre_decision: bool = False
    label_free: bool = True


class OnchainDecision(BaseModel):
    """The ``DecisionProof.Decision`` struct, field for field.

    Named to match the Solidity so the UI can present it as "this is literally what is on chain"
    rather than as a reformatted summary. Note what is *not* here: no evidence rows, no prompts,
    no rationale. There is no function on the contract that could store them.
    """

    incident_id: str = ""
    evidence_hash: str = ""
    output_hash: str = ""
    label: str = ""
    risk: str = ""
    state: str = ""
    agent: str = ""
    approver: str = ""
    comment_hash: str = ""
    submitted_at: int = 0
    decided_at: int = 0
    finalized_at: int = 0


class AnchorAttempt(BaseModel):
    """One row of ``blockchain_proofs``.

    Plural because a retry after a network failure records another attempt rather than overwriting
    the first — see the uuid4 note in ``anchor()``. Showing the attempts is honest about what
    actually happened at the venue.
    """

    proof_id: str = ""
    tx_hash: str = ""
    block_number: int | None = None
    gas_used: int | None = None
    #: The chain's own words when the submission was refused. Empty on a successful anchor.
    failure_reason: str = ""
    agent_address: str = ""
    onchain_state: str = ""
    anchored_at: str = ""

    @field_validator("proof_id", "tx_hash", "failure_reason", "agent_address", "onchain_state",
                     "anchored_at", mode="before")
    @classmethod
    def _null_is_empty(cls, value):
        """SQLite NULL means "not recorded", which for these columns is the empty string.

        Two write paths reach `blockchain_proofs`: the API route, which always supplies every
        column, and `services/decisions.py`, which the CLI and the idempotent-recovery path use and
        which leaves newer columns at their NULL default. A row from the second path made the whole
        Proof endpoint fail validation with a 500 — so anchoring from `run_demo.py --anchor`, the
        exact path a rehearsal uses, broke the screen it was rehearsing.
        """
        return "" if value is None else value


class LocalApproval(BaseModel):
    """The human decision as recorded in SQLite, before anything reaches the chain.

    Kept separate from ``OnchainDecision.approver`` on purpose: this is what the analyst did, the
    other is what the contract witnessed, and until the anchor succeeds only the first exists. The
    comment text stays here and never leaves — only ``comment_hash`` is anchorable.
    """

    approver: str = ""
    approved: bool = False
    comment_hash: str = ""
    recorded_at: str = ""


class ProofInfo(BaseModel):
    decision_id: str
    found: bool = False
    anchored: bool = False
    evidence_hash: str = ""
    output_hash: str = ""
    tx_hash: str = ""
    block_number: int | None = None
    gas_used: int | None = None
    chain_id: int | None = None
    contract_address: str = ""
    registry_address: str = ""
    network: str = ""
    agent_address: str = ""
    #: Registered agent roles to addresses, read from the deployment record, not from the chain.
    registered_agents: dict[str, str] = Field(default_factory=dict)
    onchain_decision_id: int | None = None
    onchain_state: str = ""
    explorer_url: str = ""
    #: Explorer origin for this chain id, e.g. "https://sepolia.etherscan.io". Served so the UI can
    #: link a contract or an address without hardcoding a host -- a link to the wrong network's
    #: explorer is worse than no link, and the chain id is only known here.
    explorer_base: str = ""
    #: True when tx/block/gas describe the transaction that *first* anchored these digests rather
    #: than one this decision sent. The figures are real and on a public explorer; only the
    #: authorship differs, and the UI must say so rather than implying we just submitted them.
    recovered: bool = False
    valid: bool | None = None
    chain_available: bool = False
    #: False when this response was assembled without touching an RPC. The Proof screen shows it
    #: so "we did not ask the contract" is never mistaken for "the contract said no".
    chain_checked: bool = False
    onchain: OnchainDecision | None = None
    attempts: list[AnchorAttempt] = Field(default_factory=list)
    #: The locally recorded human decision, if one has been made yet.
    approval: LocalApproval | None = None
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


class WitFooIncident(BaseModel):
    """A WitFoo incident.

    ``threat_labels`` counts benign/suspicious/malicious edges. Those are *threat assessments*,
    not the analyst triage verdicts GUIDE carries, and the field is named to keep that visible.
    """

    incident_id: str
    mo_name: str = ""
    disposition: str = ""
    disposition_category: str = ""
    status_name: str = ""
    lifecycle_stage: str = ""
    suspicion_score: float = 0.0
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    products_observed: list[str] = Field(default_factory=list)
    edge_count: int = 0
    node_count: int = 0
    threat_labels: dict[str, int] = Field(default_factory=dict)
    first_observed_at: int | None = None
    last_observed_at: int | None = None
    report_text: str = ""


class ProvenanceEdge(BaseModel):
    source: str
    target: str
    type: str = ""
    threat_label: str = ""
    confidence: float = 0.0
    scored: bool = False
    attack_techniques: list[str] = Field(default_factory=list)


class ProvenanceGraph(BaseModel):
    """One incident's provenance subgraph, as shipped by the dataset rather than constructed."""

    incident: WitFooIncident
    nodes: list[str] = Field(default_factory=list)
    edges: list[ProvenanceEdge] = Field(default_factory=list)
    blast_radius: BlastRadiusInfo | None = None
    attack_path: AttackPathInfo | None = None
    #: How many confidence *lookups* during traversal came from the dataset rather than a fallback
    #: prior. Lookups, not edges — Dijkstra queries an edge more than once while relaxing.
    confidence_sources: dict = Field(default_factory=dict)
    node_count: int = 0
    #: Distinct entity pairs. Lower than ``incident.edge_count``, which counts raw edge records:
    #: WitFoo observes the same pair repeatedly over time, and the traversal graph is simple, so
    #: 24 observations between 4 entities collapse to 3 connections. Both are reported because
    #: they answer different questions — how much was observed, and how much is connected.
    edge_count: int = 0
    edge_records: int = 0


class ProofMetrics(BaseModel):
    """Aggregate integrity results computed locally without contacting the chain."""

    decisions: int = 0
    anchored: int = 0
    valid: int = 0
    tampered: int = 0
    validity_rate: float | None = None
    verification_scope: str = "local"


class MetricsResponse(BaseModel):
    baseline: dict = Field(default_factory=dict)
    evaluation: dict = Field(default_factory=dict)
    graph: dict = Field(default_factory=dict)
    index: dict = Field(default_factory=dict)
    proofs: ProofMetrics = Field(default_factory=ProofMetrics)
    witfoo: dict = Field(default_factory=dict)
    #: Measured live run-to-run variance from scripts/measure_variance.py. Empty on a fresh clone.
    variance: dict = Field(default_factory=dict)
    #: The end-to-end rehearsal sweep from scripts/rehearse.py. Empty until it has been run.
    rehearsal: dict = Field(default_factory=dict)
