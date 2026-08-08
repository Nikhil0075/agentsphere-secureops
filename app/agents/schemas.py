"""Frozen output contracts for the six agents (master plan §6.1).

These are frozen on Day 2 and are not renegotiated afterwards. ``scripts/freeze_schemas.py``
dumps the generated JSON Schema to ``artifacts/schemas/`` and ``tests/test_schemas_frozen.py``
fails if a dump changes — which is what makes "frozen" mechanical rather than aspirational.

The same JSON Schema objects are handed verbatim to the OpenAI structured-output call, so a change
here changes what the model is required to emit. That is exactly why it is locked.

Every model sets ``extra="forbid"``: OpenAI's strict structured-output mode requires
``additionalProperties: false``, and an agent inventing a field is a contract violation we want to
see, not absorb.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Confidence = Annotated[float, Field(ge=0.0, le=1.0)]
EvidenceIds = Annotated[list[str], Field(min_length=1, max_length=50)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --- enumerations -------------------------------------------------------------------------

class TriageLabel(str, Enum):
    TRUE_POSITIVE = "TruePositive"
    BENIGN_POSITIVE = "BenignPositive"
    FALSE_POSITIVE = "FalsePositive"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerifierVerdict(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    ESCALATE = "escalate"


class AgentName(str, Enum):
    DETECTION = "detection"
    CORRELATION = "correlation"
    INVESTIGATION = "investigation"
    TRIAGE = "triage"
    REMEDIATION = "remediation"
    VERIFIER = "verifier"


# --- shared parts -------------------------------------------------------------------------

class SuspiciousEntity(StrictModel):
    entity_type: Literal[
        "account", "device", "ip", "filehash", "url", "process", "mailbox"
    ]
    value: str
    reason: str = Field(max_length=400)


class Relationship(StrictModel):
    source: str
    target: str
    relation: str = Field(max_length=120)


class TimelineEvent(StrictModel):
    timestamp: str
    description: str = Field(max_length=400)
    evidence_id: str


class SimilarCase(StrictModel):
    incident_id: str
    similarity: Confidence
    why_similar: str = Field(max_length=400)


class MitreMapping(StrictModel):
    technique_id: str = Field(max_length=16)
    technique_name: str = Field(max_length=160)
    supporting_evidence_ids: EvidenceIds


class PolicyCheck(StrictModel):
    policy_id: str
    passed: bool
    detail: str = Field(max_length=400)


# --- the six agent contracts ----------------------------------------------------------------

class DetectionOutput(StrictModel):
    """Input: raw incident fields and detector metadata."""

    severity_score: Confidence
    suspicious_entities: list[SuspiciousEntity] = Field(max_length=25)
    initial_reason: str = Field(max_length=1200)


class CorrelationOutput(StrictModel):
    """Input: evidence and related alerts."""

    evidence_bundle: EvidenceIds
    relationships: list[Relationship] = Field(max_length=40)
    timeline: list[TimelineEvent] = Field(max_length=40)
    missing_information: list[str] = Field(max_length=15)


class InvestigationOutput(StrictModel):
    """Input: evidence bundle plus retrieved incidents."""

    similar_cases: list[SimilarCase] = Field(max_length=10)
    mitre_mapping: list[MitreMapping] = Field(max_length=10)
    investigation_summary: str = Field(max_length=2000)


class TriageOutput(StrictModel):
    """Input: investigation output plus baseline score."""

    label: TriageLabel
    confidence: Confidence
    rationale: str = Field(max_length=1500)
    supporting_evidence_ids: EvidenceIds


class RemediationOutput(StrictModel):
    """Input: triage result plus policy catalogue. Every action is simulated."""

    recommended_action: str = Field(max_length=120)
    action_risk: RiskLevel
    rollback_plan: str = Field(max_length=1000)
    justification: str = Field(max_length=1500)


class VerifierOutput(StrictModel):
    """Input: all prior outputs. This agent may reject its own team."""

    verdict: VerifierVerdict
    contradictions: list[str] = Field(max_length=15)
    policy_checks: list[PolicyCheck] = Field(max_length=20)
    escalation_required: bool
    reasoning: str = Field(max_length=1500)


class HumanApproval(StrictModel):
    """Not an LLM output — the analyst's recorded decision on a high-risk recommendation."""

    approved: bool
    comment: str = Field(max_length=1000)
    analyst: str
    signature: str = ""


AGENT_OUTPUT_MODELS: dict[str, type[StrictModel]] = {
    AgentName.DETECTION.value: DetectionOutput,
    AgentName.CORRELATION.value: CorrelationOutput,
    AgentName.INVESTIGATION.value: InvestigationOutput,
    AgentName.TRIAGE.value: TriageOutput,
    AgentName.REMEDIATION.value: RemediationOutput,
    AgentName.VERIFIER.value: VerifierOutput,
}


# --- workflow state -------------------------------------------------------------------------

class BaselinePrediction(BaseModel):
    """The non-LLM comparison point (§6). Kept separate from agent output so the two can never be
    conflated when metrics are reported."""

    model_config = ConfigDict(extra="forbid")

    label: TriageLabel
    confidence: Confidence
    probabilities: dict[str, float] = Field(default_factory=dict)
    model_name: str = ""


class AgentRunRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: str
    sequence: int
    status: str  # ok|invalid_output|timeout|error|fallback
    attempts: int = 1
    latency_ms: int = 0
    backend: str = ""
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached: bool = False
    trace_id: str = ""
    validation_error: str = ""
    output_hash: str = ""


class WorkflowState(BaseModel):
    """The single object the orchestrator threads through every node."""

    model_config = ConfigDict(extra="forbid")

    workflow_id: str
    incident_id: str
    incident_summary: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    risk_score: float = 0.0

    baseline: BaselinePrediction | None = None
    detection: DetectionOutput | None = None
    correlation: CorrelationOutput | None = None
    investigation: InvestigationOutput | None = None
    triage: TriageOutput | None = None
    remediation: RemediationOutput | None = None
    verifier: VerifierOutput | None = None
    approval: HumanApproval | None = None

    correlation_clusters: int = 0
    requires_approval: bool = False
    evidence_hash: str = ""
    output_hash: str = ""
    runs: list[AgentRunRecord] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def completed_agents(self) -> list[str]:
        return [
            name
            for name in AGENT_OUTPUT_MODELS
            if getattr(self, name, None) is not None
        ]
