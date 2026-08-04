"""The agent workflow.

An explicit typed state machine over :class:`WorkflowState`. LangGraph was evaluated and left out
for now: the Day 3 chain is linear, LangGraph's value is dependency-aware scheduling, and §8.2 is
blunt that presenting a topological sort of a straight line as an orchestration algorithm collapses
under one follow-up question. The nodes below are plain functions with a uniform signature, so if
Day 4 introduces genuine fan-out — parallel enrichment joining before Triage — swapping the driver
for LangGraph is a wiring change and not a rewrite.

Each node is independently recoverable. A node that fails produces its agent's conservative
fallback, records the degradation, and the workflow continues — because a Verifier that never runs
because Correlation timed out is strictly worse than a Verifier that runs on a degraded bundle and
says so.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable

import pandas as pd

from app.agents.correlation import CorrelationAgent
from app.agents.detection import DetectionAgent
from app.agents.investigation import InvestigationAgent
from app.agents.llm import LLMClient, build_client
from app.agents.schemas import BaselinePrediction, WorkflowState
from app.agents.triage import TriageAgent
from app.blockchain.hashing import hash_agent_output, hash_evidence_bundle
from app.graph.correlate import correlate
from app.observability.logging import log_event
from app.orchestration.context import IncidentContext
from app.retrieval.base import NullRetriever, Retriever

#: The Day 3 chain. Remediation and Verifier land on Day 4.
AGENT_SEQUENCE = ("detection", "correlation", "investigation", "triage")

Node = Callable[[WorkflowState, IncidentContext], WorkflowState]


@dataclass
class WorkflowResult:
    state: WorkflowState
    context: IncidentContext

    @property
    def label(self) -> str:
        return self.state.triage.label.value if self.state.triage else ""

    @property
    def confidence(self) -> float:
        return self.state.triage.confidence if self.state.triage else 0.0

    def timeline(self) -> list[dict]:
        return [run.model_dump(mode="json") for run in self.state.runs]

    def degraded_agents(self) -> list[str]:
        return [run.agent for run in self.state.runs if run.status != "ok"]

    def total_latency_ms(self) -> int:
        return sum(run.latency_ms for run in self.state.runs)


class Workflow:
    """Runs the agent chain for one incident."""

    def __init__(
        self,
        client: LLMClient | None = None,
        retriever: Retriever | None = None,
    ) -> None:
        self.client = client or build_client()
        self.retriever = retriever or NullRetriever()
        self.agents = {
            "detection": DetectionAgent(self.client, sequence=1),
            "correlation": CorrelationAgent(self.client, sequence=2),
            "investigation": InvestigationAgent(self.client, sequence=3),
            "triage": TriageAgent(self.client, sequence=4),
        }

    # --- context assembly ---------------------------------------------------------------

    def build_context(
        self,
        incident: dict | pd.Series,
        evidence: pd.DataFrame,
        baseline_model=None,
    ) -> IncidentContext:
        incident_id = str(
            incident["incident_id"] if not isinstance(incident, dict) else incident["incident_id"]
        )

        correlation = correlate(evidence) if len(evidence) else None
        similar = self.retriever.similar(incident_id, k=5)

        baseline = None
        if baseline_model is not None:
            try:
                baseline = baseline_model.predict_one(incident)
            except Exception as exc:  # noqa: BLE001 - a stale model must not stop triage
                log_event("baseline_failed", incident_id=incident_id, error=str(exc))

        return IncidentContext.from_incident(
            incident,
            evidence,
            correlation=correlation,
            similar=similar,
            baseline=baseline,
        )

    # --- nodes --------------------------------------------------------------------------

    def _run_agent(
        self, name: str, state: WorkflowState, context: IncidentContext
    ) -> WorkflowState:
        agent = self.agents[name]
        output, record = agent.run(state, context=context)
        setattr(state, name, output)
        state.runs.append(record)
        if record.status != "ok":
            state.errors.append(f"{name}: {record.status} — {record.validation_error}")
        return state

    # --- driver -------------------------------------------------------------------------

    def run(
        self,
        incident: dict | pd.Series,
        evidence: pd.DataFrame,
        baseline_model=None,
        workflow_id: str | None = None,
    ) -> WorkflowResult:
        context = self.build_context(incident, evidence, baseline_model)

        state = WorkflowState(
            workflow_id=workflow_id or f"WF-{uuid.uuid4().hex[:12]}",
            incident_id=context.incident_id,
            incident_summary=context.summary,
            evidence_ids=context.evidence_ids,
            correlation_clusters=(
                context.correlation.cluster_count if context.correlation else 0
            ),
        )
        if context.baseline:
            state.baseline = BaselinePrediction(**context.baseline)

        log_event(
            "workflow_start",
            workflow_id=state.workflow_id,
            incident_id=state.incident_id,
            backend=getattr(self.client, "backend", "unknown"),
            evidence=len(context.evidence),
            clusters=state.correlation_clusters,
        )

        for name in AGENT_SEQUENCE:
            state = self._run_agent(name, state, context)

        # Hash what the decision was actually built on. Day 5 anchors these.
        bundle = (
            state.correlation.evidence_bundle if state.correlation else state.evidence_ids
        )
        state.evidence_hash = hash_evidence_bundle(bundle, state.incident_id)
        state.output_hash = hash_agent_output(
            "workflow",
            {
                name: getattr(state, name).model_dump(mode="json")
                for name in AGENT_SEQUENCE
                if getattr(state, name) is not None
            },
        )

        log_event(
            "workflow_end",
            workflow_id=state.workflow_id,
            incident_id=state.incident_id,
            label=state.triage.label.value if state.triage else "",
            confidence=state.triage.confidence if state.triage else 0.0,
            degraded=[r.agent for r in state.runs if r.status != "ok"],
            latency_ms=sum(r.latency_ms for r in state.runs),
        )

        return WorkflowResult(state=state, context=context)
