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
from dataclasses import dataclass, field
from typing import Callable

import pandas as pd

from app.agents.correlation import CorrelationAgent
from app.agents.detection import DetectionAgent
from app.agents.investigation import InvestigationAgent
from app.agents.llm import LLMClient, build_client
from app.agents.remediation import RemediationAgent
from app.agents.schemas import BaselinePrediction, WorkflowState
from app.agents.triage import TriageAgent
from app.agents.verifier import VerifierAgent
from app.blockchain.hashing import hash_agent_output, hash_evidence_bundle
from app.graph.correlate import correlate
from app.observability.logging import log_event
from app.orchestration.context import IncidentContext
from app.policies import engine
from app.retrieval.base import NullRetriever, Retriever

#: The full chain (§6.1). Detection through Verifier, in contract order.
AGENT_SEQUENCE = (
    "detection",
    "correlation",
    "investigation",
    "triage",
    "remediation",
    "verifier",
)

Node = Callable[[WorkflowState, IncidentContext], WorkflowState]


@dataclass
class WorkflowResult:
    state: WorkflowState
    context: IncidentContext
    gate: "engine.GateDecision | None" = None
    #: What each agent was actually asked, one entry per run, keyed by ``run_index``.
    #:
    #: Keyed by index rather than by agent name because the live revision pass runs triage,
    #: remediation and verifier a second time — nine runs, with two entries per revised agent.
    #: Defaulted so existing constructors keep working.
    traces: list[dict] = field(default_factory=list)

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

    @property
    def revision_fired(self) -> bool:
        """Whether the live-only triage correction pass ran, adding three stages to the timeline."""
        return len(self.state.runs) > len(AGENT_SEQUENCE)

    def resampled_agents(self) -> list[str]:
        """Agents that succeeded only on a later attempt.

        A retry re-issues a byte-identical prompt, so on a model with any sampling variance a
        second-attempt success is a *resample*, not a corrected call. It is recorded as ``ok`` and
        nothing else distinguishes it, which makes it worth naming: two runs of the same incident
        can diverge here without either being degraded.

        Derived rather than stored -- ``AgentRunRecord`` is frozen into
        ``artifacts/schemas/workflow_state.schema.json`` and cannot take a new field.
        """
        return [
            run.agent for run in self.state.runs if run.status == "ok" and run.attempts > 1
        ]

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
            "remediation": RemediationAgent(self.client, sequence=5),
            "verifier": VerifierAgent(self.client, sequence=6),
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
        self,
        name: str,
        state: WorkflowState,
        context: IncidentContext,
        traces: list[dict] | None = None,
        **kwargs,
    ) -> WorkflowState:
        agent = self.agents[name]
        sink: dict = {} if traces is not None else None  # type: ignore[assignment]
        output, record = agent.run(state, context=context, trace_sink=sink, **kwargs)
        # Revision passes follow the original six stages in the audit timeline.
        record.sequence = len(state.runs) + 1
        setattr(state, name, output)
        state.runs.append(record)
        if traces is not None and sink:
            # Stamped after the run so the index matches this record's position in state.runs.
            sink["run_index"] = len(state.runs) - 1
            sink["sequence"] = record.sequence
            sink["status"] = record.status
            traces.append(sink)
        if record.status != "ok":
            state.errors.append(f"{name}: {record.status} — {record.validation_error}")
        return state

    def _revise_rejected_live_triage(
        self, state: WorkflowState, context: IncidentContext, traces: list[dict] | None = None
    ) -> WorkflowState:
        """Give a live Sol judge one bounded correction pass after verifier rejection.

        Replay remains byte-for-byte presentation-safe and deterministic mode remains fully
        offline. The correction loop is therefore live-only, capped at one pass, and the final
        deterministic policy gate still has the last word.

        The consequence to know before comparing hashes: **a live run that fires this produces
        nine agent runs and a different ``output_hash`` than its replay, which produces six.**
        Replay cannot reproduce the revision because the pass is gated on ``backend == "live"``,
        so the entries it writes to the cache are only ever reachable from another live run. That
        is a divergence by design, not a replay bug; ``WorkflowResult.revision_fired`` reports it
        and ``scripts/prewarm_replay.py`` records it per incident in the demo manifest.
        """
        if getattr(self.client, "backend", "") != "live" or state.verifier is None:
            return state
        if state.verifier.verdict.value == "accept" or not state.verifier.contradictions:
            return state
        if any(run.status != "ok" for run in state.runs):
            return state

        feedback = "; ".join(state.verifier.contradictions[:6])
        state = self._run_agent(
            "triage",
            state,
            context,
            traces,
            revision_feedback=feedback,
            reasoning_effort="high",
        )
        state = self._run_agent("remediation", state, context, traces)
        state = self._run_agent("verifier", state, context, traces, reasoning_effort="high")
        return state

    def _apply_gate(self, state: WorkflowState) -> engine.GateDecision | None:
        """Run the deterministic policy gate over the finished chain.

        This is the last word on autonomy and it is not an LLM. The Verifier reasons about whether
        the recommendation holds up; this decides whether it may proceed without a human, by
        dictionary lookup and threshold comparison. An agent cannot argue its way past it — which
        is the honest answer to "is this just an LLM wrapper?" (§12.3).
        """
        if state.triage is None or state.remediation is None:
            # Without both, there is nothing to gate and no basis to auto-approve anything.
            state.requires_approval = True
            return None

        bundle = state.correlation.evidence_bundle if state.correlation else state.evidence_ids
        gate = engine.evaluate(
            triage=state.triage,
            remediation=state.remediation,
            verifier=state.verifier,
            evidence_ids=bundle,
            baseline=state.baseline,
            degraded_agents=[run.agent for run in state.runs if run.status != "ok"],
        )
        state.requires_approval = gate.requires_approval

        log_event(
            "policy_gate",
            workflow_id=state.workflow_id,
            incident_id=state.incident_id,
            action=state.remediation.recommended_action,
            action_risk=gate.action_risk,
            requires_approval=gate.requires_approval,
            auto_approved=gate.auto_approved,
            failed_policies=gate.failed_policies(),
            reasons=gate.reasons,
        )
        return gate

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

        traces: list[dict] = []
        for name in AGENT_SEQUENCE:
            state = self._run_agent(name, state, context, traces)

        state = self._revise_rejected_live_triage(state, context, traces)

        gate = self._apply_gate(state)

        # Hash what the decision was actually built on. Day 5 anchors these.
        bundle = (
            state.correlation.evidence_bundle if state.correlation else state.evidence_ids
        )
        # Hash evidence *content*, not just the selection of ids. Pinning ids alone would let an
        # edit to an evidence row pass verification, and the tamper-evidence claim would be false.
        state.evidence_hash = hash_evidence_bundle(
            bundle, state.incident_id, payloads=context.evidence_payloads(bundle)
        )
        state.output_hash = hash_agent_output(
            "workflow",
            {
                name: getattr(state, name).model_dump(mode="json")
                for name in AGENT_SEQUENCE
                if getattr(state, name) is not None
            },
        )

        result = WorkflowResult(state=state, context=context, gate=gate, traces=traces)

        log_event(
            "workflow_end",
            workflow_id=state.workflow_id,
            incident_id=state.incident_id,
            label=state.triage.label.value if state.triage else "",
            confidence=state.triage.confidence if state.triage else 0.0,
            verdict=state.verifier.verdict.value if state.verifier else "",
            requires_approval=state.requires_approval,
            degraded=result.degraded_agents(),
            resampled=result.resampled_agents(),
            revision_fired=result.revision_fired,
            latency_ms=result.total_latency_ms(),
        )

        return result
