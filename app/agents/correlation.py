"""Correlation agent — evidence bundle, relationships, timeline, gaps.

Input: evidence and related alerts.
Output: ``evidence_bundle``, ``relationships``, ``timeline``, ``missing_information`` (§6.1).

The Union-Find clustering has already run before this agent is called. The agent does not redo it;
it interprets it. That division matters — the clustering is a deterministic algorithm whose result
can be checked, and the agent's job is to say what the clusters mean.
"""

from __future__ import annotations

from app.agents.base import Agent
from app.agents.schemas import (
    CorrelationOutput,
    Relationship,
    TimelineEvent,
    WorkflowState,
)
from app.data.schema import ENTITY_COLUMNS
from app.orchestration.context import IncidentContext

MAX_BUNDLE = 50


class CorrelationAgent(Agent):
    name = "correlation"
    output_model = CorrelationOutput
    role = (
        "Evidence assembly. Normalise the alerts and evidence into one bundle, state the "
        "relationships between entities, order what happened, and — importantly — name what is "
        "missing. An honest gap list is more useful than a confident narrative built on absent "
        "data."
    )

    def build_context(self, state: WorkflowState, context: IncidentContext = None, **kwargs):
        assert context is not None
        clusters = []
        if context.correlation:
            clusters = [
                {
                    "cluster_id": c.cluster_id,
                    "alerts": len(c.alert_ids),
                    "linking_entities": c.linking_entities[:6],
                    "evidence_count": c.evidence_count,
                }
                for c in context.correlation.clusters[:10]
            ]

        return {
            "incident_id": context.incident_id,
            "evidence_ids": context.evidence_ids,
            "timeline": context.timeline_rows(20),
            "clusters": clusters,
            "correlation_summary": (
                context.correlation.as_dict() if context.correlation else {}
            ),
            "entity_counts": context.entity_counts(),
            "top_entities": context.top_entities(10),
            "detection_entities": (
                [e.model_dump(mode="json") for e in state.detection.suspicious_entities]
                if state.detection
                else []
            ),
        }

    def build_prompt(self, context: dict) -> str:
        clusters = "\n".join(
            f"- {c['cluster_id']}: {c['alerts']} alert(s), {c['evidence_count']} evidence "
            f"item(s), linked by {', '.join(c['linking_entities']) or 'time proximity'}"
            for c in context["clusters"]
        ) or "- no clusters formed"
        timeline = "\n".join(
            f"- {row['timestamp']} [{row['evidence_id']}] {row['description']}"
            for row in context["timeline"][:12]
        ) or "- no usable timestamps"
        summary = context["correlation_summary"]

        return (
            f"Incident {context['incident_id']}\n\n"
            f"Union-Find correlation collapsed {summary.get('alerts', 0)} alert(s) into "
            f"{summary.get('clusters', 0)} cluster(s).\n\n"
            f"Clusters:\n{clusters}\n\n"
            f"Chronology:\n{timeline}\n\n"
            f"Entity counts: {context['entity_counts']}\n\n"
            "Produce evidence_bundle (evidence ids only, drawn from the ids shown above), "
            "relationships between entities, a timeline, and missing_information — the specific "
            "things you would need to reach a firmer conclusion."
        )

    # --- offline path -------------------------------------------------------------------

    def _relationships(self, context: dict) -> list[Relationship]:
        entities = context["top_entities"]
        out: list[Relationship] = []
        for i, (type_a, value_a, _) in enumerate(entities[:6]):
            for type_b, value_b, _ in entities[i + 1 : 6]:
                if type_a == type_b:
                    continue
                out.append(
                    Relationship(
                        source=f"{type_a}:{value_a}",
                        target=f"{type_b}:{value_b}",
                        relation="co-observed on the same incident",
                    )
                )
        return out[:20]

    def _missing(self, context: dict) -> list[str]:
        present = set(context["entity_counts"])
        gaps = [
            f"no {entity_type} entity recorded on this incident"
            for entity_type in ENTITY_COLUMNS
            if entity_type not in present
        ]
        if not context["timeline"]:
            gaps.append("no usable timestamps, so no chronology could be built")
        if not context["clusters"]:
            gaps.append("alerts did not cluster; no shared entity linked them")
        return gaps[:15]

    def fallback(self, context: dict) -> CorrelationOutput:
        return CorrelationOutput(
            evidence_bundle=context["evidence_ids"][:MAX_BUNDLE] or ["EVD-none"],
            relationships=self._relationships(context),
            timeline=[
                TimelineEvent(
                    timestamp=row["timestamp"],
                    description=row["description"][:400],
                    evidence_id=row["evidence_id"],
                )
                for row in context["timeline"][:40]
            ],
            missing_information=self._missing(context),
        )
