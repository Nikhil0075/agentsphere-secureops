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
        # The chronology is capped, and the cap used to be silent. Downstream agents were told
        # "26 evidence item(s)" and then shown 12 chronology rows, which the Verifier reported as
        # an accounting inconsistency rather than as a display limit — because from where it sat,
        # that is exactly what it looked like. Disclose the cap and the mismatch disappears.
        shown = context["timeline"][:12]
        timeline = "\n".join(
            f"- {row['timestamp']} [{row['evidence_id']}] {row['description']}" for row in shown
        ) or "- no usable timestamps"
        if len(context["timeline"]) > len(shown):
            timeline += (
                f"\n- ... {len(context['timeline']) - len(shown)} further dated event(s) not "
                "shown here; this is a display limit, not missing data"
            )
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
            "things you would need to reach a firmer conclusion.\n\n"
            "For missing_information, list only gaps that would change your conclusion. An entity "
            "type that does not appear above is not a gap: each evidence row carries only the "
            "fields its source product emits, so most incidents legitimately have two or three "
            "types and no more. Do not list absent entity types. If nothing genuinely limits the "
            "conclusion, return an empty list."
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
        """Gaps that would actually change a conclusion — not the shape of the telemetry.

        This used to emit one gap per *absent* entity type, all seven of them checked against
        every incident. Measured across the 5,000-incident corpus that is a mean of **5.26
        manufactured gaps each**: only 5 incidents carry all seven types, 53.2% carry one or
        none. GUIDE is evidence-level and each row holds only the fields its source product
        emits, so a mailbox alert has no file hash and never will. Reporting that absence as
        missing information asserts an investigative hole on 99.9% of incidents.

        The cost was not cosmetic. ``missing_information`` is rendered into the Investigation,
        Triage, Remediation and Verifier prompts, and the field caps at 15 entries — so five-odd
        fabricated gaps both crowded out the real ones and told four downstream agents, on every
        incident, that the evidence was incomplete. Agents asked to reason about an incident
        described as full of holes hedge and escalate, which is precisely what the gate measured.

        What remains are conditions that genuinely limit the conclusion: no entities to pivot on,
        no chronology, nothing linking the alerts, or a single uncorroborated source.
        """
        gaps: list[str] = []
        counts = context["entity_counts"]

        if not counts:
            # Distinct from the sparse case: there is nothing to pivot on at all.
            gaps.append(
                "no entities of any type were extracted, so this incident cannot be pivoted on "
                "or linked to any other"
            )
        elif len(counts) == 1:
            only = next(iter(counts))
            gaps.append(
                f"every entity on this incident is of one type ({only}); there is no second "
                "observable to corroborate against"
            )

        if not context["timeline"]:
            gaps.append("no usable timestamps, so no chronology could be built")
        if not context["clusters"]:
            gaps.append("alerts did not cluster; no shared entity linked them")
        elif len(context["clusters"]) > 1 and not any(
            c["linking_entities"] for c in context["clusters"]
        ):
            gaps.append(
                "clusters were formed on time proximity alone, with no shared entity joining them"
            )

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
