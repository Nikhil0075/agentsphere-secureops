"""Detection agent — initial severity and suspicious entities.

Input: raw incident fields and detector metadata.
Output: ``severity_score``, ``suspicious_entities``, ``initial_reason`` (§6.1).
"""

from __future__ import annotations

from app.agents.base import Agent
from app.agents.schemas import DetectionOutput, SuspiciousEntity, WorkflowState
from app.data.summarize import build_evidence_block
from app.orchestration.context import IncidentContext

_SUSPICION_WEIGHT = {"Malicious": 1.0, "Incriminated": 0.9, "Suspicious": 0.65, "Benign": 0.1}
_VERDICT_WEIGHT = {
    "Malicious": 1.0,
    "Suspicious": 0.65,
    "Clean": 0.1,
    "NoThreatsFound": 0.05,
}


class DetectionAgent(Agent):
    name = "detection"
    output_model = DetectionOutput
    role = (
        "Triage intake. Read the raw incident and its detector metadata, assign an initial "
        "severity between 0 and 1, and list the entities that warrant investigation. You are "
        "not deciding whether this is a true positive — that is the Triage agent's job. You are "
        "deciding what deserves attention and why."
    )

    def build_context(self, state: WorkflowState, context: IncidentContext = None, **kwargs):
        assert context is not None
        return {
            "incident_id": context.incident_id,
            "summary": context.summary,
            "evidence_block": build_evidence_block(context.evidence, limit=20),
            "evidence_ids": context.evidence_ids,
            "top_entities": context.top_entities(8),
            # The grounding allowlist, which must cover everything the prompt exposes -- the
            # evidence block shows entities beyond the top 8, and validating against the summary
            # alone rejected genuine citations as invented.
            "known_entities": context.all_entity_values(),
            "entity_counts": context.entity_counts(),
            "suspicion": context.suspicion_profile(),
            "alert_count": int(context.incident_fields.get("alert_count", 0) or 0),
            "evidence_count": int(context.incident_fields.get("evidence_count", 0) or 0),
            "detector": context.incident_fields.get("top_detector", ""),
            "category": context.incident_fields.get("top_category", ""),
            "baseline_tp": context.baseline_tp_probability(),
        }

    def build_prompt(self, context: dict) -> str:
        entities = "\n".join(
            f"- {t}:{v} (on {n} evidence row(s))" for t, v, n in context["top_entities"]
        ) or "- none recorded"
        suspicion = (
            ", ".join(f"{k}={v}" for k, v in sorted(context["suspicion"].items()))
            or "no detector verdicts recorded"
        )
        return (
            f"Incident {context['incident_id']}\n\n"
            f"{context['summary']}\n\n"
            f"Detector verdict counts: {suspicion}\n"
            f"Category: {context['category'] or 'unknown'}; "
            f"detector: {context['detector'] or 'unknown'}\n\n"
            f"Most frequently observed entities:\n{entities}\n\n"
            f"Evidence sample (cite these ids):\n{context['evidence_block']}\n\n"
            "Assign severity_score in [0,1], list the suspicious entities with a specific reason "
            "for each, and give initial_reason. Do not claim anything the evidence above does "
            "not show."
        )

    # --- offline path -------------------------------------------------------------------

    def _severity(self, context: dict) -> float:
        """Blend detector verdicts with the non-LLM baseline.

        Detector verdicts are the strongest available signal in GUIDE, but they are also the
        signal that produced the alert in the first place, so leaning on them alone just restates
        the detector's opinion. The baseline probability is mixed in to add an independent view.
        """
        best = 0.0
        for key, count in context["suspicion"].items():
            if not count:
                continue
            _, _, value = key.partition(":")
            weight = _SUSPICION_WEIGHT.get(value) or _VERDICT_WEIGHT.get(value, 0.0)
            best = max(best, weight)
        if best == 0.0:
            best = 0.3  # nothing recorded: mildly suspicious, not benign

        breadth = min(1.0, context["evidence_count"] / 50.0)
        score = 0.55 * best + 0.30 * context["baseline_tp"] + 0.15 * breadth
        return round(min(1.0, max(0.0, score)), 4)

    def _entities(self, context: dict) -> list[SuspiciousEntity]:
        return [
            SuspiciousEntity(
                entity_type=entity_type,
                value=value,
                reason=f"observed on {count} evidence row(s) in this incident",
            )
            for entity_type, value, count in context["top_entities"][:10]
        ]

    def fallback(self, context: dict) -> DetectionOutput:
        return DetectionOutput(
            severity_score=self._severity(context),
            suspicious_entities=self._entities(context),
            initial_reason=(
                f"Rule-based intake for {context['incident_id']}: "
                f"{context['alert_count']} alert(s), {context['evidence_count']} evidence "
                f"item(s), category {context['category'] or 'unknown'}. Detector verdicts: "
                + (
                    ", ".join(f"{k}={v}" for k, v in sorted(context["suspicion"].items()))
                    or "none recorded"
                )
                + ". Severity is derived from detector verdicts, the non-LLM baseline "
                "probability and evidence breadth."
            ),
        )
