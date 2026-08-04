"""Triage agent — the TP/BP/FP call.

Input: investigation output plus the non-LLM baseline score.
Output: ``label``, ``confidence``, ``rationale``, ``supporting_evidence_ids`` (§6.1).

This is the agent the metrics are computed on, so two properties are enforced rather than
requested. It must cite evidence ids that exist in the bundle — the policy gate rejects the
decision otherwise (POL-002) — and it never sees the ground-truth label, from the incident record,
from the retrieved similar cases, or from the summary.

The baseline probability is supplied deliberately. An agent that disagrees with a calibrated
classifier should have to do so knowingly and say why, and the disagreement rate between the two
is itself a metric worth showing (§13.2).
"""

from __future__ import annotations

from app.agents.base import Agent
from app.agents.schemas import TriageLabel, TriageOutput, WorkflowState
from app.orchestration.context import IncidentContext

MAX_CITED = 12


class TriageAgent(Agent):
    name = "triage"
    output_model = TriageOutput
    role = (
        "Classification. Decide whether this incident is a TruePositive, a BenignPositive or a "
        "FalsePositive, state a calibrated confidence, and cite the specific evidence ids that "
        "support the call. A BenignPositive is real activity that is authorised or expected; a "
        "FalsePositive is a detection that did not reflect what actually happened. If the "
        "evidence is thin, lower the confidence rather than picking a safer-sounding label."
    )

    def build_context(self, state: WorkflowState, context: IncidentContext = None, **kwargs):
        assert context is not None
        bundle = (
            state.correlation.evidence_bundle if state.correlation else context.evidence_ids
        )
        baseline = context.baseline or {}
        return {
            "incident_id": context.incident_id,
            "summary": context.summary,
            "evidence_bundle": bundle[:50],
            "severity": state.detection.severity_score if state.detection else 0.5,
            "investigation_summary": (
                state.investigation.investigation_summary if state.investigation else ""
            ),
            "similar_count": (
                len(state.investigation.similar_cases) if state.investigation else 0
            ),
            "techniques": (
                [m.technique_id for m in state.investigation.mitre_mapping]
                if state.investigation
                else []
            ),
            "missing": state.correlation.missing_information if state.correlation else [],
            "baseline_label": baseline.get("label", ""),
            "baseline_confidence": float(baseline.get("confidence", 0.0) or 0.0),
            "baseline_probabilities": baseline.get("probabilities", {}),
            "baseline_model": baseline.get("model_name", ""),
            "suspicion": context.suspicion_profile(),
        }

    def build_prompt(self, context: dict) -> str:
        probabilities = (
            ", ".join(f"{k}={v:.2f}" for k, v in sorted(context["baseline_probabilities"].items()))
            or "unavailable"
        )
        gaps = "; ".join(context["missing"][:5]) or "none reported"
        return (
            f"Incident {context['incident_id']}\n\n"
            f"{context['summary']}\n\n"
            f"Detection severity: {context['severity']:.2f}\n"
            f"Detector verdict counts: "
            f"{', '.join(f'{k}={v}' for k, v in sorted(context['suspicion'].items())) or 'none'}\n"
            f"Investigation: {context['investigation_summary'][:900]}\n"
            f"MITRE techniques mapped: {', '.join(context['techniques'][:8]) or 'none'}\n"
            f"Evidence gaps: {gaps}\n\n"
            f"Non-LLM baseline ({context['baseline_model'] or 'unavailable'}) predicts "
            f"{context['baseline_label'] or 'nothing'} at "
            f"{context['baseline_confidence']:.2f} confidence. Class probabilities: "
            f"{probabilities}. You may disagree with it, but if you do, say why.\n\n"
            f"Evidence ids you may cite: {', '.join(context['evidence_bundle'][:25])}\n\n"
            "Return label, confidence, rationale and supporting_evidence_ids. Every cited id "
            "must appear in the list above."
        )

    # --- offline path -------------------------------------------------------------------

    def fallback(self, context: dict) -> TriageOutput:
        """Follow the baseline, and discount confidence for what is missing.

        This is the conservative choice on purpose: with no model available, deferring to the
        calibrated classifier and lowering confidence for evidence gaps is defensible, whereas
        inventing a label from heuristics would not be.
        """
        label = context["baseline_label"] or TriageLabel.BENIGN_POSITIVE.value
        confidence = context["baseline_confidence"] or 0.4

        if context["missing"]:
            confidence *= 0.85
        if not context["evidence_bundle"]:
            confidence *= 0.7
        if context["similar_count"] == 0:
            confidence *= 0.95
        confidence = round(min(0.99, max(0.05, confidence)), 4)

        cited = context["evidence_bundle"][:MAX_CITED] or ["EVD-none"]

        return TriageOutput(
            label=TriageLabel(label),
            confidence=confidence,
            rationale=(
                f"Rule-based triage for {context['incident_id']}. Deferred to the non-LLM "
                f"baseline ({context['baseline_model'] or 'unavailable'}), which predicts "
                f"{label} at {context['baseline_confidence']:.2f}. Detection severity was "
                f"{context['severity']:.2f} and "
                f"{context['similar_count']} similar historical incident(s) were retrieved. "
                f"Confidence was reduced for {len(context['missing'])} recorded evidence gap(s). "
                f"Cited evidence: {', '.join(cited[:5])}."
            )[:1500],
            supporting_evidence_ids=cited,
        )
