"""Remediation agent — propose a containment action.

Input: triage result plus the policy catalogue.
Output: ``recommended_action``, ``action_risk``, ``rollback_plan``, ``justification`` (§6.1).

**Every action here is simulated.** Nothing in this repository isolates a device, disables an
account or touches a real system. The agent proposes; the deterministic policy gate decides
whether a human has to sign off; nothing executes either way.

The agent chooses from the catalogue rather than free-forming an action. That is what makes the
downstream gate meaningful — a proposal outside the catalogue has no risk level, no rollback and
no applicability rules, so `engine.evaluate()` treats it as *unknown*, which is worse than
high-risk rather than better than it.
"""

from __future__ import annotations

from app.agents.base import Agent
from app.agents.schemas import RemediationOutput, RiskLevel, TriageLabel, WorkflowState
from app.orchestration.context import IncidentContext
from app.policies import engine


class RemediationAgent(Agent):
    name = "remediation"
    output_model = RemediationOutput
    role = (
        "Response planning. Given the triage result, choose the single most appropriate action "
        "from the catalogue supplied, state its risk level, and give a rollback plan. Choose the "
        "least invasive action that actually addresses the finding — proposing device isolation "
        "for a low-confidence benign positive is a worse error than proposing monitoring for a "
        "genuine compromise, because the first one is the kind of mistake that stops an "
        "organisation trusting the system at all. Use only action ids from the catalogue."
    )

    def build_context(self, state: WorkflowState, context: IncidentContext = None, **kwargs):
        assert context is not None
        label = state.triage.label.value if state.triage else TriageLabel.BENIGN_POSITIVE.value
        applicable = engine.actions_for_label(label)

        return {
            "incident_id": context.incident_id,
            "label": label,
            "confidence": state.triage.confidence if state.triage else 0.0,
            "rationale": state.triage.rationale if state.triage else "",
            "severity": state.detection.severity_score if state.detection else 0.5,
            "missing": state.correlation.missing_information if state.correlation else [],
            "techniques": (
                [m.technique_id for m in state.investigation.mitre_mapping]
                if state.investigation
                else []
            ),
            "entity_counts": context.entity_counts(),
            "catalogue_block": engine.catalogue_prompt_block(),
            "applicable_ids": [a["id"] for a in applicable],
            "applicable": applicable,
        }

    def build_prompt(self, context: dict) -> str:
        gaps = "; ".join(context["missing"][:5]) or "none reported"
        return (
            f"Incident {context['incident_id']}\n\n"
            f"Triage: {context['label']} at {context['confidence']:.2f} confidence.\n"
            f"Rationale: {context['rationale'][:700]}\n"
            f"Detection severity: {context['severity']:.2f}\n"
            f"MITRE techniques: {', '.join(context['techniques'][:8]) or 'none'}\n"
            f"Evidence gaps: {gaps}\n"
            f"Entities involved: {context['entity_counts'] or 'none recorded'}\n\n"
            f"Action catalogue (choose exactly one id):\n{context['catalogue_block']}\n\n"
            f"Actions applicable to {context['label']}: "
            f"{', '.join(context['applicable_ids']) or 'none'}\n\n"
            "Return recommended_action (a catalogue id), action_risk matching that action's "
            "risk level, rollback_plan and justification. All actions are simulated."
        )

    # --- offline path -------------------------------------------------------------------

    def fallback(self, context: dict) -> RemediationOutput:
        """Pick the least invasive applicable action, and get *more* cautious as evidence thins.

        Note the direction: low confidence leads to a *weaker* action, not a stronger one. The
        instinct to "escalate when unsure" is wrong here — an uncertain finding does not justify
        disabling somebody's account, it justifies watching more closely and asking a human.
        """
        applicable = context["applicable"]
        label = context["label"]
        confidence = context["confidence"]

        if not applicable:
            return RemediationOutput(
                recommended_action="monitor_and_watchlist",
                action_risk=RiskLevel.LOW,
                rollback_plan="Remove the watchlist entry.",
                justification=(
                    f"No catalogue action is applicable to {label}, so the safest available "
                    "response is enhanced monitoring pending analyst review."
                ),
            )

        risk_rank = {"low": 0, "medium": 1, "high": 2}
        ordered = sorted(applicable, key=lambda a: (risk_rank[a["risk"]], a["id"]))

        if label == TriageLabel.TRUE_POSITIVE.value and confidence >= 0.85 and not context["missing"]:
            # Strong, well-evidenced true positive: the most decisive applicable action.
            chosen = ordered[-1]
            reason = (
                f"High-confidence true positive ({confidence:.2f}) with no reported evidence "
                "gaps, so a containment action is proportionate."
            )
        elif label == TriageLabel.TRUE_POSITIVE.value:
            mid = [a for a in ordered if a["risk"] == "medium"]
            chosen = mid[0] if mid else ordered[0]
            reason = (
                f"True positive at {confidence:.2f} confidence with "
                f"{len(context['missing'])} evidence gap(s); a reversible intermediate action is "
                "proportionate to what is actually established."
            )
        else:
            chosen = ordered[0]
            reason = (
                f"{label} at {confidence:.2f} confidence does not justify an invasive action; "
                f"{chosen['id']} is the least disruptive applicable response."
            )

        return RemediationOutput(
            recommended_action=chosen["id"],
            action_risk=RiskLevel(chosen["risk"]),
            rollback_plan=str(chosen.get("rollback", "No system state is changed."))[:1000],
            justification=(
                f"Rule-based remediation for {context['incident_id']}. {reason} "
                f"Selected {chosen['id']} ({chosen['risk']} risk): {chosen.get('description', '')} "
                "This action is simulated and is not executed against any system."
            )[:1500],
        )
