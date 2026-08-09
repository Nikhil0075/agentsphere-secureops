"""Verifier agent — the independent check that can reject its own team.

Input: all prior outputs.
Output: ``verdict``, ``contradictions``, ``policy_checks``, ``escalation_required``, ``reasoning``.

This is the agent the whole "not an LLM wrapper" claim rests on, so two things about it matter more
than its prose quality.

**It must be able to say no.** A verifier that accepts everything is decoration. Its offline path
runs seven concrete structural checks against the earlier agents' outputs, and any hard failure
produces ``reject`` regardless of how confident the chain sounded. §12.2 calls the conflict
scenario the most persuasive part of the demo precisely because most teams only show their system
succeeding.

**It is not the policy gate.** This agent *reasons* about whether the recommendation holds up; the
deterministic engine in ``app/policies/engine.py`` *decides* whether it may proceed without a
human. An agent cannot argue its way past a dictionary lookup. Keeping those separate is what makes
the autonomy boundary a control rather than a suggestion.
"""

from __future__ import annotations

from app.agents.base import Agent
from app.agents.schemas import (
    PolicyCheck,
    TriageLabel,
    VerifierOutput,
    VerifierVerdict,
    WorkflowState,
)
from app.data.summarize import build_evidence_block
from app.orchestration.context import IncidentContext
from app.policies import engine

#: A confidence this high has to be earned; above it, unreported gaps become a contradiction.
HIGH_CONFIDENCE = 0.85

#: Below this, a chain should not be claiming a decisive answer at all.
LOW_CONFIDENCE = 0.40

#: How many reported evidence gaps are normal rather than disqualifying. GUIDE's median incident
#: has one evidence row, so "no device entity recorded" is the dataset speaking, not the chain
#: overreaching. Above this, thinness becomes a genuine concern.
GAP_TOLERANCE = 3

# The model may contribute semantic judgement only through this small, documented vocabulary.
# Deterministic VER-* checks below remain authoritative for set membership and policy lookups.
SEMANTIC_CHECKS = {
    "SEM-001": "Evidence directly contradicts the assigned label or stated rationale",
    "SEM-002": "The agent chain materially contradicts itself",
    "SEM-003": "The recommended action is unsupported or disproportionate",
    "SEM-004": "Confidence is materially miscalibrated to the evidence and stated gaps",
}
SEMANTIC_REJECT_CHECKS = frozenset({"SEM-001", "SEM-002"})


class VerifierAgent(Agent):
    name = "verifier"
    output_model = VerifierOutput
    role = (
        "Independent consistency and safety verification. Do not re-run triage and do not decide "
        "whether an action may auto-execute; the deterministic policy gate does that. Check "
        "direct evidence contradiction, internal chain consistency, action proportionality, and "
        "confidence calibration using only SEM-001 through SEM-004. Accept means safe to send to "
        "the deterministic gate, not that the label is certain. Sparse or anonymised fields, an "
        "unexplained baseline, missing evidence outside the correlation bundle, and lack of "
        "affirmative proof of benignity are not contradictions by themselves; uncertainty should "
        "already be represented by confidence."
    )

    def build_context(self, state: WorkflowState, context: IncidentContext = None, **kwargs):
        assert context is not None
        bundle = state.correlation.evidence_bundle if state.correlation else []
        action = (
            engine.action_by_id(state.remediation.recommended_action)
            if state.remediation
            else None
        )
        return {
            "incident_id": context.incident_id,
            "summary": context.summary,
            # The evidence itself. `build_evidence_block`'s docstring has always said it exists
            # "so an agent can cite it and the Verifier can check the citation later" -- it was
            # simply never wired in here. Without it the model is asked to certify citations it
            # cannot see, and it correctly refuses: measured escalation was 97.5% live against
            # 5.0% on the deterministic backend, on incidents whose structural checks all passed.
            #
            # Scoped to the correlation bundle, not to the first 25 rows of the incident. Showing
            # 25 arbitrary records against a 12-id bundle reads as an inconsistency, and the model
            # said so: "the gaps say the chronology contains only 12 evidence IDs, while 25
            # evidence records are displayed". The verifier should see exactly what was in scope.
            "evidence_block": build_evidence_block(
                context.evidence[context.evidence["evidence_id"].isin(bundle)]
                if bundle
                else context.evidence,
                limit=30,
            ),
            "label": state.triage.label.value if state.triage else "",
            "confidence": state.triage.confidence if state.triage else 0.0,
            "rationale": state.triage.rationale if state.triage else "",
            "cited": list(state.triage.supporting_evidence_ids) if state.triage else [],
            "bundle": list(bundle),
            "incident_evidence_count": int(len(context.evidence)),
            # The deterministic Union-Find result. Without it the Verifier could read Correlation
            # asserting "26 alerts across 18 clusters" and had no way to check the claim, so it
            # recorded the figure as unsupported — a contradiction manufactured purely by what it
            # was not shown. The clustering is an algorithm whose output is checkable; show it.
            "correlation_summary": (
                context.correlation.as_dict() if context.correlation else {}
            ),
            "missing": state.correlation.missing_information if state.correlation else [],
            "severity": state.detection.severity_score if state.detection else 0.0,
            "similar_count": (
                len(state.investigation.similar_cases) if state.investigation else 0
            ),
            "mitre_count": (
                len(state.investigation.mitre_mapping) if state.investigation else 0
            ),
            "action": state.remediation.recommended_action if state.remediation else "",
            "action_risk": state.remediation.action_risk.value if state.remediation else "",
            "catalogue_action": action,
            "action_in_catalogue": action is not None,
            "applicable_labels": (action or {}).get("applicable_labels", []),
            "baseline_label": state.baseline.label.value if state.baseline else "",
            "baseline_confidence": state.baseline.confidence if state.baseline else 0.0,
            "degraded_agents": [r.agent for r in state.runs if r.status != "ok"],
        }

    def build_prompt(self, context: dict) -> str:
        unknown = [e for e in context["cited"] if e not in set(context["bundle"])]
        return (
            f"Incident {context['incident_id']} — verify the chain below.\n\n"
            f"{context['summary']}\n\n"
            # The label has to match the scope. This block is the *correlation bundle*, not the
            # incident, so calling it "Evidence available to this incident" under a summary
            # reading "26 evidence item(s)" invited the exact complaint it drew: 26 claimed, 20
            # shown. Naming the scope costs nothing and removes the contradiction.
            f"Evidence in the correlation bundle ({len(context['bundle'])} of "
            f"{context['incident_evidence_count']} item(s) on this incident) — the Triage "
            f"citations must come from here:\n{context['evidence_block']}\n\n"
            f"Detection severity: {context['severity']:.2f}\n"
            f"Triage: {context['label']} at {context['confidence']:.2f}\n"
            f"Rationale: {context['rationale'][:800]}\n"
            f"Union-Find clustering (deterministic, computed before the chain ran): "
            f"{context['correlation_summary'].get('alerts', 0)} alert(s) collapsed into "
            f"{context['correlation_summary'].get('clusters', 0)} cluster(s)\n"
            f"Correlation bundle ({len(context['bundle'])} id(s)): "
            f"{', '.join(context['bundle'][:25]) or 'none'}\n"
            f"Evidence cited by triage ({len(context['cited'])} id(s)): "
            f"{', '.join(context['cited'][:25]) or 'none'}\n"
            f"Cited but NOT in the correlation bundle: "
            f"{', '.join(unknown[:10]) if unknown else 'none'}\n"
            f"Reported evidence gaps: {'; '.join(context['missing'][:6]) or 'none'}\n"
            f"Similar incidents retrieved: {context['similar_count']}; "
            f"MITRE mappings: {context['mitre_count']}\n"
            f"Recommended action: {context['action'] or 'none'} "
            f"({context['action_risk'] or 'unknown'} risk), "
            f"{'in catalogue' if context['action_in_catalogue'] else 'NOT IN CATALOGUE'}, "
            f"applicable to {', '.join(context['applicable_labels']) or 'nothing'}\n"
            f"Non-LLM baseline: {context['baseline_label'] or 'unavailable'} at "
            f"{context['baseline_confidence']:.2f}\n"
            f"Agents that degraded to a fallback: "
            f"{', '.join(context['degraded_agents']) or 'none'}\n\n"
            "Run exactly these four semantic checks and return each id exactly once:\n"
            "- SEM-001: fail only when supplied evidence directly contradicts the label or its "
            "rationale; missing affirmative proof is not a contradiction.\n"
            "- SEM-002: fail only for a material contradiction between agent outputs.\n"
            "- SEM-003: fail only when the simulated action is materially unsupported or "
            "disproportionate; catalogue membership and applicability are checked in code.\n"
            "- SEM-004: fail only when confidence materially overstates the supplied evidence and "
            "reported gaps; low confidence is not itself a contradiction.\n\n"
            "Use accept when all four pass. Use reject only for failed SEM-001 or SEM-002. Use "
            "escalate for failed SEM-003 or SEM-004 without a direct contradiction. Put only "
            "material contradictions tied to failed checks in contradictions. Return verdict, "
            "contradictions, policy_checks, escalation_required, and reasoning."
        )

    def validate_grounding(self, output: VerifierOutput, context: dict) -> None:
        """Require the semantic rubric before accepting a model-produced verifier result.

        The frozen schema can only say ``policy_id: str``. This content guardrail supplies the
        missing enum without changing that contract, so an omitted rubric gets one normal agent
        retry and then the conservative structural fallback. Deterministic output carries VER-*
        checks instead and is already the structural result, so it is accepted directly.
        """
        super().validate_grounding(output, context)
        ids = [check.policy_id for check in output.policy_checks]
        if all(f"VER-{index:03d}" in ids for index in range(1, 8)):
            return
        missing = sorted(set(SEMANTIC_CHECKS) - set(ids))
        duplicates = sorted(
            policy_id for policy_id in SEMANTIC_CHECKS if ids.count(policy_id) > 1
        )
        if missing or duplicates:
            problems = []
            if missing:
                problems.append("missing " + ", ".join(missing))
            if duplicates:
                problems.append("duplicated " + ", ".join(duplicates))
            raise ValueError("invalid verifier semantic rubric: " + "; ".join(problems))

        failed = {
            check.policy_id
            for check in output.policy_checks
            if check.policy_id in SEMANTIC_CHECKS and not check.passed
        }
        expected = (
            VerifierVerdict.REJECT
            if failed & SEMANTIC_REJECT_CHECKS
            else VerifierVerdict.ESCALATE
            if failed
            else VerifierVerdict.ACCEPT
        )
        if output.verdict is not expected:
            raise ValueError(
                f"verdict {output.verdict.value} conflicts with semantic checks; "
                f"expected {expected.value}"
            )
        expected_escalation = expected is not VerifierVerdict.ACCEPT
        if output.escalation_required != expected_escalation:
            raise ValueError("escalation_required conflicts with the semantic verdict")
        direct_contradiction = bool(failed & SEMANTIC_REJECT_CHECKS)
        if direct_contradiction and not output.contradictions:
            raise ValueError("failed SEM-001/SEM-002 requires a material contradiction")
        if not direct_contradiction and output.contradictions:
            raise ValueError(
                "contradictions require failed SEM-001/SEM-002; SEM-003/SEM-004 are "
                "escalation concerns"
            )

    # --- reconciliation: the structural checks always run --------------------------------

    def reconcile(self, output: VerifierOutput, context: dict) -> VerifierOutput:
        """Bound the model's verdict by the deterministic checks.

        A live model left to its own devices invents policy ids and rejects on taste. Measured on
        40 GUIDE incidents it rejected 40 of them, citing "evidence gaps" — on a dataset whose
        median incident carries exactly one evidence row, that is a property of the data, not a
        fault in the reasoning. A verifier that rejects everything is exactly as useless as one
        that accepts everything.

        So the structural checks run in code on every backend, and the model's judgement is
        layered on top under three rules:

        * a hard structural failure is a rejection, whatever the model concluded;
        * semantic judgement is actionable only through the fixed SEM-* rubric;
        * vague uncertainty and invented policy ids remain visible but cannot create a hidden
          autonomy rule.

        Unknown model checks are kept with an ``LLM-`` prefix so the audit remains complete.
        """
        structural = self._structural(context)
        structural_ids = {c.policy_id for c in structural.policy_checks}

        # On the deterministic backend the model output *is* the structural output, so its checks
        # would otherwise be re-listed as LLM-VER-001…007 beside the originals. Anything the
        # structural pass already produced is dropped rather than duplicated.
        model_checks = [
            PolicyCheck(
                policy_id=(
                    c.policy_id
                    if c.policy_id in SEMANTIC_CHECKS
                    else f"LLM-{c.policy_id}"
                )[:64],
                passed=c.passed,
                detail=c.detail,
            )
            for c in output.policy_checks
            if c.policy_id not in structural_ids
        ]
        supplied_semantic = {
            check.policy_id: check
            for check in output.policy_checks
            if check.policy_id in SEMANTIC_CHECKS
        }
        output_ids = {check.policy_id for check in output.policy_checks}
        is_structural_output = structural_ids <= output_ids
        failed_semantic = {
            policy_id
            for policy_id, check in supplied_semantic.items()
            if not check.passed
        }
        missing_semantic = (
            set() if is_structural_output else set(SEMANTIC_CHECKS) - set(supplied_semantic)
        )
        seen_contradictions = set(structural.contradictions)
        model_contradictions = (
            [c for c in output.contradictions if c not in seen_contradictions]
            if failed_semantic
            else []
        )

        if structural.verdict is VerifierVerdict.REJECT:
            verdict = VerifierVerdict.REJECT
        elif structural.verdict is VerifierVerdict.ESCALATE:
            verdict = VerifierVerdict.ESCALATE
        elif failed_semantic & SEMANTIC_REJECT_CHECKS:
            verdict = VerifierVerdict.REJECT
        elif failed_semantic or missing_semantic:
            verdict = VerifierVerdict.ESCALATE
        else:
            # Raw reject/escalate without a failed named check is not a policy. All semantic
            # checks passed, so the chain is safe to hand to the deterministic gate.
            verdict = VerifierVerdict.ACCEPT

        if missing_semantic:
            model_checks.append(
                PolicyCheck(
                    policy_id="SEM-000",
                    passed=False,
                    detail=(
                        "missing required semantic checks: "
                        + ", ".join(sorted(missing_semantic))
                    ),
                )
            )
            model_contradictions.append(
                "Verifier omitted required semantic checks: "
                + ", ".join(sorted(missing_semantic))
            )

        return VerifierOutput(
            verdict=verdict,
            contradictions=(structural.contradictions + model_contradictions)[:15],
            policy_checks=(list(structural.policy_checks) + model_checks)[:20],
            escalation_required=verdict is not VerifierVerdict.ACCEPT,
            reasoning=(
                f"{structural.reasoning} Model assessment: {output.reasoning}"
                if output.reasoning and output.reasoning != structural.reasoning
                else structural.reasoning
            )[:1500],
        )

    # --- offline path and the structural checks ------------------------------------------

    def fallback(self, context: dict) -> VerifierOutput:
        return self._structural(context)

    def _structural(self, context: dict) -> VerifierOutput:
        """Seven structural checks. Any hard failure is a rejection.

        These are deliberately checks an LLM is bad at and a program is good at: set membership,
        catalogue lookups, threshold comparisons. The agent's language ability adds nothing to
        "is this evidence id in this list", and a rule cannot be talked out of the answer.
        """
        contradictions: list[str] = []
        checks: list[PolicyCheck] = []
        hard_failure = False

        # 1. Cited evidence must exist in the bundle (mirrors POL-002).
        known = set(context["bundle"])
        unknown = [e for e in context["cited"] if e not in known] if known else []
        cited_ok = bool(context["cited"]) and not unknown
        checks.append(
            PolicyCheck(
                policy_id="VER-001",
                passed=cited_ok,
                detail=(
                    "all cited evidence is present in the bundle"
                    if cited_ok
                    else f"cited evidence absent from the bundle: {unknown[:4] or 'nothing cited'}"
                ),
            )
        )
        if not cited_ok:
            contradictions.append(
                "Triage cites evidence that is not in the correlation bundle"
                if unknown
                else "Triage cites no evidence at all"
            )
            hard_failure = True

        # 2. The action must exist in the catalogue.
        checks.append(
            PolicyCheck(
                policy_id="VER-002",
                passed=context["action_in_catalogue"],
                detail=(
                    f"{context['action']} is a catalogue action"
                    if context["action_in_catalogue"]
                    else f"{context['action']!r} is not in the action catalogue"
                ),
            )
        )
        if not context["action_in_catalogue"]:
            contradictions.append(
                f"Recommended action {context['action']!r} does not exist in the catalogue"
            )
            hard_failure = True

        # 3. The action must be applicable to the assigned label. A high-risk containment action
        #    on a FalsePositive is the disproportionate-response case from §12.2.
        applicable = context["label"] in context["applicable_labels"]
        checks.append(
            PolicyCheck(
                policy_id="VER-003",
                passed=applicable,
                detail=(
                    f"{context['action']} applies to {context['label']}"
                    if applicable
                    else f"{context['action']} is not applicable to {context['label']}"
                ),
            )
        )
        if not applicable and context["action_in_catalogue"]:
            contradictions.append(
                f"{context['action_risk']}-risk action {context['action']} proposed on a "
                f"{context['label']}, which it does not apply to"
            )
            hard_failure = True

        # 4. High confidence must not rest on acknowledged gaps.
        #
        # Calibrated to the dataset rather than to an ideal. GUIDE's median incident carries one
        # evidence row, so Correlation legitimately reports missing entity types on almost every
        # incident. Treating any gap as disqualifying rejects the whole corpus and measures
        # nothing — that is what an uncalibrated version of this check actually did, on 40 of 40.
        # A *substantial* number of gaps is still a real signal.
        gaps = len(context["missing"])
        overconfident = context["confidence"] >= HIGH_CONFIDENCE and gaps > GAP_TOLERANCE
        checks.append(
            PolicyCheck(
                policy_id="VER-004",
                passed=not overconfident,
                detail=(
                    f"confidence {context['confidence']:.2f} with {gaps} unresolved evidence "
                    f"gap(s), tolerance {GAP_TOLERANCE}"
                ),
            )
        )
        if overconfident:
            contradictions.append(
                f"Confidence of {context['confidence']:.2f} is asserted while {gaps} evidence "
                "gap(s) remain unresolved"
            )

        # 5. A high-risk action on a low-confidence finding is disproportionate.
        disproportionate = (
            context["action_risk"] == "high" and context["confidence"] < HIGH_CONFIDENCE
        )
        checks.append(
            PolicyCheck(
                policy_id="VER-005",
                passed=not disproportionate,
                detail=(
                    f"{context['action_risk'] or 'unknown'}-risk action at "
                    f"{context['confidence']:.2f} confidence"
                ),
            )
        )
        if disproportionate:
            contradictions.append(
                f"High-risk action proposed on a finding held at only "
                f"{context['confidence']:.2f} confidence"
            )

        # 6. A decisive call needs some grounding to have been retrieved.
        grounded = context["similar_count"] > 0 or context["mitre_count"] > 0
        checks.append(
            PolicyCheck(
                policy_id="VER-006",
                passed=grounded or context["confidence"] < HIGH_CONFIDENCE,
                detail=(
                    f"{context['similar_count']} similar case(s), "
                    f"{context['mitre_count']} MITRE mapping(s)"
                ),
            )
        )
        if not grounded and context["confidence"] >= HIGH_CONFIDENCE:
            contradictions.append(
                "High confidence with neither a similar historical incident nor a MITRE mapping "
                "to ground it"
            )

        # 7. A degraded agent means part of this chain was not actually reasoned.
        degraded = context["degraded_agents"]
        checks.append(
            PolicyCheck(
                policy_id="VER-007",
                passed=not degraded,
                detail=(
                    f"agents degraded to fallback: {', '.join(degraded)}"
                    if degraded
                    else "every agent completed normally"
                ),
            )
        )

        # Verdict. Hard failures reject; soft concerns escalate to a human rather than passing.
        soft = bool(contradictions) or bool(degraded) or context["confidence"] < LOW_CONFIDENCE
        if hard_failure:
            verdict = VerifierVerdict.REJECT
        elif soft:
            verdict = VerifierVerdict.ESCALATE
        else:
            verdict = VerifierVerdict.ACCEPT

        disagrees = (
            context["baseline_label"]
            and context["label"]
            and context["baseline_label"] != context["label"]
        )
        if disagrees:
            contradictions.append(
                f"Agent chain says {context['label']}; the non-LLM baseline says "
                f"{context['baseline_label']} at {context['baseline_confidence']:.2f}"
            )

        return VerifierOutput(
            verdict=verdict,
            contradictions=contradictions[:15],
            policy_checks=checks[:20],
            escalation_required=verdict is not VerifierVerdict.ACCEPT,
            reasoning=(
                f"Rule-based verification of {context['incident_id']}. "
                f"{sum(1 for c in checks if c.passed)}/{len(checks)} structural checks passed. "
                + (
                    f"Rejected: {contradictions[0]}."
                    if verdict is VerifierVerdict.REJECT
                    else f"Escalated: {contradictions[0] if contradictions else 'low confidence'}."
                    if verdict is VerifierVerdict.ESCALATE
                    else "The chain is internally consistent, the cited evidence is present, and "
                    "the recommended action is proportionate to the finding."
                )
            )[:1500],
        )


def label_is_actionable(label: str) -> bool:
    """True when a label justifies anything beyond closure or monitoring."""
    return label == TriageLabel.TRUE_POSITIVE.value
