"""The three showcase scenarios from §12.2, as constructible workflow states.

    1. True positive  — multi-evidence compromise, Verifier agrees, high-risk action blocks
                        for human approval.
    2. False positive — noisy detector with benign history; the system recommends closure and
                        takes no invasive action.
    3. Conflict       — remediation is disproportionate and under-evidenced; the Verifier rejects
                        it, and the failed proposal is recorded anyway.

The third is the one worth building the demo around. Most teams show their system succeeding;
showing it catching its own failure is what separates a prototype from something a SOC would
actually put in the loop. It is therefore an executable test, not a slide.
"""

from __future__ import annotations

from app.agents.schemas import (
    CorrelationOutput,
    DetectionOutput,
    InvestigationOutput,
    MitreMapping,
    RemediationOutput,
    RiskLevel,
    SimilarCase,
    SuspiciousEntity,
    TimelineEvent,
    TriageLabel,
    TriageOutput,
    WorkflowState,
)

EVIDENCE = [f"EVD-{i:04d}" for i in range(1, 9)]


def _detection(severity: float) -> DetectionOutput:
    return DetectionOutput(
        severity_score=severity,
        suspicious_entities=[
            SuspiciousEntity(
                entity_type="account", value="alice@contoso.com", reason="repeated failed sign-ins"
            ),
            SuspiciousEntity(
                entity_type="device", value="dev-014", reason="executed an encoded command line"
            ),
        ],
        initial_reason=f"Initial severity {severity:.2f} from detector verdicts.",
    )


def _correlation(missing: list[str], bundle: list[str] | None = None) -> CorrelationOutput:
    return CorrelationOutput(
        evidence_bundle=bundle or EVIDENCE,
        relationships=[],
        timeline=[
            TimelineEvent(
                timestamp="2026-08-07T09:00:00+00:00",
                description="first alert raised",
                evidence_id=EVIDENCE[0],
            )
        ],
        missing_information=missing,
    )


def _investigation(similar: int, techniques: list[str]) -> InvestigationOutput:
    return InvestigationOutput(
        similar_cases=[
            SimilarCase(
                incident_id=f"INC-similar{i}",
                similarity=0.8 - (i * 0.05),
                why_similar="shares account and device",
            )
            for i in range(similar)
        ],
        mitre_mapping=[
            MitreMapping(
                technique_id=t,
                technique_name=t,
                supporting_evidence_ids=EVIDENCE[:3],
            )
            for t in techniques
        ],
        investigation_summary="Investigation summary for the scenario fixture.",
    )


def _state(name: str) -> WorkflowState:
    return WorkflowState(
        workflow_id=f"WF-{name}",
        incident_id=f"INC-{name}",
        evidence_ids=EVIDENCE,
        correlation_clusters=1,
    )


# --- scenario 1: true positive, verifier agrees, high risk blocks -------------------------------

def true_positive() -> WorkflowState:
    """Well-evidenced compromise. The chain is sound; the *action* is what needs a human."""
    state = _state("truepositive")
    state.detection = _detection(0.92)
    state.correlation = _correlation(missing=[])
    state.investigation = _investigation(similar=4, techniques=["T1078", "T1059"])
    state.triage = TriageOutput(
        label=TriageLabel.TRUE_POSITIVE,
        confidence=0.93,
        rationale=(
            "Multiple independent detectors flagged the same account and device within a "
            "20-minute window, with credential access followed by lateral movement."
        ),
        supporting_evidence_ids=EVIDENCE[:6],
    )
    state.remediation = RemediationOutput(
        recommended_action="isolate_device",
        action_risk=RiskLevel.HIGH,
        rollback_plan="Release the isolation.",
        justification="Containment is proportionate to a well-evidenced active compromise.",
    )
    return state


# --- scenario 2: false positive, closed without invasive action ---------------------------------

def false_positive() -> WorkflowState:
    """Noisy detector, benign history. The right answer is to close it and touch nothing."""
    state = _state("falsepositive")
    state.detection = _detection(0.22)
    state.correlation = _correlation(missing=[])
    state.investigation = _investigation(similar=5, techniques=["T1059"])
    state.triage = TriageOutput(
        label=TriageLabel.FALSE_POSITIVE,
        confidence=0.91,
        rationale=(
            "The command line matches a signed deployment script seen in five previous "
            "incidents, all closed as false positives by analysts."
        ),
        supporting_evidence_ids=EVIDENCE[:4],
    )
    state.remediation = RemediationOutput(
        recommended_action="close_as_false_positive",
        action_risk=RiskLevel.LOW,
        rollback_plan="Reopen the incident; no system state was changed.",
        justification="No action is warranted; closing with the rationale attached.",
    )
    return state


# --- scenario 3: conflict — the verifier rejects its own team -----------------------------------

def conflict() -> WorkflowState:
    """Disproportionate and under-evidenced.

    Three things are wrong at once, and each one alone should be enough:

    * a **high-risk** containment action proposed on a **FalsePositive**, which the catalogue says
      it does not apply to;
    * triage citing an evidence id (``EVD-9999``) that is not in the correlation bundle;
    * high confidence asserted while correlation reported unresolved gaps.

    The Verifier must reject this, and the failed proposal must still be recorded — a rejected
    recommendation is part of the audit trail, not something to quietly discard.
    """
    state = _state("conflict")
    state.detection = _detection(0.35)
    state.correlation = _correlation(
        missing=[
            "no process lineage captured for the flagged command",
            "device telemetry unavailable for the relevant window",
        ]
    )
    state.investigation = _investigation(similar=0, techniques=[])
    state.triage = TriageOutput(
        label=TriageLabel.FALSE_POSITIVE,
        confidence=0.94,
        rationale="Asserted with high confidence despite acknowledged gaps in the evidence.",
        supporting_evidence_ids=[EVIDENCE[0], "EVD-9999"],  # the second is not in the bundle
    )
    state.remediation = RemediationOutput(
        recommended_action="disable_account",
        action_risk=RiskLevel.HIGH,
        rollback_plan="Re-enable the account.",
        justification="Disproportionate response for a finding classified as a false positive.",
    )
    return state


SCENARIOS = {
    "true_positive": true_positive,
    "false_positive": false_positive,
    "conflict": conflict,
}
