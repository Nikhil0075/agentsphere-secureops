"""Investigation agent — similar cases, MITRE mapping, narrative.

Input: evidence bundle plus retrieved incidents.
Output: ``similar_cases``, ``mitre_mapping``, ``investigation_summary`` (§6.1).

Retrieval today is entity overlap; Day 4 swaps in BM25 + FAISS fused with RRF behind the same
interface. Note what the retrieved records deliberately do **not** carry: the ground-truth label of
the similar incident. Handing an agent "three similar incidents, all true positives" would leak the
answer and make the metrics worthless.
"""

from __future__ import annotations

from app.agents.base import Agent
from app.agents.schemas import (
    InvestigationOutput,
    MitreMapping,
    SimilarCase,
    WorkflowState,
)
from app.orchestration.context import IncidentContext

#: Minimal technique names so the mapping is readable without a network lookup. Unlisted
#: techniques are still emitted, with the id standing in for the name.
MITRE_NAMES = {
    "T1003": "OS Credential Dumping",
    "T1005": "Data from Local System",
    "T1016": "System Network Configuration Discovery",
    "T1021": "Remote Services",
    "T1027": "Obfuscated Files or Information",
    "T1033": "System Owner/User Discovery",
    "T1036": "Masquerading",
    "T1041": "Exfiltration Over C2 Channel",
    "T1047": "Windows Management Instrumentation",
    "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection",
    "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1078": "Valid Accounts",
    "T1082": "System Information Discovery",
    "T1087": "Account Discovery",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1112": "Modify Registry",
    "T1204": "User Execution",
    "T1486": "Data Encrypted for Impact",
    "T1547": "Boot or Logon Autostart Execution",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1562": "Impair Defenses",
    "T1566": "Phishing",
}


def technique_name(technique_id: str) -> str:
    base = technique_id.split(".")[0]
    return MITRE_NAMES.get(technique_id) or MITRE_NAMES.get(base) or technique_id


class InvestigationAgent(Agent):
    name = "investigation"
    output_model = InvestigationOutput
    role = (
        "Contextual investigation. Compare this incident against historically similar ones, map "
        "the observed behaviour to MITRE ATT&CK techniques with the evidence that supports each "
        "mapping, and write a summary an analyst could act on. Every mapping must be justified "
        "by specific evidence ids, not by the technique sounding plausible."
    )

    def build_context(self, state: WorkflowState, context: IncidentContext = None, **kwargs):
        assert context is not None
        bundle = (
            state.correlation.evidence_bundle if state.correlation else context.evidence_ids
        )
        return {
            "incident_id": context.incident_id,
            "summary": context.summary,
            "evidence_bundle": bundle[:50],
            "techniques": context.mitre_techniques()[:15],
            "similar": [
                {
                    "incident_id": s.incident_id,
                    "score": s.score,
                    "why": s.why(),
                    "summary": s.summary[:400],
                }
                for s in context.similar[:8]
            ],
            "missing": (
                state.correlation.missing_information if state.correlation else []
            ),
            "severity": state.detection.severity_score if state.detection else 0.5,
            "entity_counts": context.entity_counts(),
        }

    def build_prompt(self, context: dict) -> str:
        similar = "\n".join(
            f"- {s['incident_id']} (similarity {s['score']:.2f}, {s['why']})\n  "
            + s["summary"].replace("\n", " ")[:240]
            for s in context["similar"]
        ) or "- no sufficiently similar historical incident found"
        techniques = ", ".join(context["techniques"]) or "none tagged by the detector"
        gaps = "\n".join(f"- {g}" for g in context["missing"][:8]) or "- none reported"

        return (
            f"Incident {context['incident_id']} (detection severity "
            f"{context['severity']:.2f})\n\n"
            f"{context['summary']}\n\n"
            f"Detector-tagged MITRE techniques: {techniques}\n\n"
            f"Similar historical incidents (labels withheld — do not assume their outcome):\n"
            f"{similar}\n\n"
            f"Known evidence gaps:\n{gaps}\n\n"
            f"Evidence ids available for citation: {', '.join(context['evidence_bundle'][:25])}\n\n"
            "Produce similar_cases, mitre_mapping with supporting_evidence_ids drawn from the "
            "list above, and investigation_summary."
        )

    # --- offline path -------------------------------------------------------------------

    def fallback(self, context: dict) -> InvestigationOutput:
        bundle = context["evidence_bundle"] or ["EVD-none"]

        similar_cases = [
            SimilarCase(
                incident_id=s["incident_id"],
                similarity=min(1.0, max(0.0, float(s["score"]))),
                why_similar=s["why"][:400],
            )
            for s in context["similar"][:10]
        ]

        mapping = [
            MitreMapping(
                technique_id=technique[:16],
                technique_name=technique_name(technique)[:160],
                supporting_evidence_ids=bundle[:5],
            )
            for technique in context["techniques"][:10]
        ]

        if similar_cases:
            similarity_line = (
                f"{len(similar_cases)} historically similar incident(s) share entities with this "
                f"one; the strongest match is {similar_cases[0].incident_id} at "
                f"{similar_cases[0].similarity:.2f}."
            )
        else:
            similarity_line = (
                "No historically similar incident shares entities with this one, so there is no "
                "precedent to reason from."
            )

        return InvestigationOutput(
            similar_cases=similar_cases,
            mitre_mapping=mapping,
            investigation_summary=(
                f"Rule-based investigation of {context['incident_id']}. {similarity_line} "
                f"Detector-tagged techniques: "
                f"{', '.join(context['techniques'][:8]) or 'none'}. "
                f"Entity coverage: {context['entity_counts'] or 'none recorded'}. "
                f"Outstanding gaps: {'; '.join(context['missing'][:3]) or 'none reported'}."
            )[:2000],
        )
