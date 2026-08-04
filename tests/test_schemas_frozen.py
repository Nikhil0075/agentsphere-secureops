"""The Day 2 contract freeze, enforced.

If these fail, an agent output contract changed after the freeze. That is not necessarily wrong,
but it invalidates every prompt, validator and stored output hash built against the old shape, so
it must be a deliberate act with the artifacts regenerated — never a silent drift.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.agents.json_schema import response_format, to_openai_schema
from app.agents.schemas import (
    AGENT_OUTPUT_MODELS,
    DetectionOutput,
    TriageLabel,
    TriageOutput,
    VerifierOutput,
    WorkflowState,
)
from app.config import SCHEMAS_DIR
from scripts.freeze_schemas import render


def test_frozen_artifacts_match_the_models():
    drift = []
    for filename, content in render().items():
        path = SCHEMAS_DIR / filename
        assert path.exists(), f"{filename} was never frozen"
        if path.read_text(encoding="utf-8").strip() != content.strip():
            drift.append(filename)
    assert not drift, f"schema drift in: {drift}"


def test_all_six_agents_have_a_contract():
    assert set(AGENT_OUTPUT_MODELS) == {
        "detection",
        "correlation",
        "investigation",
        "triage",
        "remediation",
        "verifier",
    }


@pytest.mark.parametrize("name,model", sorted(AGENT_OUTPUT_MODELS.items()))
def test_schema_is_valid_for_openai_strict_mode(name, model):
    """Strict mode: every object closed, every property required, refs resolvable."""
    schema = to_openai_schema(model)

    def walk(node, path="root"):
        if isinstance(node, dict):
            if node.get("type") == "object" or "properties" in node:
                assert node.get("additionalProperties") is False, f"{path} is open"
                assert set(node.get("required", [])) == set(
                    node.get("properties", {})
                ), f"{path} has optional properties"
            for key, value in node.items():
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")

    walk(schema)
    for ref in json.dumps(schema).split('"$ref": "')[1:]:
        target = ref.split('"')[0]
        assert target.startswith("#/$defs/"), target
        assert target.split("/")[-1] in schema.get("$defs", {}), target


def test_response_format_shape():
    payload = response_format(TriageOutput, "triage")
    assert payload["type"] == "json_schema"
    assert payload["json_schema"]["strict"] is True
    assert payload["json_schema"]["name"] == "triage"


def test_agents_reject_unknown_fields():
    with pytest.raises(ValidationError):
        DetectionOutput(
            severity_score=0.5,
            suspicious_entities=[],
            initial_reason="x",
            invented_field="nope",
        )


def test_confidence_is_bounded():
    for bad in (-0.1, 1.1):
        with pytest.raises(ValidationError):
            TriageOutput(
                label=TriageLabel.TRUE_POSITIVE,
                confidence=bad,
                rationale="x",
                supporting_evidence_ids=["EVD-1"],
            )


def test_triage_must_cite_evidence():
    with pytest.raises(ValidationError):
        TriageOutput(
            label=TriageLabel.TRUE_POSITIVE,
            confidence=0.9,
            rationale="trust me",
            supporting_evidence_ids=[],
        )


def test_triage_label_is_a_closed_set():
    with pytest.raises(ValidationError):
        TriageOutput(
            label="Maybe",
            confidence=0.5,
            rationale="x",
            supporting_evidence_ids=["EVD-1"],
        )


def test_verifier_can_reject():
    out = VerifierOutput(
        verdict="reject",
        contradictions=["triage cites evidence absent from the bundle"],
        policy_checks=[],
        escalation_required=True,
        reasoning="unsupported citation",
    )
    assert out.verdict.value == "reject"


def test_workflow_state_starts_empty():
    state = WorkflowState(workflow_id="wf-1", incident_id="INC-1")
    assert state.completed_agents() == []
    assert state.requires_approval is False
