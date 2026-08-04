"""Canonical JSON and keccak256.

Every proof written on Day 5 rests on these being stable. A hash that changes because a dict was
built in a different order would show as tampering when nothing was tampered with — which is worse
than no proof at all, because it destroys trust in the one thing the system claims to guarantee.
"""

from __future__ import annotations

import pytest

from app.agents.schemas import TriageLabel, TriageOutput
from app.blockchain.hashing import (
    CanonicalisationError,
    canonical_json,
    hash_agent_output,
    hash_decision,
    hash_evidence_bundle,
    hash_payload,
    keccak256,
    verify,
)


def test_keccak256_matches_the_known_empty_string_digest():
    """The canonical keccak-256 test vector. Guards against silently using SHA-3 instead."""
    assert keccak256(b"") == (
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


def test_canonical_json_sorts_keys():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_canonical_json_has_no_whitespace():
    rendered = canonical_json({"a": [1, 2], "b": {"c": 3}})
    assert " " not in rendered


def test_key_order_does_not_change_the_hash():
    assert hash_payload({"a": 1, "b": 2}) == hash_payload({"b": 2, "a": 1})


def test_nested_key_order_does_not_change_the_hash():
    a = {"outer": {"x": 1, "y": [{"p": 1, "q": 2}]}}
    b = {"outer": {"y": [{"q": 2, "p": 1}], "x": 1}}
    assert hash_payload(a) == hash_payload(b)


def test_list_order_does_change_the_hash():
    """Lists are ordered data. Two different sequences are two different facts."""
    assert hash_payload([1, 2]) != hash_payload([2, 1])


def test_a_changed_value_changes_the_hash():
    assert hash_payload({"label": "TruePositive"}) != hash_payload({"label": "FalsePositive"})


def test_nan_is_rejected_rather_than_silently_hashed():
    with pytest.raises(CanonicalisationError):
        hash_payload({"confidence": float("nan")})


def test_infinity_is_rejected():
    with pytest.raises(CanonicalisationError):
        hash_payload({"score": float("inf")})


def test_nested_nan_is_caught():
    with pytest.raises(CanonicalisationError):
        hash_payload({"a": {"b": [1, float("nan")]}})


def test_evidence_bundle_hash_ignores_order_and_duplicates():
    a = hash_evidence_bundle(["EVD-2", "EVD-1"], "INC-1")
    b = hash_evidence_bundle(["EVD-1", "EVD-2", "EVD-1"], "INC-1")
    assert a == b


def test_evidence_bundle_hash_is_bound_to_the_incident():
    assert hash_evidence_bundle(["EVD-1"], "INC-1") != hash_evidence_bundle(["EVD-1"], "INC-2")


def test_agent_output_hash_is_bound_to_the_agent():
    """Identical content from a different agent is a different fact."""
    output = TriageOutput(
        label=TriageLabel.TRUE_POSITIVE,
        confidence=0.9,
        rationale="r",
        supporting_evidence_ids=["EVD-1"],
    )
    assert hash_agent_output("triage", output) != hash_agent_output("verifier", output)


def test_agent_output_hash_survives_a_round_trip_through_json():
    output = TriageOutput(
        label=TriageLabel.TRUE_POSITIVE,
        confidence=0.9,
        rationale="r",
        supporting_evidence_ids=["EVD-1"],
    )
    assert hash_agent_output("triage", output) == hash_agent_output(
        "triage", output.model_dump(mode="json")
    )


def test_decision_hash_changes_with_the_label():
    args = dict(incident_id="INC-1", evidence_hash="0xabc", outputs={}, action="isolate_device")
    assert hash_decision(label="TruePositive", **args) != hash_decision(
        label="FalsePositive", **args
    )


def test_verify_detects_tampering():
    """The Day 6 demo moment, in one assertion."""
    payload = {"label": "FalsePositive", "confidence": 0.9}
    digest = hash_payload(payload)
    assert verify(payload, digest) is True

    payload["label"] = "TruePositive"
    assert verify(payload, digest) is False


def test_hashes_are_hex_prefixed_and_full_length():
    digest = hash_payload({"a": 1})
    assert digest.startswith("0x")
    assert len(digest) == 66
