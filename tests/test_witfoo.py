"""WitFoo provenance graph ingest, adapter and confidence grounding.

The most important test in this file is `test_witfoo_never_enters_the_guide_metrics_path`. WitFoo's
labels are *threat assessments* (benign / suspicious / malicious); GUIDE's are analyst *triage
verdicts* (TruePositive / BenignPositive / FalsePositive). They are not interchangeable, and
quietly mapping one onto the other would corrupt every metric this project reports. The rest of the
file exists to make the feature safe; that one exists to keep the rest of the project honest.
"""

from __future__ import annotations

import json

import pytest

from app.data import witfoo
from app.data.schema import ENTITY_TYPES, LABELS
from app.graph import traverse
from app.graph.build import EntityGraph
from app.graph.confidence import MIN_CONFIDENCE
from app.graph.witfoo_graph import NON_ACTIVITY_EDGES, WitFooConfidence, build


# --- fixtures ----------------------------------------------------------------------------

def _edge(src, dst, **labels):
    base = {
        "label_binary": "benign",
        "label_confidence": 0.5,
        "suspicion_score": 0.0,
        "attack_techniques": [],
        "attack_tactics": [],
        "incident_ids": [],
        "disposition": "Unprocessed",
        "is_false_positive": False,
        "matched_rules": [],
    }
    base.update(labels)
    return {
        "src": src,
        "dst": dst,
        "type": "EVENT",
        "timestamp": 1721992489.0,
        "attrs": {},
        "labels": base,
        "edge_id": f"e-{src}-{dst}",
    }


NODES = {
    "10.136.248.162": {"node_id": "10.136.248.162", "type": "HOST", "attrs": {}},
    "HOST-0001.example.internal": {
        "node_id": "HOST-0001.example.internal",
        "type": "HOST",
        "attrs": {},
    },
    "user:USER-0001": {"node_id": "user:USER-0001", "type": "CREDENTIAL", "attrs": {}},
    "10.6.109.12": {"node_id": "10.6.109.12", "type": "HOST", "attrs": {}},
}


@pytest.fixture
def sample_graph():
    edges = [
        _edge("10.136.248.162", "HOST-0001.example.internal",
              label_binary="malicious", suspicion_score=0.79,
              attack_techniques=["T1190"], incident_ids=["inc-1"]),
        _edge("HOST-0001.example.internal", "user:USER-0001",
              label_binary="suspicious", suspicion_score=0.45, incident_ids=["inc-1"]),
        _edge("user:USER-0001", "10.6.109.12", label_binary="benign"),
    ]
    return build(nodes=NODES, edges=iter(edges))


# --- node typing --------------------------------------------------------------------------

def test_a_host_that_is_an_ip_is_typed_as_an_ip():
    """WitFoo HOST ids are sometimes addresses. Typing both as 'device' would merge two genuinely
    different entity kinds."""
    assert witfoo.node_key("10.136.248.162", "HOST") == ("ip", "10.136.248.162")


def test_a_host_that_is_a_hostname_is_typed_as_a_device():
    assert witfoo.node_key("USER-0010-0001.domain-0022.example.net", "HOST") == (
        "device",
        "USER-0010-0001.domain-0022.example.net",
    )


def test_ipv6_hosts_are_recognised():
    assert witfoo.node_key("2001:db8::1", "HOST")[0] == "ip"


def test_credential_types_map_to_account():
    for witfoo_type in ("CREDENTIAL", "CRED", "ACTOR"):
        assert witfoo.node_key("user:USER-0001", witfoo_type)[0] == "account"


def test_credential_prefixes_are_stripped():
    assert witfoo.node_key("user:USER-0001", "CREDENTIAL") == ("account", "USER-0001")


def test_service_and_file_map_to_the_canonical_vocabulary():
    assert witfoo.node_key("svc:sshd", "SERVICE")[0] == "process"
    assert witfoo.node_key("file:abc", "FILE")[0] == "filehash"


def test_every_mapping_target_is_a_known_entity_type():
    """A typo here would create an entity type nothing else in the system understands."""
    for canonical in witfoo.WITFOO_NODE_TYPES.values():
        assert canonical in ENTITY_TYPES


def test_an_unknown_node_type_falls_back_rather_than_raising():
    assert witfoo.node_key("thing", "SOMETHING_NEW")[0] in ENTITY_TYPES


# --- streaming readers ----------------------------------------------------------------------

def test_jsonl_reader_skips_a_truncated_final_line(tmp_path):
    """An interrupted download leaves a half-written record. That should cost one row."""
    path = tmp_path / "edges.jsonl"
    path.write_text('{"a":1}\n{"b":2}\n{"c":', encoding="utf-8")
    assert list(witfoo.iter_jsonl(path)) == [{"a": 1}, {"b": 2}]


def test_jsonl_reader_skips_blank_lines(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_text('{"a":1}\n\n\n{"b":2}\n', encoding="utf-8")
    assert len(list(witfoo.iter_jsonl(path))) == 2


def test_jsonl_reader_on_a_missing_file_yields_nothing(tmp_path):
    assert list(witfoo.iter_jsonl(tmp_path / "nope.jsonl")) == []


def test_metadata_on_a_missing_file_is_empty_not_an_exception(tmp_path):
    assert witfoo.load_metadata(tmp_path / "nope.json") == {}


def test_metadata_on_malformed_json_is_empty(tmp_path):
    bad = tmp_path / "meta.json"
    bad.write_text("{not json", encoding="utf-8")
    assert witfoo.load_metadata(bad) == {}


# --- edge labels ---------------------------------------------------------------------------

def test_edge_labels_are_parsed():
    labels = witfoo.EdgeLabels.from_edge(
        _edge("a", "b", label_binary="malicious", suspicion_score=0.9,
              attack_techniques=["T1190"], incident_ids=["inc-1"])
    )
    assert labels.threat_label == "malicious"
    assert labels.suspicion_score == 0.9
    assert labels.attack_techniques == ["T1190"]
    assert labels.incident_ids == ["inc-1"]


def test_the_threat_label_is_not_called_a_triage_label():
    """Field naming is the cheapest defence against the two label systems being conflated."""
    labels = witfoo.EdgeLabels.from_edge(_edge("a", "b"))
    assert hasattr(labels, "threat_label")
    assert not hasattr(labels, "label")
    assert not hasattr(labels, "triage_label")


def test_the_unscored_default_is_not_treated_as_a_measurement():
    """A benign edge at exactly 0.5 is WitFoo's default, not a judgement. Counting it as grounding
    would claim precision the dataset never offered."""
    assert not witfoo.EdgeLabels.from_edge(
        _edge("a", "b", label_binary="benign", label_confidence=0.5)
    ).scored


def test_a_suspicion_score_counts_as_scored():
    assert witfoo.EdgeLabels.from_edge(_edge("a", "b", suspicion_score=0.7)).scored


def test_a_malicious_edge_with_a_real_confidence_counts_as_scored():
    assert witfoo.EdgeLabels.from_edge(
        _edge("a", "b", label_binary="malicious", label_confidence=0.93)
    ).scored


# --- the adapter ------------------------------------------------------------------------------

def test_the_adapter_produces_the_real_entity_graph(sample_graph):
    """Not a parallel type — the same class, so every traversal works unchanged."""
    assert isinstance(sample_graph.graph, EntityGraph)


def test_nodes_and_edges_are_registered(sample_graph):
    assert sample_graph.graph.node_count == 4
    assert sample_graph.graph.edge_count == 3
    assert sample_graph.edges_used == 3


def test_incident_link_edges_are_excluded():
    """An INCIDENT_LINK joins an incident record to its entities. Traversing it would let a path
    hop between unrelated hosts through the incident node and call that an attack chain."""
    edge = _edge("10.136.248.162", "10.6.109.12", incident_ids=["inc-1"])
    edge["type"] = "INCIDENT_LINK"
    result = build(nodes=NODES, edges=iter([edge]))
    assert result.edges_used == 0
    assert result.edges_skipped_type == 1
    assert "INCIDENT_LINK" in NON_ACTIVITY_EDGES


def test_self_loops_are_dropped():
    result = build(nodes=NODES, edges=iter([_edge("10.6.109.12", "10.6.109.12")]))
    assert result.edges_used == 0


def test_incidents_only_keeps_incident_edges():
    edges = [
        _edge("10.136.248.162", "10.6.109.12", incident_ids=["inc-1"]),
        _edge("10.6.109.12", "HOST-0001.example.internal"),
    ]
    result = build(nodes=NODES, edges=iter(edges), incidents_only=True)
    assert result.edges_used == 1


def test_incident_membership_is_recorded(sample_graph):
    assert len(sample_graph.incident_edges["inc-1"]) == 2
    assert len(sample_graph.nodes_for_incident("inc-1")) == 3


def test_labels_are_retrievable_in_either_direction(sample_graph):
    a, b = ("ip", "10.136.248.162"), ("device", "HOST-0001.example.internal")
    assert sample_graph.labels_for(a, b) is not None
    assert sample_graph.labels_for(b, a) is not None


def test_max_edges_bounds_the_build():
    edges = [_edge(f"10.0.0.{i}", f"10.0.1.{i}") for i in range(50)]
    assert build(nodes={}, edges=iter(edges), max_edges=10).edges_used == 10


def test_stats_are_reportable(sample_graph):
    stats = sample_graph.stats()
    assert stats["nodes"] == 4 and stats["edges"] == 3 and stats["incidents"] == 1


# --- traversal runs unmodified on WitFoo ------------------------------------------------------

def test_blast_radius_runs_on_the_witfoo_graph(sample_graph):
    """The portability claim, demonstrated: the Day 4 traversal code is dataset-independent."""
    radius = traverse.blast_radius(
        sample_graph.graph, [("ip", "10.136.248.162")], max_hops=2
    )
    assert ("device", "HOST-0001.example.internal") in radius.nodes


def test_dijkstra_runs_on_the_witfoo_graph(sample_graph):
    model = WitFooConfidence(sample_graph)
    path = traverse.most_probable_path(
        sample_graph.graph,
        ("ip", "10.136.248.162"),
        ("ip", "10.6.109.12"),
        model.confidence,
    )
    assert path is not None
    assert path.nodes[0] == ("ip", "10.136.248.162")
    assert 0.0 < path.probability <= 1.0


def test_hub_detection_runs_on_the_witfoo_graph(sample_graph):
    assert sample_graph.graph.degree_stats(threshold=2)["nodes"] == 4


# --- confidence grounding ----------------------------------------------------------------------

def test_a_scored_edge_uses_the_dataset_value(sample_graph):
    model = WitFooConfidence(sample_graph)
    value = model.confidence(("ip", "10.136.248.162"), ("device", "HOST-0001.example.internal"))
    assert value == pytest.approx(0.79)
    assert model.grounded == 1


def test_an_unscored_edge_falls_back_to_a_prior(sample_graph):
    model = WitFooConfidence(sample_graph)
    model.confidence(("account", "USER-0001"), ("ip", "10.6.109.12"))
    assert model.fallback == 1
    assert model.grounded == 0


def test_an_unknown_edge_falls_back_rather_than_raising(sample_graph):
    model = WitFooConfidence(sample_graph)
    assert 0.0 < model.confidence(("ip", "1.1.1.1"), ("ip", "2.2.2.2")) <= 1.0


def test_confidence_is_never_zero(sample_graph):
    """A zero becomes an infinite Dijkstra cost and silently deletes the path (§8.2)."""
    model = WitFooConfidence(sample_graph)
    for a, b in list(sample_graph.edge_labels) + [(("ip", "9.9.9.9"), ("ip", "8.8.8.8"))]:
        assert model.confidence(a, b) >= MIN_CONFIDENCE


def test_confidence_is_bounded_above(sample_graph):
    model = WitFooConfidence(sample_graph)
    assert all(model.confidence(a, b) <= 1.0 for a, b in sample_graph.edge_labels)


def test_grounding_is_quantified_not_implied(sample_graph):
    """"Grounded in dataset labels" is only worth saying where it is true, so it is counted."""
    model = WitFooConfidence(sample_graph)
    for a, b in sample_graph.edge_labels:
        model.confidence(a, b)
    breakdown = model.source_breakdown()
    assert breakdown["grounded_lookups"] + breakdown["fallback_lookups"] == 3
    assert 0.0 <= breakdown["grounded_fraction"] <= 1.0


def test_a_malicious_edge_outranks_a_benign_one(sample_graph):
    model = WitFooConfidence(sample_graph)
    malicious = model.confidence(
        ("ip", "10.136.248.162"), ("device", "HOST-0001.example.internal")
    )
    benign = model.confidence(("account", "USER-0001"), ("ip", "10.6.109.12"))
    assert malicious > benign


# --- the isolation guard ----------------------------------------------------------------------

def test_witfoo_never_enters_the_guide_metrics_path():
    """WitFoo threat labels must never be presented as GUIDE triage verdicts.

    If a future change maps malicious -> TruePositive, this fails. Every accuracy number in the
    project depends on the two label systems staying apart.
    """
    assert set(witfoo.THREAT_LABELS).isdisjoint(set(LABELS))

    import ast
    import pathlib

    from app.graph import witfoo_graph

    def code_string_literals(path: pathlib.Path) -> set[str]:
        """String constants that are actually *used*, ignoring docstrings.

        The docstrings in these modules name the triage labels on purpose, to explain why they
        must never be mapped. Matching on raw text would flag that explanation as the very
        offence it warns about, so this reads the syntax tree and skips documentation.
        """
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = {
            node.body[0].value
            for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef))
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        }
        return {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node not in docstrings
        }

    literals: set[str] = set()
    for module in (witfoo, witfoo_graph):
        literals |= code_string_literals(pathlib.Path(module.__file__))

    leaked = literals & set(LABELS)
    assert not leaked, (
        f"{sorted(leaked)} appear as code literals in the WitFoo modules — the threat labels and "
        "the triage verdicts must not be mapped onto each other"
    )


def test_the_evaluation_corpus_ignores_witfoo(tmp_path, monkeypatch):
    """scripts/evaluate.py reads the prepared GUIDE frame; WitFoo lives in its own artifacts and
    must not appear there."""
    from app.data import loader

    try:
        _, incidents = loader.load_prepared()
    except FileNotFoundError:
        pytest.skip("prepared dataset not built")

    ids = set(incidents["incident_id"])
    assert all(str(i).startswith("INC-") for i in list(ids)[:200])
    # WitFoo incident ids are UUIDs, never the INC- form.
    assert not any("-" in str(i) and len(str(i)) == 36 for i in list(ids)[:200])


def test_witfoo_artifacts_are_optional():
    """The frozen Phase 0 system must run with none of this present."""
    from app.graph import witfoo_graph

    assert callable(witfoo_graph.build)
    assert isinstance(witfoo.available(), bool)


def test_an_empty_build_is_harmless():
    result = build(nodes={}, edges=iter([]))
    assert result.graph.node_count == 0
    assert result.stats()["incidents"] == 0


# --- listing facets ------------------------------------------------------------------------------


def _store(rows):
    from app.services.provenance import ProvenanceStore

    store = ProvenanceStore(incidents=rows)
    store._index = {r["incident_id"]: r for r in rows}
    return store


_ROWS = [
    {
        "incident_id": "a", "mo_name": "Phishing", "status_name": "Disrupted",
        "suspicion_score": 0.99, "node_count": 4, "last_observed_at": 10,
        "threat_labels": {"malicious": 3},
    },
    {
        "incident_id": "b", "mo_name": "Data Theft", "status_name": "Unprocessed",
        "suspicion_score": 0.25, "node_count": 40, "last_observed_at": 99,
        "threat_labels": {"malicious": 9},
    },
]


def test_the_listing_can_be_ordered_by_something_other_than_suspicion():
    """Fixed suspicion-descending ordering made the corpus look like one kind of incident.

    The median shipped suspicion score is 0.250 against a maximum of 0.992, so the first page was
    a run of near-identical 0.99s while most of the dataset sat at the floor, unreachable without
    paging.
    """
    store = _store(_ROWS)
    assert [r["incident_id"] for r in store.list_incidents(sort="suspicion")] == ["a", "b"]
    assert [r["incident_id"] for r in store.list_incidents(sort="suspicion_asc")] == ["b", "a"]
    assert store.list_incidents(sort="nodes")[0]["incident_id"] == "b"
    assert store.list_incidents(sort="recent")[0]["incident_id"] == "b"


def test_the_listing_filters_on_the_facets_that_vary():
    store = _store(_ROWS)
    assert [r["incident_id"] for r in store.list_incidents(mo_name="Phishing")] == ["a"]
    assert [r["incident_id"] for r in store.list_incidents(status="Unprocessed")] == ["b"]
    assert store.list_incidents(mo_name="Phishing", status="Unprocessed") == []


def test_the_threat_label_spread_is_counted_per_incident_not_per_edge():
    """Why there is no threat-label filter, expressed as a measurement.

    The edge-level label histogram can look varied while every *incident* still resolves to a
    single label — which is the case on the shipped corpus: 9,552 of 9,552 are malicious. A
    filter over one value is not a filter, so the UI states the fact instead of offering one.
    """
    assert _store(_ROWS).threat_label_spread() == {"malicious": 2}
