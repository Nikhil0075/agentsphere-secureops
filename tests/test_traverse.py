"""Blast radius and attack-path reconstruction.

The two tests that matter most here are the hub-containment test and the §8.2 cost-function
counterexample. Both encode a specific way this could go wrong that was identified before any code
was written, which is the only reason they are worth having.
"""

from __future__ import annotations

from math import isclose

import pandas as pd
import pytest

from app.graph.build import EntityGraph
from app.graph.confidence import ConfidenceModel
from app.graph.traverse import (
    AttackPath,
    blast_radius,
    edge_cost,
    most_probable_path,
    process_lineage,
)


def _graph(edges: list[tuple[tuple[str, str], tuple[str, str]]], incident: str = "INC-1"):
    graph = EntityGraph()
    for a, b in edges:
        graph.add_node(a, incident, "ALT-1")
        graph.add_node(b, incident, "ALT-1")
        graph.add_edge(a, b, incident)
    return graph


A = ("account", "alice")
B = ("device", "dev-1")
C = ("ip", "10.0.0.1")
D = ("filehash", "abc")


# --- blast radius --------------------------------------------------------------------------

def test_one_hop_returns_direct_neighbours_only():
    graph = _graph([(A, B), (B, C)])
    result = blast_radius(graph, [A], max_hops=1)
    assert result.by_hop[1] == [B]
    assert C not in result.nodes


def test_two_hops_reaches_further():
    graph = _graph([(A, B), (B, C)])
    result = blast_radius(graph, [A], max_hops=2)
    assert set(result.nodes) == {B, C}


def test_hop_cap_is_respected():
    chain = [(("n", str(i)), ("n", str(i + 1))) for i in range(10)]
    graph = _graph(chain)
    result = blast_radius(graph, [("n", "0")], max_hops=3)
    assert max(result.by_hop) == 3


def test_seeds_are_not_reported_as_impacted():
    graph = _graph([(A, B)])
    assert A not in blast_radius(graph, [A], max_hops=2).nodes


def test_an_unknown_seed_returns_empty_rather_than_raising():
    graph = _graph([(A, B)])
    assert blast_radius(graph, [("account", "nobody")]).nodes == []


def test_results_group_by_entity_type():
    graph = _graph([(A, B), (A, C)])
    grouped = blast_radius(graph, [A], max_hops=1).by_type()
    assert grouped == {"device": ["dev-1"], "ip": ["10.0.0.1"]}


def test_traversal_is_deterministic():
    graph = _graph([(A, B), (A, C), (A, D)])
    first = blast_radius(graph, [A], max_hops=2).nodes
    second = blast_radius(graph, [A], max_hops=2).nodes
    assert first == second


# --- hub containment: the demo-freezing failure mode (§8.4) ----------------------------------

def _hub_graph(fanout: int = 1200):
    """One node connected to `fanout` others — the shape of process:6 in the real corpus."""
    hub = ("process", "powershell.exe")
    edges = [(hub, ("device", f"dev-{i}")) for i in range(fanout)]
    edges.append((("account", "patient-zero"), hub))
    return _graph(edges), hub


def test_traversal_does_not_expand_through_a_hub():
    """The real worst case: process:6 at degree 1,025. An uncapped BFS returns the graph."""
    graph, hub = _hub_graph()
    result = blast_radius(graph, [("account", "patient-zero")], max_hops=3, hub_degree=150)

    assert hub in result.nodes, "a reached hub is genuinely impacted and must be reported"
    assert hub in result.hubs_blocked
    assert len(result.nodes) < 50, f"hub fan-out leaked: {len(result.nodes)} nodes returned"


def test_hub_containment_is_fast():
    import time

    graph, _ = _hub_graph(fanout=5000)
    started = time.perf_counter()
    blast_radius(graph, [("account", "patient-zero")], max_hops=3, hub_degree=150)
    assert time.perf_counter() - started < 1.0


def test_max_nodes_truncates_a_dense_neighbourhood():
    """Second belt: even below the hub threshold, the answer stays bounded."""
    edges = [(("account", "a"), ("device", f"d{i}")) for i in range(500)]
    graph = _graph(edges)
    result = blast_radius(
        graph, [("account", "a")], max_hops=2, hub_degree=100_000, max_nodes=50
    )
    assert result.truncated
    assert len(result.nodes) <= 51


def test_traversal_can_be_scoped_to_one_incident():
    graph = EntityGraph()
    graph.add_node(A, "INC-1", "ALT-1")
    graph.add_node(B, "INC-1", "ALT-1")
    graph.add_node(C, "INC-2", "ALT-2")
    graph.add_edge(A, B, "INC-1")
    graph.add_edge(B, C, "INC-2")

    scoped = blast_radius(graph, [A], max_hops=3, incident_id="INC-1")
    assert B in scoped.nodes
    assert C not in scoped.nodes


# --- the cost function (§8.2) ------------------------------------------------------------------

def test_edge_cost_is_negative_log():
    assert isclose(edge_cost(1.0), 0.0, abs_tol=1e-9)
    assert edge_cost(0.5) > edge_cost(0.9) > edge_cost(1.0)


def test_edge_cost_is_never_infinite():
    """An infinite cost silently deletes a path. Clamp before the log."""
    assert edge_cost(0.0) < float("inf")
    assert edge_cost(-1.0) == edge_cost(0.0)


def test_edge_costs_are_non_negative_so_dijkstra_stays_valid():
    assert all(edge_cost(c) >= 0.0 for c in (0.0, 0.01, 0.5, 0.99, 1.0))


def test_dijkstra_picks_the_most_probable_path_not_the_least_weak():
    """The §8.2 counterexample, executable.

    Path A: 0.50, 0.99 -> product 0.4950
    Path B: 0.74, 0.74 -> product 0.5476

    cost = 1 - c  picks A (wrong). cost = -log(c) picks B (correct).
    """
    source, target = ("account", "src"), ("account", "dst"),
    mid_a, mid_b = ("device", "via-a"), ("device", "via-b")
    graph = _graph([(source, mid_a), (mid_a, target), (source, mid_b), (mid_b, target)])

    confidences = {
        frozenset({source, mid_a}): 0.50,
        frozenset({mid_a, target}): 0.99,
        frozenset({source, mid_b}): 0.74,
        frozenset({mid_b, target}): 0.74,
    }

    def confidence(a, b):
        return confidences[frozenset({a, b})]

    path = most_probable_path(graph, source, target, confidence)
    assert path is not None
    assert mid_b in path.nodes, "picked the path with the weak 0.50 link"
    assert isclose(path.probability, 0.5476, abs_tol=1e-4)

    # And confirm the rejected cost function really would have got it wrong.
    linear_a = (1 - 0.50) + (1 - 0.99)
    linear_b = (1 - 0.74) + (1 - 0.74)
    assert linear_a < linear_b, "the counterexample no longer demonstrates anything"


def test_path_probability_is_the_product_of_confidences():
    source, mid, target = ("account", "s"), ("device", "m"), ("ip", "t")
    graph = _graph([(source, mid), (mid, target)])
    path = most_probable_path(graph, source, target, lambda a, b: 0.5)
    assert isclose(path.probability, 0.25, abs_tol=1e-6)


def test_weakest_link_is_reported():
    source, mid, target = ("account", "s"), ("device", "m"), ("ip", "t")
    graph = _graph([(source, mid), (mid, target)])
    confidences = {frozenset({source, mid}): 0.9, frozenset({mid, target}): 0.3}
    path = most_probable_path(graph, source, target, lambda a, b: confidences[frozenset({a, b})])
    assert isclose(path.weakest_link, 0.3, abs_tol=1e-9)


def test_no_path_returns_none_rather_than_an_empty_result():
    graph = _graph([(A, B), (C, D)])
    assert most_probable_path(graph, A, D, lambda a, b: 0.9) is None


def test_path_to_self_is_trivial():
    graph = _graph([(A, B)])
    path = most_probable_path(graph, A, A, lambda a, b: 0.9)
    assert path.nodes == [A]
    assert path.probability == 1.0


def test_unknown_endpoint_returns_none():
    graph = _graph([(A, B)])
    assert most_probable_path(graph, A, ("ip", "nope"), lambda a, b: 0.9) is None


def test_dijkstra_does_not_route_through_a_hub():
    """A path through a hub is an artefact of the hub, not an attack chain."""
    graph, hub = _hub_graph(fanout=400)
    source = ("account", "patient-zero")
    target = ("device", "dev-7")
    path = most_probable_path(graph, source, target, lambda a, b: 0.9, hub_degree=150)
    assert path is None


def test_expansion_budget_bounds_the_search():
    chain = [(("n", str(i)), ("n", str(i + 1))) for i in range(500)]
    graph = _graph(chain)
    assert (
        most_probable_path(
            graph, ("n", "0"), ("n", "500"), lambda a, b: 0.9, max_expansions=10
        )
        is None
    )


# --- lineage ------------------------------------------------------------------------------

def test_process_lineage_returns_a_chain():
    chain = [(("n", str(i)), ("n", str(i + 1))) for i in range(5)]
    graph = _graph(chain)
    lineage = process_lineage(graph, ("n", "0"), max_depth=4)
    assert lineage[0] == ("n", "0")
    assert len(lineage) <= 4


def test_lineage_of_an_unknown_node_is_empty():
    assert process_lineage(_graph([(A, B)]), ("ip", "nope")) == []


# --- confidence model ---------------------------------------------------------------------

def _evidence(rows: list[dict]) -> pd.DataFrame:
    base = {
        "incident_id": "INC-1",
        "alert_id": "ALT-1",
        "suspicion_level": "",
        "last_verdict": "",
    }
    return pd.DataFrame([{**base, **r} for r in rows])


def test_confidence_is_bounded():
    graph = _graph([(A, B)])
    model = ConfidenceModel(graph, _evidence([{}]))
    assert 0.0 < model.confidence(A, B) <= 1.0


def test_a_malicious_verdict_raises_confidence():
    graph = _graph([(A, B)])
    weak = ConfidenceModel(graph, _evidence([{"last_verdict": "Clean"}])).confidence(A, B)
    strong = ConfidenceModel(graph, _evidence([{"last_verdict": "Malicious"}])).confidence(A, B)
    assert strong > weak


def test_a_widely_spread_entity_lowers_confidence():
    """Sharing a file hash means something; sharing powershell.exe means almost nothing."""
    rare = _graph([(A, B)])
    common = _graph([(A, B)])
    for i in range(200):
        common.add_node(B, f"INC-{i}", f"ALT-{i}")

    evidence = _evidence([{"last_verdict": "Malicious"}])
    assert (
        ConfidenceModel(common, evidence).confidence(A, B)
        < ConfidenceModel(rare, evidence).confidence(A, B)
    )


def test_confidence_never_returns_zero():
    """A zero would become an infinite Dijkstra cost."""
    graph = _graph([(A, B)])
    for i in range(500):
        graph.add_node(B, f"INC-{i}", f"ALT-{i}")
    assert ConfidenceModel(graph, _evidence([{"last_verdict": "NoThreatsFound"}])).confidence(
        A, B
    ) >= 0.01


def test_attack_path_serialises_for_the_api():
    path = AttackPath(nodes=[A, B], total_cost=0.2, edge_confidences=[0.8])
    payload = path.as_dict()
    assert payload["path"] == ["account:alice", "device:dev-1"]
    assert payload["hops"] == 1
    assert 0 < payload["probability"] <= 1
