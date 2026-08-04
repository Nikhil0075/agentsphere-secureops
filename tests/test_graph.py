"""Union-Find, entity graph construction and alert correlation."""

from __future__ import annotations

import pandas as pd

from app.graph import build as graph_build
from app.graph.correlate import correlate
from app.graph.union_find import UnionFind


# --- Union-Find -----------------------------------------------------------------------------

def test_elements_start_in_their_own_set():
    uf = UnionFind(["a", "b", "c"])
    assert uf.component_count == 3
    assert not uf.connected("a", "b")


def test_union_merges_and_is_transitive():
    uf = UnionFind(["a", "b", "c", "d"])
    uf.union("a", "b")
    uf.union("b", "c")
    assert uf.connected("a", "c")
    assert not uf.connected("a", "d")
    assert uf.component_count == 2


def test_repeated_union_is_a_no_op():
    uf = UnionFind(["a", "b"])
    assert uf.union("a", "b") is True
    assert uf.union("a", "b") is False
    assert uf.component_count == 1


def test_find_compresses_the_path():
    """After a find, every node on the path should point straight at the root."""
    uf = UnionFind()
    for i in range(100):
        uf.add(str(i))
    for i in range(99):
        uf.union(str(i), str(i + 1))

    root = uf.find("99")
    assert all(uf._parent[str(i)] == root for i in range(100))


def test_union_by_rank_keeps_trees_shallow():
    """Path compression alone gives O(log n); the near-constant bound needs rank too (§8.2)."""
    uf = UnionFind()
    for i in range(1000):
        uf.add(str(i))
    for i in range(999):
        uf.union(str(i), str(i + 1))

    # Depth before any compression happens on this node.
    depth, node = 0, "500"
    while uf._parent[node] != node and depth < 1000:
        node = uf._parent[node]
        depth += 1
    assert depth <= 3, f"tree is {depth} deep; union by rank is not doing its job"


def test_find_is_iterative_not_recursive():
    """A 200k chain must not blow the recursion limit."""
    uf = UnionFind()
    for i in range(200_000):
        uf.union(str(i), str(i + 1))
    assert uf.find("0") == uf.find("200000")


def test_unknown_element_is_added_on_find():
    uf = UnionFind()
    assert uf.find("ghost") == "ghost"
    assert "ghost" in uf


def test_components_are_deterministic():
    uf = UnionFind(["a", "b", "c", "d"])
    uf.union("c", "a")
    uf.union("d", "b")
    assert uf.components() == UnionFind.components(uf)
    assert uf.component_sizes() == [2, 2]


# --- entity graph ---------------------------------------------------------------------------

def _evidence_rows(rows: list[dict]) -> pd.DataFrame:
    base = {
        "incident_id": "INC-1",
        "alert_id": "ALT-1",
        "account_upn": "",
        "device_id": "",
        "ip_address": "",
        "file_sha256": "",
        "url": "",
        "file_name": "",
        "mailbox_message_id": "",
    }
    return pd.DataFrame([{**base, **row} for row in rows])


def test_graph_creates_typed_nodes():
    evidence = _evidence_rows([{"account_upn": "alice", "ip_address": "10.0.0.1"}])
    graph = graph_build.build(evidence)
    assert ("account", "alice") in graph.adjacency
    assert ("ip", "10.0.0.1") in graph.adjacency


def test_entities_on_the_same_alert_are_connected():
    evidence = _evidence_rows([{"account_upn": "alice", "device_id": "dev-1"}])
    graph = graph_build.build(evidence)
    assert ("device", "dev-1") in graph.neighbours(("account", "alice"))


def test_blank_values_never_become_nodes():
    """Sentinel masking upstream produces blanks; a blank must not become a shared node."""
    evidence = _evidence_rows(
        [
            {"account_upn": "alice", "device_id": ""},
            {"account_upn": "bob", "device_id": "", "alert_id": "ALT-2"},
        ]
    )
    graph = graph_build.build(evidence)
    assert all(value != "" for _, value in graph.adjacency)


def test_shared_value_across_alerts_is_one_node():
    """Two alerts touching the same IP join through that node — no second edge type needed."""
    evidence = _evidence_rows(
        [
            {"alert_id": "ALT-1", "ip_address": "10.0.0.1", "account_upn": "alice"},
            {"alert_id": "ALT-2", "ip_address": "10.0.0.1", "account_upn": "bob"},
        ]
    )
    graph = graph_build.build(evidence)
    node = ("ip", "10.0.0.1")
    assert graph.node_alerts[node] == {"ALT-1", "ALT-2"}
    assert {("account", "alice"), ("account", "bob")} <= graph.neighbours(node)


def test_clique_size_is_capped():
    """A pathological alert must cost bounded time, not quadratic time."""
    rows = [{"account_upn": f"user{i}", "alert_id": "ALT-1"} for i in range(200)]
    graph = graph_build.build(_evidence_rows(rows), max_entities_per_alert=10)
    assert graph.degree(("account", "user0")) <= 10


def test_hub_detection_reports_the_worst_node():
    rows = [
        {"alert_id": f"ALT-{i}", "ip_address": "hub", "account_upn": f"user{i}"}
        for i in range(60)
    ]
    graph = graph_build.build(_evidence_rows(rows))
    stats = graph.degree_stats(threshold=50)
    assert stats["max_degree"] >= 50
    assert stats["hubs"][0]["node"] == "ip:hub"
    assert ("ip", "hub") in graph.hubs(threshold=50)


def test_incident_span_counts_distinct_incidents():
    evidence = _evidence_rows(
        [
            {"incident_id": "INC-1", "alert_id": "A", "ip_address": "shared"},
            {"incident_id": "INC-2", "alert_id": "B", "ip_address": "shared"},
        ]
    )
    graph = graph_build.build(evidence)
    assert graph.incident_span(("ip", "shared")) == 2


# --- correlation ----------------------------------------------------------------------------

def _alerts(spec: list[tuple[str, str]]) -> pd.DataFrame:
    rows = []
    for i, (alert_id, account) in enumerate(spec):
        rows.append(
            {
                "incident_id": "INC-1",
                "alert_id": alert_id,
                "evidence_id": f"EVD-{i}",
                "timestamp": f"2026-08-04T10:{i:02d}:00+00:00",
                "account_upn": account,
                "device_id": "",
                "ip_address": "",
                "file_sha256": "",
                "url": "",
                "file_name": "",
                "mailbox_message_id": "",
            }
        )
    return pd.DataFrame(rows)


def test_alerts_sharing_an_account_collapse_into_one_cluster():
    """The Day 3 exit criterion, as a test."""
    evidence = _alerts([("ALT-1", "alice"), ("ALT-2", "alice"), ("ALT-3", "alice")])
    result = correlate(evidence)
    assert result.alert_count == 3
    assert result.cluster_count == 1
    assert result.reduction > 0.6


def test_unrelated_alerts_stay_separate():
    evidence = _alerts([("ALT-1", "alice"), ("ALT-2", "bob"), ("ALT-3", "carol")])
    result = correlate(evidence)
    assert result.cluster_count == 3
    assert result.reduction == 0.0


def test_correlation_is_deterministic():
    evidence = _alerts([("ALT-1", "alice"), ("ALT-2", "alice"), ("ALT-3", "bob")])
    first, second = correlate(evidence), correlate(evidence)
    assert [c.alert_ids for c in first.clusters] == [c.alert_ids for c in second.clusters]
    assert [c.cluster_id for c in first.clusters] == [c.cluster_id for c in second.clusters]


def test_cluster_records_what_linked_it():
    evidence = _alerts([("ALT-1", "alice"), ("ALT-2", "alice")])
    cluster = correlate(evidence).clusters[0]
    assert "account:alice" in cluster.linking_entities


def test_an_over_shared_entity_does_not_merge_everything():
    """A value carried by more alerts than the cap is background, not a link."""
    evidence = _alerts([(f"ALT-{i}", "shared-service-account") for i in range(50)])
    result = correlate(evidence, max_shared_alerts=10)
    assert result.cluster_count == 50


def test_cluster_lookup_finds_the_owning_cluster():
    evidence = _alerts([("ALT-1", "alice"), ("ALT-2", "alice")])
    result = correlate(evidence)
    assert result.cluster_for("ALT-2").size == 2
    assert result.cluster_for("ALT-nope") is None
