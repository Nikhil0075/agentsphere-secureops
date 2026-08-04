"""Entity graph construction (master plan §8.4).

**Graph algorithms need a graph, and GUIDE does not ship one.** It is tabular — incidents, alerts
and evidence rows with typed entities. WitFoo is the dataset with provenance graphs and it is
deferred to the on-site round. So the graph is built here, as an explicit task, because BFS, DFS,
Dijkstra and Union-Find all block on it.

Nodes are ``(entity_type, value)`` pairs drawn from the evidence entity columns, and edges are
**co-occurrence**: two entities observed on the same alert.

Sharing an entity value across alerts needs no edge of its own — the node *is* the value, so two
alerts that both touch ``ip:349667`` are already joined through that single node, and a path
running through it is exactly the shared-entity relationship. Adding a second edge type for it
would double-count the same fact.

Every edge carries the set of incidents that witnessed it, which is what lets a traversal be
scoped to one incident or run across the corpus.

Hub nodes are computed at build time rather than discovered during a demo. §8.4 names an uncapped
traversal from a hub as the most likely cause of the system freezing in front of judges, so degree
statistics are an output of this module, not an afterthought.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from app.data.schema import ENTITY_COLUMNS

#: Nodes above this degree are treated as hubs and excluded from expansion by default.
DEFAULT_HUB_DEGREE = 150

Node = tuple[str, str]


def node_label(node: Node) -> str:
    return f"{node[0]}:{node[1]}"


@dataclass
class EntityGraph:
    """Undirected multigraph over typed entities, stored as adjacency dictionaries.

    Adjacency dicts rather than networkx: the operations needed through Day 4 are neighbour
    lookup, degree and traversal, all of which a dict of sets does at full speed with no
    dependency and no conversion cost.
    """

    adjacency: dict[Node, set[Node]] = field(default_factory=lambda: defaultdict(set))
    node_incidents: dict[Node, set[str]] = field(default_factory=lambda: defaultdict(set))
    node_alerts: dict[Node, set[str]] = field(default_factory=lambda: defaultdict(set))
    edge_incidents: dict[tuple[Node, Node], set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )

    # --- construction -------------------------------------------------------------------

    def add_node(self, node: Node, incident_id: str, alert_id: str) -> None:
        self.adjacency.setdefault(node, set())
        self.node_incidents[node].add(incident_id)
        self.node_alerts[node].add(alert_id)

    def add_edge(self, a: Node, b: Node, incident_id: str) -> None:
        if a == b:
            return
        self.adjacency[a].add(b)
        self.adjacency[b].add(a)
        self.edge_incidents[_edge_key(a, b)].add(incident_id)

    # --- queries ------------------------------------------------------------------------

    @property
    def node_count(self) -> int:
        return len(self.adjacency)

    @property
    def edge_count(self) -> int:
        return len(self.edge_incidents)

    def degree(self, node: Node) -> int:
        return len(self.adjacency.get(node, ()))

    def neighbours(self, node: Node) -> set[Node]:
        return self.adjacency.get(node, set())

    def incident_span(self, node: Node) -> int:
        """How many distinct incidents this entity appears in."""
        return len(self.node_incidents.get(node, ()))

    def nodes_for_incident(self, incident_id: str) -> list[Node]:
        return sorted(
            node for node, incidents in self.node_incidents.items() if incident_id in incidents
        )

    def hubs(self, threshold: int = DEFAULT_HUB_DEGREE) -> set[Node]:
        """Nodes whose degree makes them a traversal hazard."""
        return {node for node in self.adjacency if self.degree(node) >= threshold}

    def degree_stats(self, top_n: int = 20, threshold: int = DEFAULT_HUB_DEGREE) -> dict:
        degrees = sorted(
            ((node, self.degree(node)) for node in self.adjacency),
            key=lambda kv: (-kv[1], node_label(kv[0])),
        )
        if not degrees:
            return {"nodes": 0, "edges": 0, "hubs": []}

        values = [d for _, d in degrees]
        return {
            "nodes": self.node_count,
            "edges": self.edge_count,
            "hub_degree_threshold": threshold,
            "hub_count": sum(1 for v in values if v >= threshold),
            "max_degree": values[0],
            "median_degree": values[len(values) // 2],
            "mean_degree": round(sum(values) / len(values), 2),
            "by_type": {
                entity_type: sum(1 for node in self.adjacency if node[0] == entity_type)
                for entity_type in ENTITY_COLUMNS
            },
            "hubs": [
                {
                    "node": node_label(node),
                    "degree": degree,
                    "incidents": self.incident_span(node),
                }
                for node, degree in degrees[:top_n]
            ],
        }


def _edge_key(a: Node, b: Node) -> tuple[Node, Node]:
    return (a, b) if a <= b else (b, a)


def extract_entities(row: dict) -> list[Node]:
    """Typed entities present on a single evidence row.

    Blank values are skipped, which is why sentinel masking has to happen upstream — an unmasked
    placeholder would become a node that every incident connects to.
    """
    nodes: list[Node] = []
    for entity_type, column in ENTITY_COLUMNS.items():
        value = str(row.get(column, "") or "").strip()
        if value:
            nodes.append((entity_type, value))
    return nodes


def build(evidence: pd.DataFrame, max_entities_per_alert: int = 40) -> EntityGraph:
    """Build the entity graph from evidence rows.

    Co-occurrence edges are formed within an alert rather than within an incident. An incident
    with 1,313 evidence rows would otherwise produce a near-complete graph over its entities —
    O(n²) edges that assert a relationship the data does not support.
    """
    graph = EntityGraph()
    columns = ["incident_id", "alert_id"] + [
        c for c in ENTITY_COLUMNS.values() if c in evidence.columns
    ]
    frame = evidence[columns]

    for (incident_id, alert_id), group in frame.groupby(["incident_id", "alert_id"], sort=True):
        entities: list[Node] = []
        seen: set[Node] = set()
        for row in group.to_dict("records"):
            for node in extract_entities(row):
                if node not in seen:
                    seen.add(node)
                    entities.append(node)

        for node in entities:
            graph.add_node(node, str(incident_id), str(alert_id))

        # Cap the clique size. A pathological alert should cost bounded time, not quadratic time.
        for i, a in enumerate(entities[:max_entities_per_alert]):
            for b in entities[i + 1 : max_entities_per_alert]:
                graph.add_edge(a, b, str(incident_id))

    return graph


def write_degree_stats(graph: EntityGraph, path: str | Path, threshold: int = DEFAULT_HUB_DEGREE) -> dict:
    stats = graph.degree_stats(threshold=threshold)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(stats, indent=2, sort_keys=True), encoding="utf-8")
    return stats
