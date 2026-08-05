"""Build the entity graph from WitFoo's shipped provenance data.

This deliberately constructs the **same** :class:`app.graph.build.EntityGraph` the GUIDE path
produces, rather than a parallel type. Everything in :mod:`app.graph.traverse` — depth-capped BFS,
Dijkstra on −log(confidence), DFS lineage, hub detection — then works on WitFoo with no changes at
all. That reuse *is* the cross-domain portability claim, demonstrated rather than asserted, and it
costs nothing because the traversal layer never knew which dataset it was walking.

The interesting half is :class:`WitFooConfidence`. §8.5 requires saying plainly that the GUIDE
edge-confidence weights are hand-set; they are. WitFoo ships a confidence and a suspicion score on
every edge, so on this dataset the Dijkstra cost can be grounded in the data instead. The class
tracks how many edges it actually grounded versus fell back on, because "grounded in dataset
labels" is only worth saying about the edges where it is true.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from app.data import witfoo
from app.graph.build import EntityGraph, Node
from app.graph.confidence import MIN_CONFIDENCE

#: WitFoo edge types that represent bookkeeping rather than observed activity. An INCIDENT_LINK
#: joins an incident record to its entities; treating it as a traversal edge would let paths hop
#: between unrelated hosts through the incident node and report that as an attack chain.
NON_ACTIVITY_EDGES = frozenset({"INCIDENT_LINK"})


@dataclass
class WitFooGraph:
    """An EntityGraph plus the WitFoo edge labels that produced it."""

    graph: EntityGraph
    #: (src, dst) -> the label block, for confidence lookup and UI display.
    edge_labels: dict[tuple[Node, Node], witfoo.EdgeLabels] = field(default_factory=dict)
    #: incident id -> the edges witnessing it.
    incident_edges: dict[str, list[tuple[Node, Node]]] = field(
        default_factory=lambda: defaultdict(list)
    )
    edges_read: int = 0
    edges_used: int = 0
    edges_skipped_type: int = 0

    def labels_for(self, a: Node, b: Node) -> witfoo.EdgeLabels | None:
        return self.edge_labels.get((a, b)) or self.edge_labels.get((b, a))

    def nodes_for_incident(self, incident_id: str) -> list[Node]:
        seen: list[Node] = []
        for src, dst in self.incident_edges.get(incident_id, []):
            for node in (src, dst):
                if node not in seen:
                    seen.append(node)
        return seen

    def stats(self) -> dict:
        return {
            "nodes": self.graph.node_count,
            "edges": self.graph.edge_count,
            "edges_read": self.edges_read,
            "edges_used": self.edges_used,
            "edges_skipped_link_type": self.edges_skipped_type,
            "incidents": len(self.incident_edges),
        }


def build(
    nodes: dict[str, dict] | None = None,
    edges=None,
    incidents_only: bool = False,
    max_edges: int | None = None,
) -> WitFooGraph:
    """Assemble a :class:`WitFooGraph` from node and edge records.

    ``incidents_only`` keeps just the edges carrying an incident id, which is what the per-incident
    provenance views need and is a small fraction of the 634,190 total.
    """
    nodes = nodes if nodes is not None else witfoo.load_nodes()
    edges = edges if edges is not None else witfoo.iter_edges()

    result = WitFooGraph(graph=EntityGraph())

    for edge in edges:
        result.edges_read += 1
        if max_edges is not None and result.edges_used >= max_edges:
            break

        edge_type = str(edge.get("type", "") or "").upper()
        if edge_type in NON_ACTIVITY_EDGES:
            result.edges_skipped_type += 1
            continue

        endpoints = witfoo.edge_endpoints(edge, nodes)
        if endpoints is None:
            continue
        src, dst = endpoints

        labels = witfoo.EdgeLabels.from_edge(edge)
        if incidents_only and not labels.incident_ids:
            continue

        # An incident id where available, so a traversal can be scoped the way the GUIDE path
        # scopes by incident. Edges outside any incident are still real observed activity.
        scope = labels.incident_ids[0] if labels.incident_ids else "witfoo-corpus"
        alert = str(edge.get("edge_id", "") or f"{src}-{dst}")

        result.graph.add_node(src, scope, alert)
        result.graph.add_node(dst, scope, alert)
        result.graph.add_edge(src, dst, scope)

        result.edge_labels[(src, dst)] = labels
        for incident_id in labels.incident_ids:
            result.incident_edges[incident_id].append((src, dst))
        result.edges_used += 1

    return result


class WitFooConfidence:
    """Edge confidence taken from the dataset rather than from hand-set weights.

    Implements the same ``confidence(a, b) -> float`` contract as
    :class:`app.graph.confidence.ConfidenceModel`, so it drops straight into
    :func:`app.graph.traverse.most_probable_path`.

    Precedence: ``suspicion_score`` when the dataset scored the edge, otherwise a value derived
    from the threat label and ``label_confidence``, otherwise a neutral fallback. Every result is
    clamped to ``MIN_CONFIDENCE`` so ``-log(confidence)`` stays finite — the §8.2 requirement,
    which applies no matter where the number came from.
    """

    #: How much an unscored edge of each threat label is believed to represent a real relationship.
    #: Used only where the dataset gave us nothing better, and counted separately.
    _LABEL_PRIOR = {"malicious": 0.85, "suspicious": 0.6, "benign": 0.35, "": 0.4}

    def __init__(self, witfoo_graph: WitFooGraph) -> None:
        self.witfoo_graph = witfoo_graph
        self.grounded = 0
        self.fallback = 0

    def confidence(self, a: Node, b: Node) -> float:
        labels = self.witfoo_graph.labels_for(a, b)
        if labels is None:
            self.fallback += 1
            return self._LABEL_PRIOR[""]

        if labels.scored:
            self.grounded += 1
            # suspicion_score is the dataset's own strength-of-evidence figure; prefer it, and
            # fall back to label_confidence when it is absent.
            score = labels.suspicion_score or labels.label_confidence
            return max(MIN_CONFIDENCE, min(1.0, score))

        self.fallback += 1
        prior = self._LABEL_PRIOR.get(labels.threat_label, self._LABEL_PRIOR[""])
        return max(MIN_CONFIDENCE, min(1.0, prior))

    def source_breakdown(self) -> dict:
        """How much of a path's confidence actually came from the dataset.

        Reported alongside any attack path so the grounding claim is quantified rather than
        implied.
        """
        total = self.grounded + self.fallback
        return {
            # Lookups, not edges: Dijkstra queries the same edge more than once while relaxing,
            # so calling these "edges" would overstate the corpus every time a path is computed.
            "grounded_lookups": self.grounded,
            "fallback_lookups": self.fallback,
            "grounded_fraction": round(self.grounded / total, 4) if total else 0.0,
        }
