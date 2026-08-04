"""Graph traversal: blast radius and attack-path reconstruction.

Two algorithms, each answering a question an analyst actually asks:

* **Blast radius** — "what else is touched?" Depth-capped BFS, O(V + E).
* **Attack chain** — "how did it get from here to there?" Dijkstra over ``-log(confidence)``.

## The hub problem is not hypothetical

§8.4 names an uncapped traversal from a hub node as the single most likely cause of the demo
freezing in front of judges. The Day 3 graph build found the real worst case in this corpus:
``process:6`` at degree 1,025. Expansion is therefore capped at 2-3 hops *and* refuses to expand
through nodes above a degree threshold. A hub can be *reached* and reported — it is a real part of
the blast radius — but the frontier does not fan out through it.

## Why -log(confidence) and not 1 - confidence

Both were proposed; they are not interchangeable and only one supports the claim being made
(§8.2). Minimising Σ(1 − c) minimises average edge weakness. Minimising Σ(−log c) *maximises the
product of confidences*, which is the actual probability of the path.

    Path A: 0.50, 0.99   ->  true probability 0.4950
    Path B: 0.74, 0.74   ->  true probability 0.5476

    cost = 1 - c      ->  A 0.5100, B 0.5200  ->  picks A   (wrong)
    cost = -log(c)    ->  A 0.7032, B 0.6022  ->  picks B   (correct)

The linear cost systematically prefers a path containing one very weak link, which is exactly the
path an analyst would distrust. All ``-log(c)`` costs are non-negative for c ≤ 1, so Dijkstra
remains valid.
"""

from __future__ import annotations

import heapq
from collections import deque
from dataclasses import dataclass, field
from math import exp, log
from typing import Callable, Iterable

from app.graph.build import DEFAULT_HUB_DEGREE, EntityGraph, Node, node_label

DEFAULT_MAX_HOPS = 2
DEFAULT_MAX_NODES = 400
MIN_CONFIDENCE = 0.01


# --- blast radius ------------------------------------------------------------------------------

@dataclass
class BlastRadius:
    """Entities reachable from the seeds within the hop cap."""

    seeds: list[Node]
    by_hop: dict[int, list[Node]] = field(default_factory=dict)
    hubs_blocked: list[Node] = field(default_factory=list)
    truncated: bool = False
    visited_count: int = 0

    @property
    def nodes(self) -> list[Node]:
        return [node for hop in sorted(self.by_hop) for node in self.by_hop[hop]]

    def by_type(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for entity_type, value in self.nodes:
            grouped.setdefault(entity_type, []).append(value)
        return {k: sorted(v) for k, v in sorted(grouped.items())}

    def as_dict(self) -> dict:
        return {
            "seeds": [node_label(n) for n in self.seeds],
            "hops": {
                str(hop): [node_label(n) for n in nodes]
                for hop, nodes in sorted(self.by_hop.items())
            },
            "impacted_by_type": self.by_type(),
            "total_nodes": len(self.nodes),
            "hubs_blocked": [node_label(n) for n in self.hubs_blocked],
            "truncated": self.truncated,
        }


def blast_radius(
    graph: EntityGraph,
    seeds: Iterable[Node],
    max_hops: int = DEFAULT_MAX_HOPS,
    hub_degree: int = DEFAULT_HUB_DEGREE,
    max_nodes: int = DEFAULT_MAX_NODES,
    incident_id: str | None = None,
) -> BlastRadius:
    """Depth-capped BFS from the seed entities.

    A hub is included in the results when reached — it is genuinely affected — but is never
    expanded *through*. Without that, one shared NAT address or ``powershell.exe`` returns most of
    the graph, which is both useless to an analyst and slow enough to stall a live demo.

    ``max_nodes`` is a second, independent belt: even with hubs excluded, a dense enough
    neighbourhood should degrade to a truncated answer rather than an unbounded one.
    """
    seeds = [s for s in seeds if s in graph.adjacency]
    result = BlastRadius(seeds=list(seeds))
    if not seeds or max_hops < 1:
        return result

    seen: set[Node] = set(seeds)
    blocked: list[Node] = []
    queue: deque[tuple[Node, int]] = deque((s, 0) for s in seeds)

    while queue:
        node, depth = queue.popleft()
        result.visited_count += 1

        if depth >= max_hops:
            continue
        if graph.degree(node) >= hub_degree and depth > 0:
            # Reached a hub: report it, do not fan out through it.
            blocked.append(node)
            continue

        for neighbour in sorted(graph.neighbours(node)):
            if neighbour in seen:
                continue
            if incident_id is not None and incident_id not in graph.node_incidents.get(
                neighbour, set()
            ):
                continue

            seen.add(neighbour)
            result.by_hop.setdefault(depth + 1, []).append(neighbour)

            if len(seen) - len(seeds) >= max_nodes:
                result.truncated = True
                result.hubs_blocked = blocked
                return result

            queue.append((neighbour, depth + 1))

    result.hubs_blocked = blocked
    return result


# --- attack path -------------------------------------------------------------------------------

def edge_cost(confidence: float) -> float:
    """``-log(confidence)``, with the floor applied first.

    Clamping before the log is what stops a zero-confidence edge producing an infinite cost and
    quietly deleting a path from consideration (§8.2).
    """
    return -log(max(MIN_CONFIDENCE, min(1.0, confidence)))


@dataclass
class AttackPath:
    """The most probable chain between two entities."""

    nodes: list[Node]
    total_cost: float
    edge_confidences: list[float] = field(default_factory=list)

    @property
    def probability(self) -> float:
        """Product of the edge confidences — the quantity Dijkstra actually maximised."""
        return exp(-self.total_cost) if self.nodes else 0.0

    @property
    def weakest_link(self) -> float:
        return min(self.edge_confidences) if self.edge_confidences else 0.0

    def as_dict(self) -> dict:
        return {
            "path": [node_label(n) for n in self.nodes],
            "hops": max(0, len(self.nodes) - 1),
            "probability": round(self.probability, 6),
            "total_cost": round(self.total_cost, 6),
            "edge_confidences": [round(c, 4) for c in self.edge_confidences],
            "weakest_link": round(self.weakest_link, 4),
        }


def most_probable_path(
    graph: EntityGraph,
    source: Node,
    target: Node,
    confidence_fn: Callable[[Node, Node], float],
    hub_degree: int = DEFAULT_HUB_DEGREE,
    max_expansions: int = 20_000,
) -> AttackPath | None:
    """Dijkstra over ``-log(confidence)``, returning the highest-probability chain.

    ``max_expansions`` bounds the search on a corpus-wide graph. Reaching it means the answer is
    "no credible path found within budget", which is an honest result and infinitely better than a
    frozen UI.
    """
    if source not in graph.adjacency or target not in graph.adjacency:
        return None
    if source == target:
        return AttackPath(nodes=[source], total_cost=0.0)

    dist: dict[Node, float] = {source: 0.0}
    previous: dict[Node, Node] = {}
    settled: set[Node] = set()
    # node_label in the tuple keeps the heap totally ordered without comparing raw tuples in a
    # way that could raise on mixed types (§8.1).
    heap: list[tuple[float, str, Node]] = [(0.0, node_label(source), source)]
    expansions = 0

    while heap:
        cost, _, node = heapq.heappop(heap)
        if node in settled:
            continue
        settled.add(node)

        if node == target:
            break

        expansions += 1
        if expansions > max_expansions:
            return None
        # Do not route *through* a hub; it connects everything to everything and any path using
        # it is an artefact of the hub, not evidence of an attack chain.
        if node != source and graph.degree(node) >= hub_degree:
            continue

        for neighbour in sorted(graph.neighbours(node)):
            if neighbour in settled:
                continue
            candidate = cost + edge_cost(confidence_fn(node, neighbour))
            if candidate < dist.get(neighbour, float("inf")):
                dist[neighbour] = candidate
                previous[neighbour] = node
                heapq.heappush(heap, (candidate, node_label(neighbour), neighbour))

    if target not in dist:
        return None

    path: list[Node] = [target]
    while path[-1] != source:
        path.append(previous[path[-1]])
    path.reverse()

    confidences = [confidence_fn(a, b) for a, b in zip(path, path[1:])]
    return AttackPath(nodes=path, total_cost=dist[target], edge_confidences=confidences)


def process_lineage(
    graph: EntityGraph,
    source: Node,
    max_depth: int = 4,
    hub_degree: int = DEFAULT_HUB_DEGREE,
    incident_id: str | None = None,
) -> list[Node]:
    """DFS lineage from a seed entity.

    DFS returns *one* complete chain, not the best one — §8.2 is explicit about that limitation,
    which is why :func:`most_probable_path` exists. This is useful for showing a reachable
    sequence, not for claiming it is the likely one.
    """
    if source not in graph.adjacency:
        return []

    best: list[Node] = []
    stack: list[tuple[Node, list[Node]]] = [(source, [source])]
    seen: set[Node] = set()

    while stack:
        node, path = stack.pop()
        if len(path) > len(best):
            best = path
        if len(path) >= max_depth:
            continue
        if node in seen:
            continue
        seen.add(node)
        if node != source and graph.degree(node) >= hub_degree:
            continue

        for neighbour in sorted(graph.neighbours(node), reverse=True):
            if neighbour in path:
                continue
            if incident_id is not None and incident_id not in graph.node_incidents.get(
                neighbour, set()
            ):
                continue
            stack.append((neighbour, path + [neighbour]))

    return best
