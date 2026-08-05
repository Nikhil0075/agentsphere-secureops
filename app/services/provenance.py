"""WitFoo provenance service.

Loads the reduced artifacts produced by ``scripts/build_witfoo_graph.py`` and serves per-incident
provenance subgraphs. Follows the ``load_if_available`` pattern from
:mod:`app.retrieval.hybrid`: when the artifacts are absent everything returns empty and the rest
of the system is unaffected. This is an additive feature and must never be able to take the
frozen Phase 0 demo down.

The subgraphs are small — the dataset's own attack reports report node counts in the single digits
for many incidents — so a per-incident view needs no sampling and cannot fan out the way an
uncapped traversal of the GUIDE corpus graph can.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from app.config import ARTIFACTS
from app.data import witfoo
from app.graph.build import EntityGraph, Node, node_label
from app.graph.witfoo_graph import WitFooConfidence, WitFooGraph

WITFOO_ARTIFACTS = ARTIFACTS / "witfoo"
INCIDENT_EDGES = WITFOO_ARTIFACTS / "incident_edges.jsonl"
INCIDENTS = WITFOO_ARTIFACTS / "incidents.json"
STATS = WITFOO_ARTIFACTS / "graph_stats.json"


@dataclass
class ProvenanceStore:
    """Per-incident provenance, held in memory.

    Only the incident-linked edges are loaded — 155,456 of the corpus's 634,190 — which is what
    makes holding this reasonable at all.
    """

    incidents: list[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    signal_metadata: dict = field(default_factory=dict)
    _by_incident: dict[str, list[dict]] = field(default_factory=lambda: defaultdict(list))
    _index: dict[str, dict] = field(default_factory=dict)

    @property
    def available(self) -> bool:
        return bool(self.incidents)

    # --- loading ------------------------------------------------------------------------

    @classmethod
    def load(cls, directory: str | Path = WITFOO_ARTIFACTS) -> "ProvenanceStore":
        directory = Path(directory)
        incidents_file = directory / "incidents.json"
        edges_file = directory / "incident_edges.jsonl"
        if not incidents_file.exists() or not edges_file.exists():
            return cls()

        try:
            incidents = json.loads(incidents_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return cls()

        store = cls(
            incidents=incidents,
            stats=witfoo.load_metadata(directory / "graph_stats.json"),
            signal_metadata=witfoo.load_signal_metadata(),
        )
        store._index = {i["incident_id"]: i for i in incidents}
        for edge in witfoo.iter_jsonl(edges_file):
            for incident_id in edge.get("incident_ids") or []:
                store._by_incident[str(incident_id)].append(edge)
        return store

    # --- queries ------------------------------------------------------------------------

    def list_incidents(
        self, limit: int = 50, offset: int = 0, search: str = "", mo_name: str = ""
    ) -> list[dict]:
        rows = self.incidents
        if mo_name:
            rows = [r for r in rows if r.get("mo_name") == mo_name]
        if search:
            needle = search.lower()
            rows = [
                r
                for r in rows
                if needle in r["incident_id"].lower()
                or needle in str(r.get("mo_name", "")).lower()
                or needle in " ".join(r.get("attack_techniques") or []).lower()
            ]
        return rows[offset : offset + limit]

    def incident(self, incident_id: str) -> dict | None:
        return self._index.get(incident_id)

    def mo_names(self) -> list[str]:
        return sorted({r.get("mo_name", "") for r in self.incidents if r.get("mo_name")})

    def edges_for(self, incident_id: str) -> list[dict]:
        return self._by_incident.get(incident_id, [])

    def subgraph(self, incident_id: str) -> WitFooGraph | None:
        """Rebuild one incident's provenance subgraph as a real :class:`EntityGraph`.

        Returns the WitFoo wrapper so the edge labels travel with it — the UI colours edges by
        their dataset threat label, and the confidence model reads the same records.
        """
        edges = self.edges_for(incident_id)
        if not edges:
            return None

        result = WitFooGraph(graph=EntityGraph())
        for edge in edges:
            src: Node = (edge["src"][0], edge["src"][1])
            dst: Node = (edge["dst"][0], edge["dst"][1])
            if src == dst:
                continue
            alert = f"{node_label(src)}->{node_label(dst)}"
            result.graph.add_node(src, incident_id, alert)
            result.graph.add_node(dst, incident_id, alert)
            result.graph.add_edge(src, dst, incident_id)
            result.edge_labels[(src, dst)] = witfoo.EdgeLabels(
                threat_label=edge.get("threat_label", ""),
                label_confidence=float(edge.get("label_confidence", 0.0) or 0.0),
                suspicion_score=float(edge.get("suspicion_score", 0.0) or 0.0),
                attack_techniques=list(edge.get("attack_techniques") or []),
                incident_ids=list(edge.get("incident_ids") or []),
                matched_rules=list(edge.get("matched_rules") or []),
            )
            result.incident_edges[incident_id].append((src, dst))
            result.edges_used += 1
        result.edges_read = len(edges)
        return result

    def confidence_model(self, subgraph: WitFooGraph) -> WitFooConfidence:
        return WitFooConfidence(subgraph)

    def summary(self) -> dict:
        """What the dataset panels report. Every figure traces to a file, not to a constant."""
        parsed = self.stats.get("parsed", {})
        declared = self.stats.get("declared", {})
        return {
            "available": self.available,
            "source": self.stats.get("source", "witfoo/precinct6-cybersecurity"),
            "licence": self.stats.get("licence", "Apache-2.0"),
            "declared_nodes": declared.get("nodes"),
            "declared_edges": declared.get("edges"),
            "edges_read": parsed.get("edges_read"),
            "edges_used": parsed.get("edges_used"),
            "graph_nodes": parsed.get("nodes"),
            "incidents": len(self.incidents),
            "incident_edges": parsed.get("incident_edges_kept"),
            "reconciles": self.stats.get("reconciles", {}),
            "node_accounting": self.stats.get("node_accounting", {}),
            "grounding": self.stats.get("grounding", {}),
            "threat_labels": self.stats.get("threat_labels", {}),
            "edge_types": self.stats.get("edge_types", {}),
            "max_degree": self.stats.get("max_degree"),
            "signals": self.signal_metadata.get("total_records"),
            # Stated on every response that carries WitFoo data, because the distinction is easy
            # to lose once the numbers are on a screen next to GUIDE's.
            "label_note": (
                "WitFoo labels are threat assessments (benign/suspicious/malicious), not the "
                "analyst triage verdicts GUIDE carries. They are excluded from all triage metrics."
            ),
        }


def load_if_available(directory: str | Path = WITFOO_ARTIFACTS) -> ProvenanceStore:
    """Never raises. An absent WitFoo dataset degrades the Provenance tab and nothing else."""
    try:
        return ProvenanceStore.load(directory)
    except Exception:  # noqa: BLE001 - an additive feature must not break startup
        return ProvenanceStore()
