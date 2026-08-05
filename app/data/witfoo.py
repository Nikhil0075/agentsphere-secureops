"""WitFoo Precinct6 ingest.

The master plan's §8.4 problem, solved from the other direction: GUIDE is tabular, so the entity
graph has to be *constructed* from evidence rows. WitFoo **ships** a provenance graph — 35,133
typed nodes and 634,190 labelled edges — and each edge carries the dataset's own confidence, which
is what lets the Dijkstra attack path stop resting on hand-set weights.

Two things about the source shape the code here.

**The Hub's parquet configs are broken, so this reads JSONL over plain HTTP.** The dataset's YAML
declares ``graph/nodes.jsonl``, ``graph/edges.jsonl`` and ``graph/incidents.jsonl`` as ``parquet``;
they are JSONL, and ``datasets.load_dataset`` fails on all three with "Parquet magic bytes not
found in footer". The files are fine — only the declaration is wrong.

**Labels here are not GUIDE labels.** WitFoo's ``label_binary`` is benign/suspicious/malicious, a
*threat assessment*. GUIDE's ``IncidentGrade`` is TruePositive/BenignPositive/FalsePositive, an
analyst *triage verdict*. They are not interchangeable, and nothing in this module converts one to
the other. WitFoo is used for provenance, correlation and scale — never for the triage metrics.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from app.config import DATA_RAW

WITFOO_DIR = DATA_RAW / "witfoo"

NODES_FILE = WITFOO_DIR / "graph_nodes.jsonl"
EDGES_FILE = WITFOO_DIR / "graph_edges.jsonl"
REPORTS_FILE = WITFOO_DIR / "graph_attack_reports.jsonl"
GRAPH_META_FILE = WITFOO_DIR / "graph_metadata.json"
SIGNAL_META_FILE = WITFOO_DIR / "signals_metadata.json"
RULES_FILE = WITFOO_DIR / "reference_lead_rules_catalog.json"

#: WitFoo node type -> the canonical entity vocabulary in app/data/schema.py. HOST is resolved at
#: runtime because WitFoo HOST ids are sometimes IP addresses and sometimes hostnames.
WITFOO_NODE_TYPES = {
    "CREDENTIAL": "account",
    "CRED": "account",
    "ACTOR": "account",
    "SERVICE": "process",
    "FILE": "filehash",
    "HOST": "device",  # overridden to "ip" when the id parses as an address
}

#: Threat labels, kept under their own names precisely so they cannot be mistaken for triage
#: verdicts.
THREAT_LABELS = ("benign", "suspicious", "malicious")


def available() -> bool:
    """True when enough has been downloaded to build the graph."""
    return NODES_FILE.exists() and EDGES_FILE.exists()


# --- node typing ------------------------------------------------------------------------

def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def node_key(node_id: str, node_type: str, attrs: dict | None = None) -> tuple[str, str]:
    """Map a WitFoo node onto a canonical ``(entity_type, value)`` pair.

    A HOST whose id is ``10.136.248.162`` is an IP address and a HOST whose id is
    ``USER-0010-0001.domain-0022.example.net`` is a device. Typing both as "device" would merge two
    genuinely different entity kinds and make the blast radius read as if hosts and addresses were
    interchangeable.
    """
    attrs = attrs or {}
    canonical = WITFOO_NODE_TYPES.get(str(node_type).upper(), "device")

    if canonical == "device":
        bare = str(node_id).split(":", 1)[-1] if str(node_id).startswith("ip:") else str(node_id)
        if _is_ip(bare):
            return ("ip", bare)

    # Credential ids arrive as "user:USER-0001"; keep the value, drop the prefix.
    value = str(node_id)
    if ":" in value and value.split(":", 1)[0] in {"user", "cred", "ip", "file", "svc"}:
        value = value.split(":", 1)[1]
    return (canonical, value)


# --- streaming readers ---------------------------------------------------------------------

def iter_jsonl(path: str | Path, skip_bad: bool = True) -> Iterator[dict]:
    """Yield records from a JSONL file.

    Tolerates a truncated final line, which is what an interrupted download leaves behind. A
    partially written record should cost one row, not the whole ingest.
    """
    path = Path(path)
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                if skip_bad:
                    continue
                raise
            if isinstance(record, dict):
                yield record


def iter_edges(path: str | Path = EDGES_FILE) -> Iterator[dict]:
    """Stream the edge file. 435 MB — never held whole, the same discipline guide_loader applies."""
    yield from iter_jsonl(path)


def load_nodes(path: str | Path = NODES_FILE) -> dict[str, dict]:
    """Node id -> record. 35,133 nodes is small enough to hold."""
    return {str(r["node_id"]): r for r in iter_jsonl(path) if r.get("node_id")}


def load_attack_reports(path: str | Path = REPORTS_FILE) -> dict[str, dict]:
    """Incident id -> the per-incident report: MO name, MITRE, disposition, subgraph size."""
    return {str(r["incident_id"]): r for r in iter_jsonl(path) if r.get("incident_id")}


def load_metadata(path: str | Path = GRAPH_META_FILE) -> dict:
    """The dataset's own counts.

    Read rather than hard-coded, so every figure this project quotes about WitFoo traces to the
    dataset's own file — the §7 citation discipline, mechanically enforced.
    """
    path = Path(path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def load_signal_metadata(path: str | Path = SIGNAL_META_FILE) -> dict:
    meta = load_metadata(path)
    # The signal metadata carries a 294-entry message-type histogram that nothing here needs.
    return {
        "total_records": meta.get("total_records"),
        "columns": meta.get("columns", []),
        "label_distribution": meta.get("label_distribution", {}),
    }


def load_rules(path: str | Path = RULES_FILE) -> dict:
    return load_metadata(path)


# --- edge helpers -----------------------------------------------------------------------

@dataclass
class EdgeLabels:
    """The label block WitFoo attaches to every edge.

    ``label_binary`` is a threat assessment, not a triage verdict. The distinction is carried in
    the field name so it survives being passed around.
    """

    threat_label: str = ""
    label_confidence: float = 0.0
    suspicion_score: float = 0.0
    attack_techniques: list[str] = field(default_factory=list)
    attack_tactics: list[str] = field(default_factory=list)
    incident_ids: list[str] = field(default_factory=list)
    disposition: str = ""
    is_false_positive: bool = False
    matched_rules: list[str] = field(default_factory=list)

    @classmethod
    def from_edge(cls, edge: dict) -> "EdgeLabels":
        labels = edge.get("labels") or {}
        return cls(
            threat_label=str(labels.get("label_binary", "") or ""),
            label_confidence=float(labels.get("label_confidence", 0.0) or 0.0),
            suspicion_score=float(labels.get("suspicion_score", 0.0) or 0.0),
            attack_techniques=list(labels.get("attack_techniques") or []),
            attack_tactics=list(labels.get("attack_tactics") or []),
            incident_ids=[str(i) for i in (labels.get("incident_ids") or [])],
            disposition=str(labels.get("disposition", "") or ""),
            is_false_positive=bool(labels.get("is_false_positive", False)),
            matched_rules=list(labels.get("matched_rules") or []),
        )

    @property
    def scored(self) -> bool:
        """Whether the dataset actually scored this edge, rather than leaving the default.

        A ``label_confidence`` of exactly 0.5 on a benign edge is WitFoo's unscored default, not a
        measurement. Treating it as one would mean claiming grounding this dataset does not
        provide for that edge.
        """
        if self.suspicion_score > 0.0:
            return True
        return self.threat_label in {"malicious", "suspicious"} and self.label_confidence != 0.5


def edge_endpoints(edge: dict, nodes: dict[str, dict] | None = None) -> tuple | None:
    """Canonical ``(src_key, dst_key)`` for an edge, or None when either end is unusable."""
    src, dst = edge.get("src"), edge.get("dst")
    if not src or not dst:
        return None

    nodes = nodes or {}
    src_record = nodes.get(str(src), {})
    dst_record = nodes.get(str(dst), {})

    src_key = node_key(str(src), src_record.get("type", "HOST"), src_record.get("attrs"))
    dst_key = node_key(str(dst), dst_record.get("type", "HOST"), dst_record.get("attrs"))
    if src_key == dst_key:
        return None
    return (src_key, dst_key)
