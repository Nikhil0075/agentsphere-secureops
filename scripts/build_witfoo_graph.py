"""Reduce the 435 MB WitFoo edge file to something the API can hold.

    python scripts/build_witfoo_graph.py

One streaming pass over ``graph/edges.jsonl``, writing ``artifacts/witfoo/``:

* ``incident_edges.jsonl`` — only the edges carrying an incident id, which is all the per-incident
  provenance views need;
* ``incidents.json`` — per-incident summaries joined with the attack reports;
* ``graph_stats.json`` — the same shape as ``artifacts/graph/degree_stats.json``, so the metrics
  page renders GUIDE and WitFoo side by side with no new component.

After this the 435 MB file is never read again, the same pattern ``build_index.py`` uses.

The run **reconciles its own counts against the dataset's ``graph/metadata.json``** and says so
either way. Quoting the dataset card's 35,133 / 634,190 while silently having parsed fewer would
be exactly the citation failure §7 warns about.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import ARTIFACTS, ensure_dirs  # noqa: E402
from app.data import witfoo  # noqa: E402
from app.graph.build import node_label  # noqa: E402
from app.graph.witfoo_graph import NON_ACTIVITY_EDGES  # noqa: E402

OUT_DIR = ARTIFACTS / "witfoo"
INCIDENT_EDGES = OUT_DIR / "incident_edges.jsonl"
INCIDENTS = OUT_DIR / "incidents.json"
STATS = OUT_DIR / "graph_stats.json"

HUB_DEGREE = 150


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hub-degree", type=int, default=HUB_DEGREE)
    args = parser.parse_args()

    ensure_dirs()
    if not witfoo.available():
        print(
            "WitFoo data missing. Run: python scripts/download_witfoo.py", file=sys.stderr
        )
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("loading nodes ...", flush=True)
    nodes = witfoo.load_nodes()
    reports = witfoo.load_attack_reports()
    declared = witfoo.load_metadata()
    print(f"  {len(nodes):,} nodes, {len(reports):,} attack reports")

    print("streaming edges (435 MB, single pass) ...", flush=True)
    started = time.perf_counter()

    adjacency: dict[tuple, set] = defaultdict(set)
    edge_types: Counter[str] = Counter()
    threat_labels: Counter[str] = Counter()
    node_types: Counter[str] = Counter()
    per_incident: dict[str, dict] = defaultdict(
        lambda: {"edges": 0, "nodes": set(), "techniques": set(), "labels": Counter()}
    )

    edges_read = 0
    edges_used = 0
    skipped_link = 0
    unresolved = 0
    scored_edges = 0
    kept = 0
    # Node accounting. The traversal graph reaches far fewer nodes than the dataset declares, and
    # the difference has to be explained rather than reported as a bare smaller number: most of
    # the remainder are entities that only ever appear on an INCIDENT_LINK edge, so they have
    # incident membership but no observed activity between entities.
    activity_endpoints: set[str] = set()
    link_endpoints: set[str] = set()
    undeclared_endpoints: set[str] = set()

    with INCIDENT_EDGES.open("w", encoding="utf-8") as out:
        for edge in witfoo.iter_edges():
            edges_read += 1
            if edges_read % 100_000 == 0:
                print(f"  {edges_read:,} edges ...", end="\r", flush=True)

            edge_type = str(edge.get("type", "") or "").upper()
            edge_types[edge_type] += 1

            raw_ends = [str(e) for e in (edge.get("src"), edge.get("dst")) if e]
            undeclared_endpoints.update(e for e in raw_ends if e not in nodes)

            if edge_type in NON_ACTIVITY_EDGES:
                skipped_link += 1
                link_endpoints.update(raw_ends)
                continue

            activity_endpoints.update(raw_ends)

            endpoints = witfoo.edge_endpoints(edge, nodes)
            if endpoints is None:
                unresolved += 1
                continue
            src, dst = endpoints

            labels = witfoo.EdgeLabels.from_edge(edge)
            threat_labels[labels.threat_label or "unlabelled"] += 1
            if labels.scored:
                scored_edges += 1

            adjacency[src].add(dst)
            adjacency[dst].add(src)
            edges_used += 1

            if labels.incident_ids:
                # Keep a compact record: enough to rebuild the subgraph and render it, nothing
                # more. The full edge carries twenty fields the UI never reads.
                out.write(
                    json.dumps(
                        {
                            "src": [src[0], src[1]],
                            "dst": [dst[0], dst[1]],
                            "type": edge_type,
                            "timestamp": edge.get("timestamp"),
                            "threat_label": labels.threat_label,
                            "label_confidence": labels.label_confidence,
                            "suspicion_score": labels.suspicion_score,
                            "scored": labels.scored,
                            "attack_techniques": labels.attack_techniques,
                            "incident_ids": labels.incident_ids,
                            "matched_rules": labels.matched_rules,
                        },
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                kept += 1
                for incident_id in labels.incident_ids:
                    bucket = per_incident[incident_id]
                    bucket["edges"] += 1
                    bucket["nodes"].update({node_label(src), node_label(dst)})
                    bucket["techniques"].update(labels.attack_techniques)
                    bucket["labels"][labels.threat_label or "unlabelled"] += 1

    elapsed = time.perf_counter() - started
    print(f"  {edges_read:,} edges read in {elapsed:.1f}s" + " " * 20)

    # --- incidents ------------------------------------------------------------------------
    incidents = []
    for incident_id, bucket in sorted(per_incident.items()):
        report = reports.get(incident_id, {})
        incidents.append(
            {
                "incident_id": incident_id,
                "mo_name": report.get("mo_name", ""),
                "disposition": report.get("disposition", ""),
                "disposition_category": report.get("disposition_category", ""),
                "status_name": report.get("status_name", ""),
                "lifecycle_stage": report.get("lifecycle_stage", ""),
                "suspicion_score": report.get("suspicion_score", 0.0),
                # Techniques from the edges we actually parsed, falling back to the report's own
                # list when the edges carried none.
                "attack_techniques": sorted(bucket["techniques"])
                or list(report.get("attack_techniques") or []),
                "attack_tactics": list(report.get("attack_tactics") or []),
                "matched_rules": list(report.get("matched_rules") or []),
                "products_observed": list(report.get("products_observed") or []),
                "edge_count": bucket["edges"],
                "node_count": len(bucket["nodes"]),
                "threat_labels": dict(bucket["labels"]),
                "first_observed_at": report.get("first_observed_at"),
                "last_observed_at": report.get("last_observed_at"),
                "report_text": (report.get("report_text") or "")[:1500],
            }
        )
    incidents.sort(key=lambda i: (-float(i["suspicion_score"] or 0.0), i["incident_id"]))
    INCIDENTS.write_text(json.dumps(incidents, indent=2), encoding="utf-8")

    # --- stats ----------------------------------------------------------------------------
    degrees = sorted(
        ((node, len(neighbours)) for node, neighbours in adjacency.items()),
        key=lambda kv: (-kv[1], node_label(kv[0])),
    )
    values = [d for _, d in degrees] or [0]

    # Distinct nodes per type. Counting endpoint occurrences instead would report 711,022
    # "devices" against a graph of 16,586 nodes — a number that describes traffic volume while
    # appearing to describe the graph.
    for node in adjacency:
        node_types[node[0]] += 1

    declared_nodes = declared.get("node_count")
    declared_edges = declared.get("edge_count")

    stats = {
        "source": "witfoo/precinct6-cybersecurity",
        "licence": "Apache-2.0",
        "declared": {"nodes": declared_nodes, "edges": declared_edges},
        "parsed": {
            "edges_read": edges_read,
            "edges_used": edges_used,
            "nodes": len(adjacency),
            "skipped_incident_link": skipped_link,
            "unresolved_endpoints": unresolved,
            "incident_edges_kept": kept,
        },
        # Full node accounting, so a reader can add the parts up and get the declared total.
        # "16,586 nodes" on its own invites the reasonable suspicion that data was dropped.
        "node_accounting": {
            "declared": declared_nodes,
            "on_activity_edges": len(activity_endpoints & set(nodes)),
            "only_on_incident_link": len((link_endpoints - activity_endpoints) & set(nodes)),
            "on_no_edge": len(set(nodes) - activity_endpoints - link_endpoints),
            "endpoints_not_declared_in_nodes_file": len(undeclared_endpoints),
        },
        "reconciles": {
            "edges": declared_edges == edges_read if declared_edges else None,
            "nodes": (
                len(activity_endpoints & set(nodes))
                + len((link_endpoints - activity_endpoints) & set(nodes))
                + len(set(nodes) - activity_endpoints - link_endpoints)
                == declared_nodes
                if declared_nodes
                else None
            ),
        },
        "grounding": {
            "scored_edges": scored_edges,
            "scored_fraction": round(scored_edges / edges_used, 4) if edges_used else 0.0,
        },
        "edge_types": dict(edge_types),
        # Counted over activity edges only, so these are lower than the dataset's declared totals
        # by exactly the INCIDENT_LINK edges we exclude. Every INCIDENT_LINK edge is labelled
        # malicious, which is why that class is the one that shifts.
        "threat_labels": dict(threat_labels),
        "threat_label_reconciliation": {
            "note": (
                "activity-only counts; declared totals include INCIDENT_LINK edges, which are "
                "excluded from traversal and are all labelled malicious"
            ),
            "malicious_activity": threat_labels.get("malicious", 0),
            "plus_incident_link": skipped_link,
            "plus_unresolved": unresolved,
            "equals_declared": threat_labels.get("malicious", 0) + skipped_link + unresolved,
        },
        "node_types": dict(node_types),
        "max_degree": values[0],
        "median_degree": values[len(values) // 2],
        "mean_degree": round(sum(values) / len(values), 2),
        "hub_degree_threshold": args.hub_degree,
        "hub_count": sum(1 for v in values if v >= args.hub_degree),
        "hubs": [
            {"node": node_label(node), "degree": degree} for node, degree in degrees[:20]
        ],
        "incidents": len(incidents),
        "build_seconds": round(elapsed, 2),
    }
    STATS.write_text(json.dumps(stats, indent=2, sort_keys=True), encoding="utf-8")

    # --- report -----------------------------------------------------------------------------
    print(f"\n{'=' * 66}")
    print(f"declared by the dataset : {declared_nodes:,} nodes / {declared_edges:,} edges")
    print(f"edges read              : {edges_read:,}")
    print(f"edges used              : {edges_used:,}  "
          f"(skipped {skipped_link:,} INCIDENT_LINK, {unresolved:,} unresolved)")
    accounting = stats["node_accounting"]
    print(f"nodes in traversal graph: {len(adjacency):,}")
    print(f"  on activity edges     : {accounting['on_activity_edges']:,}")
    print(f"  only on INCIDENT_LINK : {accounting['only_on_incident_link']:,}  "
          f"(incident membership, no observed activity)")
    print(f"  on no edge at all     : {accounting['on_no_edge']:,}")
    print(f"  endpoints missing from nodes.jsonl: "
          f"{accounting['endpoints_not_declared_in_nodes_file']:,}  (typed from the id)")
    print(f"edge reconciliation     : "
          f"{'MATCHES the dataset metadata' if declared_edges == edges_read else 'DIFFERS - see graph_stats.json'}")
    print(f"node reconciliation     : "
          f"{'parts sum to the declared total' if stats['reconciles']['nodes'] else 'DOES NOT sum - see graph_stats.json'}")
    print(f"scored edges            : {scored_edges:,} "
          f"({stats['grounding']['scored_fraction']:.1%} carry dataset confidence)")
    print(f"incidents with edges    : {len(incidents):,}")
    print(f"incident edges kept     : {kept:,}")
    print(f"worst hub               : {stats['hubs'][0]['node']} at degree {stats['max_degree']:,}"
          if stats["hubs"] else "worst hub               : none")
    print(f"\nartifacts -> {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
