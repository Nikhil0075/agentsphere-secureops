"""Build the entity graph and record its degree statistics.

    python scripts/build_graph.py
    python scripts/build_graph.py --showcase-only

Writes ``artifacts/graph/degree_stats.json``. Everything graph-related on Day 4 — BFS blast
radius, Dijkstra attack paths — depends on this file existing and on its hub list being honest.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import GRAPH_DIR, ensure_dirs  # noqa: E402
from app.data import loader  # noqa: E402
from app.graph import build as graph_build  # noqa: E402
from app.graph.correlate import correlate  # noqa: E402

STATS_PATH = GRAPH_DIR / "degree_stats.json"
CORRELATION_PATH = GRAPH_DIR / "correlation_summary.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--showcase-only", action="store_true")
    parser.add_argument("--hub-degree", type=int, default=graph_build.DEFAULT_HUB_DEGREE)
    args = parser.parse_args()

    ensure_dirs()
    evidence, incidents = loader.load_prepared()

    if args.showcase_only and "is_showcase" in incidents:
        keep = set(incidents[incidents["is_showcase"]]["incident_id"])
        evidence = evidence[evidence["incident_id"].isin(keep)]
        print(f"restricted to {len(keep)} showcase incidents")

    start = time.perf_counter()
    graph = graph_build.build(evidence)
    elapsed = time.perf_counter() - start

    stats = graph_build.write_degree_stats(graph, STATS_PATH, threshold=args.hub_degree)
    stats["build_seconds"] = round(elapsed, 2)
    STATS_PATH.write_text(json.dumps(stats, indent=2, sort_keys=True), encoding="utf-8")

    print(f"graph: {stats['nodes']:,} nodes, {stats['edges']:,} edges in {elapsed:.1f}s")
    print(f"degree: max {stats['max_degree']}, median {stats['median_degree']}, "
          f"mean {stats['mean_degree']}")
    print(f"hubs at degree >= {args.hub_degree}: {stats['hub_count']}")
    for hub in stats["hubs"][:5]:
        print(f"  {hub['node']:32s} degree {hub['degree']:6d}  incidents {hub['incidents']:5d}")

    # Correlation over the showcase set: this is what the UI renders.
    showcase_ids = (
        set(incidents[incidents["is_showcase"]]["incident_id"])
        if "is_showcase" in incidents
        else set()
    )
    summaries = []
    for incident_id in sorted(showcase_ids):
        rows = evidence[evidence["incident_id"] == incident_id]
        if rows.empty:
            continue
        result = correlate(rows)
        summaries.append({"incident_id": incident_id, **result.as_dict()})

    if summaries:
        collapsed = [s for s in summaries if s["clusters"] < s["alerts"]]
        payload = {
            "showcase_incidents": len(summaries),
            "incidents_where_alerts_collapsed": len(collapsed),
            "per_incident": summaries,
        }
        CORRELATION_PATH.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
        print(
            f"\ncorrelation: {len(collapsed)}/{len(summaries)} showcase incidents have alerts "
            f"that collapse into fewer clusters"
        )
        for s in sorted(summaries, key=lambda x: -x["reduction"])[:5]:
            print(
                f"  {s['incident_id']}  {s['alerts']:4d} alerts -> {s['clusters']:4d} clusters "
                f"({s['reduction']:.0%} reduction)"
            )

    print(f"\nstats -> {STATS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
