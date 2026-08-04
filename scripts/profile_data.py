"""Profile the prepared dataset before anything is built on top of it.

    python scripts/profile_data.py

Writes ``artifacts/data_profile.json``. Answers the Day 1 questions: what does the label
distribution look like, what is missing, how many entities per incident, and — the one that
determines whether Day 4's BFS survives — how bad are the hub entities.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402

from app.config import ARTIFACTS, ensure_dirs  # noqa: E402
from app.data import loader  # noqa: E402
from app.data.schema import ENTITY_COLUMNS  # noqa: E402

OUTPUT = ARTIFACTS / "data_profile.json"
TOP_N = 10


def _missingness(frame: pd.DataFrame) -> dict[str, float]:
    out = {}
    for column in frame.columns:
        series = frame[column]
        blank = series.isna() | (series.astype(str).str.strip() == "")
        out[column] = round(float(blank.mean()), 4)
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _entity_hubs(evidence: pd.DataFrame) -> dict:
    """How many distinct incidents each entity value touches.

    A value touching hundreds of incidents is a hub: a shared NAT address, a service account,
    ``powershell.exe``. §8.4 flags these as the most likely cause of a demo freezing under an
    uncapped traversal, so they are identified on Day 1, not discovered on Day 4.
    """
    report = {}
    for entity_type, column in ENTITY_COLUMNS.items():
        if column not in evidence.columns:
            continue
        subset = evidence[[column, "incident_id"]].copy()
        subset[column] = subset[column].astype(str).str.strip()
        subset = subset[subset[column] != ""]
        if subset.empty:
            report[entity_type] = {"distinct_values": 0, "top": []}
            continue
        counts = subset.groupby(column)["incident_id"].nunique().sort_values(ascending=False)
        report[entity_type] = {
            "distinct_values": int(len(counts)),
            "max_incidents_touched": int(counts.iloc[0]),
            "top": [
                {"value": str(value), "incidents": int(n)}
                for value, n in counts.head(TOP_N).items()
            ],
        }
    return report


def main() -> int:
    ensure_dirs()
    evidence, incidents = loader.load_prepared()

    per_incident_evidence = incidents["evidence_count"]
    per_incident_alerts = incidents["alert_count"]

    profile = {
        "counts": {
            "evidence_rows": int(len(evidence)),
            "incidents": int(len(incidents)),
            "alerts": int(evidence["alert_id"].nunique()),
            "orgs": int(evidence["org_id"].nunique()),
        },
        "label_distribution": {
            str(k): int(v) for k, v in incidents["label"].value_counts().items()
        },
        "label_distribution_by_split": {
            str(split): {str(k): int(v) for k, v in group["label"].value_counts().items()}
            for split, group in incidents.groupby("split")
        },
        "evidence_per_incident": {
            "min": int(per_incident_evidence.min()),
            "median": float(per_incident_evidence.median()),
            "mean": round(float(per_incident_evidence.mean()), 2),
            "p95": float(per_incident_evidence.quantile(0.95)),
            "max": int(per_incident_evidence.max()),
        },
        "alerts_per_incident": {
            "min": int(per_incident_alerts.min()),
            "median": float(per_incident_alerts.median()),
            "max": int(per_incident_alerts.max()),
        },
        "entity_type_counts": dict(
            Counter(evidence["entity_type"].astype(str)).most_common(TOP_N)
        ),
        "category_counts": dict(Counter(evidence["category"].astype(str)).most_common(TOP_N)),
        "missingness_evidence": _missingness(evidence),
        "entity_hubs": _entity_hubs(evidence),
        "leakage_check": {
            "incident_in_multiple_splits": int(
                incidents.groupby("incident_id")["split"].nunique().gt(1).sum()
            ),
            "summary_contains_label": int(
                sum(
                    any(lbl in str(summary) for lbl in ("TruePositive", "BenignPositive",
                                                        "FalsePositive"))
                    for summary in incidents["summary"]
                )
            ),
        },
    }

    OUTPUT.write_text(json.dumps(profile, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(profile["counts"], indent=2))
    print("\nlabels:", json.dumps(profile["label_distribution"]))
    print("leakage:", json.dumps(profile["leakage_check"]))
    worst = max(
        (
            (name, data.get("max_incidents_touched", 0), data["top"][0]["value"] if data["top"] else "")
            for name, data in profile["entity_hubs"].items()
        ),
        key=lambda t: t[1],
    )
    print(f"worst hub: {worst[0]}={worst[2]!r} touches {worst[1]} incidents")
    print(f"\nwritten to {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
