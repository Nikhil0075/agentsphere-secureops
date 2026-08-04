"""Evidence rows -> incident-level records.

Both the baseline classifier and the analyst UI work at incident level, but the dataset is
evidence level. This is the one place that rollup happens, so the features the model trains on and
the counts the analyst sees can never drift apart.
"""

from __future__ import annotations

import pandas as pd

from app.data.ids import split_bucket
from app.data.schema import (
    ENTITY_COLUMNS,
    FEATURE_COLUMNS,
    LABEL_TO_INT,
    split_for_bucket,
)

_SUSPICION_ORDER = {"": 0, "Benign": 1, "Suspicious": 2, "Malicious": 3}
_VERDICT_ORDER = {
    "": 0,
    "NoThreatsFound": 1,
    "Clean": 1,
    "Suspicious": 2,
    "Malicious": 3,
}


def _mode_or_blank(series: pd.Series) -> str:
    cleaned = series.dropna().astype(str)
    cleaned = cleaned[cleaned != ""]
    if cleaned.empty:
        return ""
    return str(cleaned.mode().iloc[0])


def _max_by_order(series: pd.Series, order: dict[str, int]) -> str:
    best, best_rank = "", -1
    for value in series.dropna().astype(str):
        rank = order.get(value, 0)
        if rank > best_rank:
            best, best_rank = value, rank
    return best


def _distinct_nonblank(series: pd.Series) -> int:
    cleaned = series.dropna().astype(str)
    return int(cleaned[cleaned != ""].nunique())


def _technique_set(series: pd.Series) -> set[str]:
    out: set[str] = set()
    for value in series.dropna().astype(str):
        for token in value.replace(",", ";").split(";"):
            token = token.strip()
            if token:
                out.add(token)
    return out


def aggregate(evidence: pd.DataFrame) -> pd.DataFrame:
    """One row per incident, carrying model features, label and split assignment."""
    timestamps = pd.to_datetime(evidence["timestamp"], errors="coerce", utc=True, format="mixed")
    work = evidence.assign(_ts=timestamps)

    records = []
    for incident_id, group in work.groupby("incident_id", sort=True):
        ts = group["_ts"].dropna()
        first, last = (ts.min(), ts.max()) if not ts.empty else (pd.NaT, pd.NaT)
        techniques = _technique_set(group["mitre_techniques"])

        distinct_by_type = {
            f"distinct_{name}_count": _distinct_nonblank(group[column])
            for name, column in ENTITY_COLUMNS.items()
            if f"distinct_{name}_count" in FEATURE_COLUMNS
        }

        records.append(
            {
                "incident_id": incident_id,
                "org_id": group["org_id"].iloc[0],
                "incident_ref": group["incident_ref"].iloc[0],
                "label": group["label"].iloc[0],
                "label_int": LABEL_TO_INT[group["label"].iloc[0]],
                "first_seen": first.isoformat() if pd.notna(first) else "",
                "last_seen": last.isoformat() if pd.notna(last) else "",
                "alert_count": int(group["alert_id"].nunique()),
                "evidence_count": int(len(group)),
                "distinct_entity_count": sum(
                    _distinct_nonblank(group[c]) for c in ENTITY_COLUMNS.values()
                ),
                "mitre_technique_count": len(techniques),
                "mitre_techniques": ";".join(sorted(techniques)),
                "distinct_category_count": _distinct_nonblank(group["category"]),
                "distinct_detector_count": _distinct_nonblank(group["detector_id"]),
                "duration_minutes": (
                    float((last - first).total_seconds() / 60.0)
                    if pd.notna(first) and pd.notna(last)
                    else 0.0
                ),
                "hour_of_day": int(first.hour) if pd.notna(first) else 0,
                "top_category": _mode_or_blank(group["category"]),
                "top_entity_type": _mode_or_blank(group["entity_type"]),
                "top_detector": _mode_or_blank(group["detector_id"]),
                "top_alert_title": _mode_or_blank(group["alert_title"]),
                "max_suspicion_level": _max_by_order(
                    group["suspicion_level"], _SUSPICION_ORDER
                ),
                "max_last_verdict": _max_by_order(group["last_verdict"], _VERDICT_ORDER),
                "threat_families": ";".join(
                    sorted(
                        {
                            v
                            for v in group["threat_family"].dropna().astype(str)
                            if v
                        }
                    )
                ),
                **distinct_by_type,
            }
        )

    frame = pd.DataFrame(records)
    frame["split_bucket"] = frame["incident_id"].map(split_bucket)
    frame["split"] = frame["split_bucket"].map(split_for_bucket)
    return frame.sort_values("incident_id").reset_index(drop=True)


def evidence_for(evidence: pd.DataFrame, incident_id: str) -> pd.DataFrame:
    return evidence[evidence["incident_id"] == incident_id].reset_index(drop=True)
