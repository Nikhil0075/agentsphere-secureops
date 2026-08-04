"""Attach baseline predictions and risk scores to an incident table.

Shared by the UI and the demo runner so the queue an analyst sees and the queue the workflow pulls
from are ordered by exactly the same number.

Queue-level scoring deliberately does *not* load per-incident evidence: at 591k evidence rows,
grouping the whole corpus to compute an asset-criticality proxy for incidents nobody has opened
would make the queue slow for no visible gain. The proxies fall back to their incident-level
defaults here, and the full evidence-aware breakdown is computed when an incident is opened.
"""

from __future__ import annotations

import pandas as pd

from app.config import MODELS_DIR
from app.models.baseline import BaselineModel, load_default
from app.policies import risk
from app.policies.queue import IncidentQueue, from_frame

BASELINE_PATH = MODELS_DIR / "baseline.pkl"


def load_baseline() -> BaselineModel | None:
    return load_default(BASELINE_PATH)


def attach_baseline(
    incidents: pd.DataFrame, model: BaselineModel | None = None
) -> pd.DataFrame:
    """Add ``baseline_label``, ``baseline_confidence`` and ``baseline_tp_probability``.

    Without a trained model the columns are still created, holding neutral values, so every
    downstream consumer has one shape to handle instead of two.
    """
    out = incidents.copy()
    if model is None:
        out["baseline_label"] = ""
        out["baseline_confidence"] = 0.0
        out["baseline_tp_probability"] = 0.5
        return out

    proba = model.predict_proba(out)
    classes = ["TruePositive", "BenignPositive", "FalsePositive"]
    from app.data.schema import INT_TO_LABEL

    order = [INT_TO_LABEL[i] for i in range(proba.shape[1])]
    frame = pd.DataFrame(proba, columns=order, index=out.index)

    out["baseline_label"] = frame.idxmax(axis=1)
    out["baseline_confidence"] = frame.max(axis=1)
    out["baseline_tp_probability"] = frame.get(
        "TruePositive", pd.Series(0.5, index=out.index)
    )
    for label in classes:
        if label in frame:
            out[f"baseline_p_{label}"] = frame[label]
    return out


def attach_risk(incidents: pd.DataFrame, now=None) -> pd.DataFrame:
    """Add ``risk_score`` and the name of its strongest driver."""
    out = incidents.copy()
    scores, drivers = [], []
    for row in out.to_dict("records"):
        breakdown = risk.explain(
            row,
            evidence=None,
            baseline_confidence=row.get("baseline_tp_probability"),
            now=now,
        )
        scores.append(breakdown.score)
        drivers.append(breakdown.top_drivers(1)[0][0])
    out["risk_score"] = scores
    out["risk_top_driver"] = drivers
    return out


def prepare_queue_table(
    incidents: pd.DataFrame, model: BaselineModel | None = None, now=None
) -> pd.DataFrame:
    """Incident table with baseline predictions and risk, sorted highest risk first."""
    scored = attach_risk(attach_baseline(incidents, model), now=now)
    return scored.sort_values(
        ["risk_score", "evidence_count", "incident_id"], ascending=[False, False, True]
    ).reset_index(drop=True)


def build_queue(incidents: pd.DataFrame) -> IncidentQueue:
    """The same table as a max-heap, for callers that pop rather than page."""
    return from_frame(incidents)
