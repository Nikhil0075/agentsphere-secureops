"""AgentSphere SecureOps — analyst interface.

    streamlit run app/ui/main.py

Day 2 delivers the incident queue and incident detail. Day 3 adds the correlation view and the
agent workflow timeline. The approval gate and proof panel arrive on Days 5-6.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

import json  # noqa: E402

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from app.config import METRICS_DIR  # noqa: E402
from app.data import incidents as incidents_mod  # noqa: E402
from app.data import loader  # noqa: E402
from app.policies import risk  # noqa: E402
from app.services import scoring  # noqa: E402
from app.ui import panels  # noqa: E402

st.set_page_config(page_title="AgentSphere SecureOps", page_icon="🛡️", layout="wide")

LABEL_COLOURS = {
    "TruePositive": "#c0392b",
    "BenignPositive": "#d68910",
    "FalsePositive": "#5d6d7e",
}


@st.cache_data(show_spinner="Loading incidents…")
def load_queue() -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    evidence, incidents = loader.load_prepared()
    model = scoring.load_baseline()
    table = scoring.prepare_queue_table(incidents, model)
    manifest_path = loader.DATA_PROCESSED / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    return evidence, table, manifest


@st.cache_data(show_spinner=False)
def load_metrics() -> dict:
    path = METRICS_DIR / "baseline.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def main() -> None:
    st.title("🛡️ AgentSphere SecureOps")
    st.caption(
        "A permissioned workforce of AI agents for SOC investigation, triage and verifiable "
        "response. **All remediation is simulated.**"
    )

    try:
        evidence, table, manifest = load_queue()
    except FileNotFoundError as exc:
        st.error(str(exc))
        st.code("python scripts/prepare_data.py --source guide -n 5000", language="bash")
        return

    metrics = load_metrics()
    panels.sidebar(manifest, metrics, table)

    only_showcase = st.session_state.get("only_showcase", False)
    labels_filter = st.session_state.get("labels_filter", [])
    search = st.session_state.get("search", "")

    view = table
    if only_showcase and "is_showcase" in view:
        view = view[view["is_showcase"]]
    if labels_filter:
        view = view[view["baseline_label"].isin(labels_filter)]
    if search:
        needle = search.strip().lower()
        view = view[
            view["incident_id"].str.lower().str.contains(needle)
            | view["summary"].str.lower().str.contains(needle)
        ]

    queue_tab, detail_tab, metrics_tab = st.tabs(
        ["Incident queue", "Incident detail", "Baseline metrics"]
    )

    with queue_tab:
        panels.queue_panel(view, table)

    with detail_tab:
        selected = st.session_state.get("selected_incident")
        if not selected or selected not in set(table["incident_id"]):
            selected = view["incident_id"].iloc[0] if len(view) else None
        if selected is None:
            st.info("No incidents match the current filters.")
        else:
            row = table[table["incident_id"] == selected].iloc[0]
            rows = incidents_mod.evidence_for(evidence, selected)
            breakdown = risk.explain(
                row.to_dict(),
                evidence=rows,
                baseline_confidence=row.get("baseline_tp_probability"),
            )
            panels.detail_panel(row, rows, breakdown)

    with metrics_tab:
        panels.metrics_panel(metrics)


if __name__ == "__main__":
    main()
