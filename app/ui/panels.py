"""Streamlit panels. Kept out of ``main.py`` so the page wiring stays readable."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from app.data.schema import ENTITY_COLUMNS, LABELS
from app.policies.risk import RiskBreakdown

LABEL_BADGES = {
    "TruePositive": "🔴 TruePositive",
    "BenignPositive": "🟠 BenignPositive",
    "FalsePositive": "⚪ FalsePositive",
}


def sidebar(manifest: dict, metrics: dict, table: pd.DataFrame) -> None:
    with st.sidebar:
        st.header("Dataset")
        source = manifest.get("source", "unknown")
        st.metric("Source", "Microsoft GUIDE" if source == "guide" else "Synthetic fixture")
        if source != "guide":
            st.warning("Synthetic data — no headline metric should be quoted from this.")
        st.metric("Incidents", f"{manifest.get('incidents', len(table)):,}")
        st.metric("Evidence rows", f"{manifest.get('evidence_rows', 0):,}")

        if manifest.get("masked_sentinels"):
            with st.expander(f"{len(manifest['masked_sentinels'])} sentinels masked"):
                st.caption(
                    "GUIDE fills unused entity columns with a placeholder value. Left in place, "
                    "every incident would share one device and the entity graph would collapse "
                    "into a single component."
                )
                st.dataframe(
                    pd.DataFrame(manifest["masked_sentinels"]),
                    hide_index=True,
                    use_container_width=True,
                )

        st.divider()
        st.header("Filters")
        st.checkbox("Showcase incidents only", key="only_showcase")
        st.multiselect("Baseline prediction", LABELS, key="labels_filter")
        st.text_input("Search id or summary", key="search")

        st.divider()
        st.header("Baseline")
        if metrics:
            st.metric("Macro F1", f"{metrics.get('macro_f1', 0):.3f}")
            st.metric("True-positive recall", f"{metrics.get('true_positive_recall', 0):.3f}")
            st.caption(metrics.get("implementation", ""))
        else:
            st.info("Run `python scripts/train_baseline.py`.")


def queue_panel(view: pd.DataFrame, full: pd.DataFrame) -> None:
    st.subheader("Incident queue")
    st.caption(
        "Ordered by a max-heap over the normalised risk score (§8.1, §8.5). Weights are "
        "hand-set and sanity-checked against the validation split — not learned."
    )

    left, mid, right, far = st.columns(4)
    left.metric("Shown", f"{len(view):,}")
    mid.metric("Total", f"{len(full):,}")
    right.metric(
        "Showcase", int(full["is_showcase"].sum()) if "is_showcase" in full else 0
    )
    far.metric("Highest risk", f"{view['risk_score'].max():.3f}" if len(view) else "—")

    if not len(view):
        st.info("No incidents match the current filters.")
        return

    columns = [
        "incident_id",
        "risk_score",
        "risk_top_driver",
        "baseline_label",
        "baseline_confidence",
        "alert_count",
        "evidence_count",
        "distinct_entity_count",
        "top_category",
        "max_suspicion_level",
        "split",
    ]
    if "is_showcase" in view:
        columns.insert(1, "is_showcase")
    columns = [c for c in columns if c in view.columns]

    st.dataframe(
        view[columns].head(200),
        hide_index=True,
        use_container_width=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn(
                "risk", min_value=0.0, max_value=1.0, format="%.3f"
            ),
            "baseline_confidence": st.column_config.NumberColumn("conf", format="%.2f"),
            "is_showcase": st.column_config.CheckboxColumn("demo"),
        },
    )
    st.caption("Ground-truth labels are held back from this view — they are the answer key.")

    st.selectbox(
        "Open incident",
        options=view["incident_id"].head(200).tolist(),
        key="selected_incident",
    )


def detail_panel(row: pd.Series, evidence: pd.DataFrame, breakdown: RiskBreakdown) -> None:
    st.subheader(row["incident_id"])

    a, b, c, d = st.columns(4)
    a.metric("Risk", f"{breakdown.score:.3f}")
    b.metric("Alerts", int(row.get("alert_count", 0)))
    c.metric("Evidence", int(row.get("evidence_count", 0)))
    d.metric(
        "Baseline",
        row.get("baseline_label", "—"),
        f"{float(row.get('baseline_confidence', 0)):.0%} confident",
    )

    st.markdown("**Summary**")
    st.code(row.get("summary", ""), language=None)

    left, right = st.columns([3, 2])

    with left:
        st.markdown("**Evidence**")
        display_columns = [
            "evidence_id",
            "alert_id",
            "timestamp",
            "entity_type",
            "evidence_role",
            "suspicion_level",
            "last_verdict",
        ] + [c for c in ENTITY_COLUMNS.values() if c in evidence.columns]
        display_columns = [c for c in display_columns if c in evidence.columns]
        st.dataframe(
            evidence[display_columns].head(200),
            hide_index=True,
            use_container_width=True,
            height=340,
        )
        if len(evidence) > 200:
            st.caption(f"Showing 200 of {len(evidence):,} evidence rows.")

    with right:
        st.markdown("**Risk breakdown**")
        st.caption("Every component normalised to [0,1] before its weight is applied.")
        contributions = pd.DataFrame(
            {
                "component": list(breakdown.components),
                "normalised": [breakdown.components[k] for k in breakdown.components],
                "contribution": [breakdown.weighted[k] for k in breakdown.components],
            }
        ).sort_values("contribution", ascending=False)
        st.dataframe(
            contributions,
            hide_index=True,
            use_container_width=True,
            column_config={
                "normalised": st.column_config.NumberColumn(format="%.2f"),
                "contribution": st.column_config.ProgressColumn(
                    min_value=0.0, max_value=0.3, format="%.3f"
                ),
            },
        )

        st.markdown("**Entities**")
        counts = {
            name: int(
                evidence[column][evidence[column].astype(str).str.strip() != ""].nunique()
            )
            for name, column in ENTITY_COLUMNS.items()
            if column in evidence.columns
        }
        present = {k: v for k, v in counts.items() if v}
        st.write(
            " · ".join(f"{k} **{v}**" for k, v in present.items())
            if present
            else "No entity values on this incident."
        )

    with st.expander("Ground truth (held out from every agent and from retrieval)"):
        st.write(LABEL_BADGES.get(row.get("label", ""), row.get("label", "—")))
        st.caption(f"split: {row.get('split', '—')}")


def metrics_panel(metrics: dict) -> None:
    st.subheader("Non-LLM baseline")
    if not metrics:
        st.info("Run `python scripts/train_baseline.py` to populate this.")
        return

    st.caption(
        "This model exists to be compared against. It is the honest answer to "
        "\"is this just an LLM wrapper?\" — the agent chain has to beat a real classifier on the "
        "same split, not on a vibe."
    )

    a, b, c, d = st.columns(4)
    a.metric("Accuracy", f"{metrics['accuracy']:.3f}")
    b.metric("Macro F1", f"{metrics['macro_f1']:.3f}")
    c.metric("TP recall", f"{metrics['true_positive_recall']:.3f}")
    d.metric("Validation set", f"{metrics['dataset']['val_incidents']:,}")

    st.markdown("**Per class**")
    st.dataframe(
        pd.DataFrame(metrics["per_class"]).T.reset_index(names="label"),
        hide_index=True,
        use_container_width=True,
    )

    left, right = st.columns(2)
    with left:
        st.markdown("**Confusion matrix** (rows actual, columns predicted)")
        cm = metrics["confusion_matrix"]
        st.dataframe(
            pd.DataFrame(cm["matrix"], index=cm["labels"], columns=cm["labels"]),
            use_container_width=True,
        )
    with right:
        st.markdown("**Feature importance**")
        importance = metrics.get("feature_importance", {})
        st.dataframe(
            pd.DataFrame(
                {"feature": list(importance), "importance": list(importance.values())}
            ).head(12),
            hide_index=True,
            use_container_width=True,
        )
