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


def correlation_panel(result) -> None:
    """Alert clustering and the agent timeline for one workflow run."""
    state = result.state
    correlation = result.context.correlation

    st.subheader("Alert correlation")
    st.caption(
        "Union-Find with path compression **and** union by rank — both, which is what the "
        "O(α(n)) bound actually requires. Alerts sharing an account, device, IP or file hash "
        "collapse into one cluster."
    )

    if correlation is None:
        st.info("No alerts to correlate on this incident.")
    else:
        a, b, c = st.columns(3)
        a.metric("Alerts", correlation.alert_count)
        b.metric("Clusters", correlation.cluster_count, f"-{correlation.reduction:.0%}")
        c.metric("Largest cluster", correlation.largest_cluster)

        if correlation.reduction > 0:
            st.success(
                f"{correlation.alert_count} scattered alerts collapsed into "
                f"{correlation.cluster_count} clusters."
            )
        else:
            st.info(
                "No alerts shared a linking entity, so nothing collapsed. That is a real "
                "outcome, not a failure — GUIDE carries one evidence row per alert and many "
                "incidents genuinely have no shared entity."
            )

        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "cluster": c.cluster_id,
                        "alerts": c.size,
                        "evidence": c.evidence_count,
                        "linked by": ", ".join(c.linking_entities[:4]) or "time proximity",
                    }
                    for c in correlation.clusters[:25]
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )

    st.divider()
    st.subheader("Agent timeline")
    st.caption(
        "Every call is recorded with its latency, backend, retry count and output hash. A "
        "degraded agent shows as `fallback`, never as `ok` — a silent fallback would corrupt "
        "the metrics."
    )

    st.dataframe(
        pd.DataFrame(
            [
                {
                    "#": r.sequence,
                    "agent": r.agent,
                    "status": r.status,
                    "attempts": r.attempts,
                    "latency ms": r.latency_ms,
                    "backend": r.backend,
                    "tokens": r.prompt_tokens + r.completion_tokens,
                    "output hash": r.output_hash[:18] + "...",
                }
                for r in state.runs
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )

    if result.degraded_agents():
        st.warning(f"Degraded: {', '.join(result.degraded_agents())}")

    if state.triage:
        st.divider()
        left, right = st.columns([2, 1])
        with left:
            st.markdown(f"### Triage: {LABEL_BADGES.get(state.triage.label.value)}")
            st.progress(
                state.triage.confidence, text=f"confidence {state.triage.confidence:.0%}"
            )
            st.write(state.triage.rationale)
            st.caption(
                "Cited evidence: " + ", ".join(state.triage.supporting_evidence_ids[:8])
            )
        with right:
            if state.baseline:
                st.metric(
                    "Non-LLM baseline",
                    state.baseline.label.value,
                    f"{state.baseline.confidence:.0%}",
                )
                agrees = state.baseline.label.value == state.triage.label.value
                st.caption("agrees with the agent" if agrees else "**disagrees** with the agent")

    for name, title in (
        ("detection", "Detection"),
        ("correlation", "Correlation"),
        ("investigation", "Investigation"),
    ):
        output = getattr(state, name, None)
        if output is not None:
            with st.expander(f"{title} output"):
                st.json(output.model_dump(mode="json"))

    st.divider()
    st.markdown("**Decision integrity** — keccak256 over canonical JSON")
    st.caption(
        "These are the digests Day 5 anchors on-chain. Sorted keys, no whitespace: the same "
        "evidence always produces the same hash, so a later mismatch means the stored data "
        "changed."
    )
    st.code(
        f"evidence  {state.evidence_hash}\noutput    {state.output_hash}", language=None
    )


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
