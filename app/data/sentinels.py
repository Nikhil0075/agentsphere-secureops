"""Sentinel detection for GUIDE entity columns.

**Why this exists.** GUIDE integer-encodes every entity value and fills each entity column with a
single placeholder integer on rows where that column does not apply. Measured on a 591,340-row
sample of ``GUIDE_Train.csv``:

===================  ==========  ================================
column               sentinel    share of rows
===================  ==========  ================================
device_id            98799       97.8%
url                  160396      98.7%
mailbox_message_id   529644      96.9%
file_sha256          138268      95.9%
file_name            289573      95.1%
ip_address           360606      69.9%
account_upn          673934      68.7%
===================  ==========  ================================

The placeholder is not noise, it is structural: on rows where ``EntityType == 'Ip'`` the
``IpAddress`` sentinel appears in 0.1% of rows, and on every other row it appears in 100% of them.

Left in place, the sentinel is catastrophic rather than merely untidy. Every incident would share
one ``device_id``, so Union-Find would collapse the entire dataset into a single component, BFS
would traverse the whole graph from any starting point, and ``distinct_*_count`` features would be
constant. The §8.4 hub problem would then be an artefact we manufactured, not a property of real
SOC data.

**How it is detected.** Statistically, from the data, not from a hardcoded list. A value is a
sentinel when it occupies at least ``MIN_SHARE`` of non-null rows *and* is at least
``DOMINANCE_RATIO`` times as frequent as the next most common value. Both conditions matter: the
first alone would flag a genuinely busy shared asset, the second alone would flag a coincidence.
The detected values are written into the dataset manifest, so the decision is auditable rather
than buried.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from app.data.schema import ENTITY_COLUMNS

#: A candidate must cover at least this share of non-null rows.
MIN_SHARE = 0.60

#: ...and be at least this many times more frequent than the runner-up.
DOMINANCE_RATIO = 20.0


@dataclass(frozen=True)
class Sentinel:
    column: str
    value: str
    share: float
    dominance: float

    def as_dict(self) -> dict:
        return {
            "column": self.column,
            "value": self.value,
            "share": round(self.share, 4),
            "dominance": round(self.dominance, 1),
        }


def detect(frame: pd.DataFrame, columns: list[str] | None = None) -> list[Sentinel]:
    """Find the placeholder value in each entity column, if there is one."""
    columns = columns or list(ENTITY_COLUMNS.values())
    found: list[Sentinel] = []

    for column in columns:
        if column not in frame.columns:
            continue
        series = frame[column].dropna().astype(str)
        series = series[series.str.strip() != ""]
        if len(series) < 100:
            continue

        counts = series.value_counts()
        if counts.empty:
            continue

        top_value = str(counts.index[0])
        top_count = int(counts.iloc[0])
        share = top_count / len(series)
        runner_up = int(counts.iloc[1]) if len(counts) > 1 else 0
        dominance = top_count / runner_up if runner_up else float("inf")

        if share >= MIN_SHARE and dominance >= DOMINANCE_RATIO:
            found.append(
                Sentinel(column=column, value=top_value, share=share, dominance=dominance)
            )

    return found


def mask(frame: pd.DataFrame, sentinels: list[Sentinel]) -> pd.DataFrame:
    """Blank out detected sentinels so downstream code sees them as absent.

    Rows are kept — the evidence row is still real, it simply has no value for that entity type.
    """
    out = frame.copy()
    for sentinel in sentinels:
        column = out[sentinel.column].astype(str)
        out[sentinel.column] = column.where(column != sentinel.value, "")
    return out


def detect_and_mask(frame: pd.DataFrame) -> tuple[pd.DataFrame, list[dict]]:
    sentinels = detect(frame)
    return mask(frame, sentinels), [s.as_dict() for s in sentinels]
