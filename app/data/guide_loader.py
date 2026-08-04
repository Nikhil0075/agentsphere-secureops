"""Loader for the real Microsoft GUIDE dataset.

Interchangeable with :mod:`app.data.fixture`: same canonical columns, same id assignment. Swap by
setting ``DATA_SOURCE=guide`` and ``GUIDE_PATH``.

The train split is multiple gigabytes, so this reads in chunks and stops once the requested number
of incidents has been collected. Loading the whole file into memory to then sample from it is the
obvious mistake here and it is not made.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Iterator

import pandas as pd

from app.data import ids
from app.data.schema import CANONICAL_COLUMNS, GUIDE_COLUMN_MAP, LABELS

CHUNK_SIZE = 200_000

#: File name preferences within the Kaggle download directory.
_TRAIN_HINTS = ("train",)
_TEST_HINTS = ("test",)


def find_csv(root: str | Path, prefer: str = "train") -> Path:
    """Locate the GUIDE csv inside a kagglehub download directory."""
    root = Path(root)
    if root.is_file():
        return root
    candidates = sorted(root.rglob("*.csv"))
    if not candidates:
        raise FileNotFoundError(f"no .csv found under {root}")
    hints = _TRAIN_HINTS if prefer == "train" else _TEST_HINTS
    for c in candidates:
        if any(h in c.name.lower() for h in hints):
            return c
    return max(candidates, key=lambda p: p.stat().st_size)


def _normalise_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    present = {raw: canon for raw, canon in GUIDE_COLUMN_MAP.items() if raw in chunk.columns}
    missing = set(GUIDE_COLUMN_MAP) - set(present)
    if missing:
        warnings.warn(
            f"GUIDE file is missing {len(missing)} expected columns "
            f"(e.g. {sorted(missing)[:5]}); they will be blank.",
            stacklevel=2,
        )
    out = chunk[list(present)].rename(columns=present)
    for canon in CANONICAL_COLUMNS:
        if canon not in out.columns:
            out[canon] = ""
    out = out[list(CANONICAL_COLUMNS)]

    out = out[out["label"].isin(LABELS)]
    out = out.dropna(subset=["incident_ref", "alert_ref"])

    out["incident_id"] = [
        ids.incident_id(o, i) for o, i in zip(out["org_id"], out["incident_ref"])
    ]
    out["alert_id"] = [
        ids.alert_id(o, i, a)
        for o, i, a in zip(out["org_id"], out["incident_ref"], out["alert_ref"])
    ]
    out["evidence_id"] = [
        ids.evidence_id(o, i, a, r)
        for o, i, a, r in zip(
            out["org_id"], out["incident_ref"], out["alert_ref"], out["evidence_row_id"]
        )
    ]
    return out


def iter_chunks(csv_path: str | Path) -> Iterator[pd.DataFrame]:
    for chunk in pd.read_csv(csv_path, chunksize=CHUNK_SIZE, low_memory=False):
        yield _normalise_chunk(chunk)


def load(
    path: str | Path,
    max_incidents: int | None = None,
    prefer: str = "train",
) -> pd.DataFrame:
    """Read up to ``max_incidents`` complete incidents from the GUIDE csv.

    An incident is only accepted once we start it, and every subsequent chunk keeps contributing
    rows to already-accepted incidents — so an incident split across a chunk boundary is not
    silently truncated.
    """
    csv_path = find_csv(path, prefer=prefer)
    accepted: set[str] = set()
    frames: list[pd.DataFrame] = []

    for chunk in iter_chunks(csv_path):
        if max_incidents is None:
            frames.append(chunk)
            continue

        keep_existing = chunk[chunk["incident_id"].isin(accepted)]
        if len(accepted) < max_incidents:
            fresh = chunk[~chunk["incident_id"].isin(accepted)]
            room = max_incidents - len(accepted)
            new_ids = list(dict.fromkeys(fresh["incident_id"]))[:room]
            accepted.update(new_ids)
            keep_existing = pd.concat(
                [keep_existing, fresh[fresh["incident_id"].isin(set(new_ids))]]
            )
        if not keep_existing.empty:
            frames.append(keep_existing)

    if not frames:
        raise ValueError(f"no usable rows found in {csv_path}")
    result = pd.concat(frames, ignore_index=True)
    # Content-stable ordering, so two runs over the same file produce byte-identical output.
    return result.sort_values(["incident_id", "alert_id", "evidence_id"]).reset_index(drop=True)
