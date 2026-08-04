"""Loader for the real Microsoft GUIDE dataset.

Interchangeable with :mod:`app.data.fixture`: same canonical columns, same id assignment. Swap by
setting ``DATA_SOURCE=guide`` and ``GUIDE_PATH``.

``GUIDE_Train.csv`` is 2.43 GB across 45 columns, so this reads in chunks and never materialises
the whole file. Two details make that fast rather than merely possible:

* Incident ids are assigned by mapping over the *distinct* ``(OrgId, IncidentId)`` pairs in a
  chunk, not row by row. A chunk of 200k rows holds only a few thousand distinct incidents, so
  this is three orders of magnitude fewer hashes.
* Alert and evidence ids are computed only for rows that survive the incident filter, because
  those are per-row by definition and there is no point paying for rows we are about to discard.

Scanning stops once the requested number of incidents has been collected *and* a short trailing
window has passed with no further rows for them, so a subset does not cost a full-file read.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Iterator

import pandas as pd

from app.data import ids
from app.data.schema import CANONICAL_COLUMNS, GUIDE_COLUMN_MAP, LABELS

CHUNK_SIZE = 200_000

#: Chunks to keep scanning after the incident target is met, to pick up stragglers belonging to
#: already-accepted incidents. GUIDE groups an incident's rows closely, so this is generous.
TRAILING_CHUNKS = 2

_TRAIN_HINTS = ("train",)
_TEST_HINTS = ("test",)


def find_csv(root: str | Path, prefer: str = "train") -> Path:
    """Locate the GUIDE csv inside a kagglehub download directory."""
    root = Path(root)
    if root.is_file():
        return root
    candidates = [p for p in sorted(root.rglob("*.csv")) if "ranking" not in p.name.lower()]
    if not candidates:
        raise FileNotFoundError(f"no .csv found under {root}")
    hints = _TRAIN_HINTS if prefer == "train" else _TEST_HINTS
    for c in candidates:
        if any(h in c.name.lower() for h in hints):
            return c
    return max(candidates, key=lambda p: p.stat().st_size)


def _rename(chunk: pd.DataFrame, warn: bool = False) -> pd.DataFrame:
    present = {raw: canon for raw, canon in GUIDE_COLUMN_MAP.items() if raw in chunk.columns}
    if warn:
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
    return out[list(CANONICAL_COLUMNS)]


def _add_incident_ids(frame: pd.DataFrame) -> pd.DataFrame:
    """Assign incident ids by distinct (org, incident) pair rather than per row."""
    pairs = frame[["org_id", "incident_ref"]].drop_duplicates()
    lookup = {
        (o, i): ids.incident_id(o, i)
        for o, i in zip(pairs["org_id"], pairs["incident_ref"])
    }
    frame = frame.copy()
    frame["incident_id"] = [
        lookup[(o, i)] for o, i in zip(frame["org_id"], frame["incident_ref"])
    ]
    return frame


def _add_row_ids(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame.copy()
    frame["alert_id"] = [
        ids.alert_id(o, i, a)
        for o, i, a in zip(frame["org_id"], frame["incident_ref"], frame["alert_ref"])
    ]
    frame["evidence_id"] = [
        ids.evidence_id(o, i, a, r)
        for o, i, a, r in zip(
            frame["org_id"], frame["incident_ref"], frame["alert_ref"], frame["evidence_row_id"]
        )
    ]
    return frame


def _clean(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame[frame["label"].isin(LABELS)]
    return frame.dropna(subset=["incident_ref", "alert_ref"])


def iter_chunks(csv_path: str | Path) -> Iterator[pd.DataFrame]:
    """Normalised, id-bearing chunks. Convenience for full-file passes."""
    first = True
    for chunk in pd.read_csv(csv_path, chunksize=CHUNK_SIZE, low_memory=False):
        frame = _clean(_rename(chunk, warn=first))
        first = False
        yield _add_row_ids(_add_incident_ids(frame))


def load(
    path: str | Path,
    max_incidents: int | None = None,
    prefer: str = "train",
) -> pd.DataFrame:
    """Read up to ``max_incidents`` complete incidents from the GUIDE csv."""
    csv_path = find_csv(path, prefer=prefer)
    accepted: set[str] = set()
    frames: list[pd.DataFrame] = []
    quiet_chunks = 0
    first = True

    for chunk in pd.read_csv(csv_path, chunksize=CHUNK_SIZE, low_memory=False):
        frame = _clean(_rename(chunk, warn=first))
        first = False
        if frame.empty:
            continue
        frame = _add_incident_ids(frame)

        if max_incidents is None:
            frames.append(_add_row_ids(frame))
            continue

        keep = frame[frame["incident_id"].isin(accepted)]
        if len(accepted) < max_incidents:
            fresh = frame[~frame["incident_id"].isin(accepted)]
            room = max_incidents - len(accepted)
            new_ids = set(list(dict.fromkeys(fresh["incident_id"]))[:room])
            accepted |= new_ids
            keep = pd.concat([keep, fresh[fresh["incident_id"].isin(new_ids)]])

        if keep.empty:
            quiet_chunks += 1
        else:
            quiet_chunks = 0
            frames.append(_add_row_ids(keep))

        if len(accepted) >= max_incidents and quiet_chunks >= TRAILING_CHUNKS:
            break

    if not frames:
        raise ValueError(f"no usable rows found in {csv_path}")
    result = pd.concat(frames, ignore_index=True)
    result = result.drop_duplicates(subset=["evidence_id"])
    # Content-stable ordering, so two runs over the same file produce identical output.
    return result.sort_values(["incident_id", "alert_id", "evidence_id"]).reset_index(drop=True)
