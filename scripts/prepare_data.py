"""Build the deterministic working dataset.

    python scripts/prepare_data.py                      # uses DATA_SOURCE from .env
    python scripts/prepare_data.py --source fixture -n 200
    python scripts/prepare_data.py --source guide -n 5000
    python scripts/prepare_data.py --verify-determinism # runs twice, compares content hashes

Outputs ``data/processed/evidence.parquet`` and ``data/processed/incidents.parquet``, plus a
manifest recording the source, row counts, split sizes and a content hash of each table.

Day 1 exit criterion: this runs from a clean checkout and produces a deterministic subset. The
``--verify-determinism`` flag is how that claim is checked rather than asserted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402

from app.config import DATA_PROCESSED, ensure_dirs, settings  # noqa: E402
from app.data import incidents as incidents_mod  # noqa: E402
from app.data import loader  # noqa: E402
from app.data.schema import REQUIRED_COLUMNS  # noqa: E402
from app.data.summarize import build_incident_summary  # noqa: E402

MANIFEST = DATA_PROCESSED / "manifest.json"


def content_hash(frame: pd.DataFrame) -> str:
    """Hash of the table's content, independent of Parquet encoding.

    Parquet files are not byte-stable across writes (timestamps, compression metadata), so
    comparing file bytes would produce false failures. Hashing the sorted CSV rendering compares
    what actually matters: the data.
    """
    ordered = frame.sort_index(axis=1)
    payload = ordered.to_csv(index=False, lineterminator="\n").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def drop_unusable(evidence: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, int]]:
    before = len(evidence)
    stats: dict[str, int] = {"input_rows": before}

    cleaned = evidence.dropna(subset=list(REQUIRED_COLUMNS))
    stats["dropped_missing_required"] = before - len(cleaned)

    deduped = cleaned.drop_duplicates(subset=["evidence_id"])
    stats["dropped_duplicate_evidence_id"] = len(cleaned) - len(deduped)

    stats["output_rows"] = len(deduped)
    return deduped.reset_index(drop=True), stats


def build(source: str, max_incidents: int) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    raw = loader.load_raw(source=source, max_incidents=max_incidents)
    evidence, drop_stats = drop_unusable(raw)

    # Stable ordering before anything is hashed or split.
    evidence = evidence.sort_values(["incident_id", "alert_id", "evidence_id"]).reset_index(
        drop=True
    )

    incident_table = incidents_mod.aggregate(evidence)

    summaries = []
    for _, row in incident_table.iterrows():
        rows = incidents_mod.evidence_for(evidence, row["incident_id"])
        summaries.append(build_incident_summary(row, rows))
    incident_table["summary"] = summaries

    # Carry the split down to evidence level so retrieval indexes can honour it.
    split_map = dict(zip(incident_table["incident_id"], incident_table["split"]))
    evidence["split"] = evidence["incident_id"].map(split_map)

    stats = {
        "source": source,
        "max_incidents": max_incidents,
        **drop_stats,
        "incidents": int(len(incident_table)),
        "label_distribution": {
            str(k): int(v) for k, v in incident_table["label"].value_counts().items()
        },
        "split_sizes": {
            str(k): int(v) for k, v in incident_table["split"].value_counts().items()
        },
    }
    return evidence, incident_table, stats


def write(evidence: pd.DataFrame, incident_table: pd.DataFrame, stats: dict) -> dict:
    ensure_dirs()
    evidence.to_parquet(loader.EVIDENCE_PARQUET, index=False)
    incident_table.to_parquet(loader.INCIDENTS_PARQUET, index=False)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **stats,
        "evidence_rows": int(len(evidence)),
        "evidence_content_sha256": content_hash(evidence),
        "incidents_content_sha256": content_hash(incident_table),
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=settings.data_source, choices=["fixture", "guide"])
    parser.add_argument("-n", "--max-incidents", type=int, default=settings.demo_incident_count)
    parser.add_argument(
        "--verify-determinism",
        action="store_true",
        help="build twice and fail if the content hashes differ",
    )
    args = parser.parse_args()

    evidence, incident_table, stats = build(args.source, args.max_incidents)
    manifest = write(evidence, incident_table, stats)

    print(json.dumps(manifest, indent=2, sort_keys=True))

    if args.verify_determinism:
        second_evidence, second_incidents, _ = build(args.source, args.max_incidents)
        mismatches = []
        if content_hash(second_evidence) != manifest["evidence_content_sha256"]:
            mismatches.append("evidence")
        if content_hash(second_incidents) != manifest["incidents_content_sha256"]:
            mismatches.append("incidents")
        if mismatches:
            print(f"\nDETERMINISM CHECK FAILED for: {', '.join(mismatches)}", file=sys.stderr)
            return 1
        print("\nDETERMINISM CHECK PASSED — both tables reproduce identical content hashes.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
