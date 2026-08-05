"""Download the WitFoo Precinct6 provenance graph.

    python scripts/download_witfoo.py
    python scripts/download_witfoo.py --include-signals   # adds the 429 MB signal log

Fetches ~442 MB into ``data/raw/witfoo/``. Re-running skips files that are already complete, so an
interrupted download resumes by simply running it again.

**Deliberately not using the `datasets` library.** The dataset's own YAML declares
``graph/nodes.jsonl``, ``graph/edges.jsonl`` and ``graph/incidents.jsonl`` as ``parquet`` when they
are JSONL, so ``load_dataset`` and the Hugging Face datasets-server both fail on them with
"Parquet magic bytes not found in footer". The files themselves are fine. Plain HTTP sidesteps a
bug in the dataset's metadata that we cannot fix from here.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import DATA_RAW, ensure_dirs  # noqa: E402

REPO = "witfoo/precinct6-cybersecurity"
BASE = f"https://huggingface.co/datasets/{REPO}/resolve/main"
WITFOO_DIR = DATA_RAW / "witfoo"

#: (remote path, why we want it). Only what the provenance-graph work needs.
FILES: list[tuple[str, str]] = [
    ("graph/metadata.json", "authoritative node/edge counts — the citation source"),
    ("graph/nodes.jsonl", "35,133 typed nodes"),
    ("graph/edges.jsonl", "634,190 labelled edges — the reason this dataset is worth having"),
    ("graph/attack_reports.jsonl", "per-incident MITRE, MO name, disposition"),
    ("signals/metadata.json", "signal counts, for the scale narrative"),
    ("reference/lead_rules_catalog.json", "the detection rules the labels reference"),
]

OPTIONAL = [("signals/signals.parquet", "2,100,363 raw signals; not needed for the graph")]


def human(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def download(remote: str, note: str) -> bool:
    """Fetch one file. Returns False on failure rather than raising."""
    import requests

    target = WITFOO_DIR / remote.replace("/", "_")
    url = f"{BASE}/{remote}"

    try:
        head = requests.head(url, allow_redirects=True, timeout=30)
        expected = int(head.headers.get("Content-Length", 0))
    except Exception as exc:  # noqa: BLE001 - report and continue with the next file
        print(f"  {remote}: HEAD failed ({type(exc).__name__}: {exc})", file=sys.stderr)
        expected = 0

    if target.exists() and expected and target.stat().st_size == expected:
        print(f"  {remote:<38} {human(expected):>10}  already complete")
        return True

    print(f"  {remote:<38} {human(expected) if expected else '?':>10}  {note}", flush=True)

    try:
        started = time.perf_counter()
        with requests.get(url, stream=True, timeout=120) as response:
            response.raise_for_status()
            written = 0
            last_report = 0.0
            # Write to a partial file and rename on success, so an interrupted run never leaves
            # something that looks complete.
            partial = target.with_suffix(target.suffix + ".partial")
            with partial.open("wb") as fh:
                for chunk in response.iter_content(chunk_size=1 << 20):
                    fh.write(chunk)
                    written += len(chunk)
                    now = time.perf_counter()
                    if expected and now - last_report > 2.0:
                        last_report = now
                        pct = 100.0 * written / expected
                        print(
                            f"    {pct:5.1f}%  {human(written)} / {human(expected)}",
                            end="\r",
                            flush=True,
                        )
            partial.replace(target)
        elapsed = time.perf_counter() - started
        print(f"    done      {human(written)} in {elapsed:.1f}s" + " " * 20)
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"    FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--include-signals", action="store_true", help="also fetch the 429 MB signal parquet"
    )
    args = parser.parse_args()

    ensure_dirs()
    WITFOO_DIR.mkdir(parents=True, exist_ok=True)

    wanted = FILES + (OPTIONAL if args.include_signals else [])
    print(f"WitFoo Precinct6 -> {WITFOO_DIR}")
    print(f"{len(wanted)} file(s); the edge file alone is ~435 MB\n")

    failures = [remote for remote, note in wanted if not download(remote, note)]

    print()
    if failures:
        print(f"{len(failures)} file(s) failed: {', '.join(failures)}", file=sys.stderr)
        print("Re-run to retry; completed files are skipped.", file=sys.stderr)
        return 1

    total = sum(f.stat().st_size for f in WITFOO_DIR.glob("*") if f.is_file())
    print(f"complete: {human(total)} in {WITFOO_DIR}")
    print("\nNext: python scripts/build_witfoo_graph.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
