"""Download the Microsoft GUIDE dataset from Kaggle.

    python scripts/download_data.py

Prints the local cache path and writes it to ``data/raw/GUIDE_PATH.txt`` so
``scripts/prepare_data.py --source guide`` can pick it up without further configuration.

kagglehub authenticates with ``~/.kaggle/kaggle.json`` or the ``KAGGLE_USERNAME`` /
``KAGGLE_KEY`` environment variables. The download is multiple gigabytes; run it once and let
kagglehub's cache serve every subsequent call.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import DATA_RAW, ensure_dirs  # noqa: E402

DATASET = "Microsoft/microsoft-security-incident-prediction"


def main() -> int:
    ensure_dirs()
    try:
        import kagglehub
    except ImportError:
        print("kagglehub is not installed. pip install -r requirements.txt", file=sys.stderr)
        return 2

    print(f"Downloading {DATASET} (this is several GB) ...", flush=True)
    try:
        path = kagglehub.dataset_download(DATASET)
    except Exception as exc:  # noqa: BLE001 - surface the real reason, whatever it is
        print(f"FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(
            "\nIf this is an authentication error, place a Kaggle API token at "
            "~/.kaggle/kaggle.json or set KAGGLE_USERNAME and KAGGLE_KEY, then re-run.",
            file=sys.stderr,
        )
        return 1

    marker = DATA_RAW / "GUIDE_PATH.txt"
    marker.write_text(str(path), encoding="utf-8")

    print(f"\nDataset files: {path}")
    files = sorted(Path(path).rglob("*"))
    for f in files:
        if f.is_file():
            print(f"  {f.name}  {f.stat().st_size / 1e9:.2f} GB")
    print(f"\nPath recorded in {marker}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
