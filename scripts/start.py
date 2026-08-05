"""One command to bring the whole demo up.

    python scripts/start.py                 # API + frontend
    python scripts/start.py --setup         # prepare data, train, index, load the DB, then run
    python scripts/start.py --check         # verify everything is in place, start nothing

Chosen over docker-compose deliberately. The demo runs from a laptop on venue wifi, where a
container build is one more thing that can fail in the ten minutes before presenting, and the
GUIDE dataset lives outside the repo anyway. This checks each prerequisite, says plainly which
one is missing and which command fixes it, then starts both servers and shuts them down together.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import ARTIFACTS, DATA_PROCESSED, MODELS_DIR, REPO_ROOT, settings  # noqa: E402

API_PORT = 8000
UI_PORT = 5173

VENV_PYTHON = REPO_ROOT / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


class Check:
    def __init__(self, name: str, ok: bool, detail: str, fix: str = "") -> None:
        self.name, self.ok, self.detail, self.fix = name, ok, detail, fix


def preflight() -> list[Check]:
    """Everything the demo needs, and the command that produces each missing piece."""
    checks: list[Check] = []

    evidence = DATA_PROCESSED / "evidence.parquet"
    checks.append(
        Check(
            "prepared dataset",
            evidence.exists(),
            str(evidence) if evidence.exists() else "missing",
            "python scripts/prepare_data.py",
        )
    )

    model = MODELS_DIR / "baseline.pkl"
    checks.append(
        Check(
            "baseline model",
            model.exists(),
            "trained" if model.exists() else "missing",
            "python scripts/train_baseline.py",
        )
    )

    index = ARTIFACTS / "index" / "corpus.json"
    checks.append(
        Check(
            "retrieval index",
            index.exists(),
            "built" if index.exists() else "missing (retrieval falls back to entity overlap)",
            "python scripts/build_index.py",
        )
    )

    database = settings.resolved_db_path
    checks.append(
        Check(
            "database",
            database.exists(),
            str(database) if database.exists() else "missing",
            "python scripts/init_db.py",
        )
    )

    deployment = ARTIFACTS / "chain" / "deployment.json"
    checks.append(
        Check(
            "chain deployment",
            deployment.exists(),
            "recorded" if deployment.exists() else "none (proof panel degrades, nothing else)",
            "cd contracts && npm run deploy:sepolia",
        )
    )

    node_modules = REPO_ROOT / "frontend" / "node_modules"
    checks.append(
        Check(
            "frontend deps",
            node_modules.exists(),
            "installed" if node_modules.exists() else "missing",
            "cd frontend && npm install",
        )
    )

    checks.append(
        Check("llm backend", True, f"{settings.llm_backend} (deterministic needs no key)", "")
    )
    return checks


def report(checks: list[Check]) -> bool:
    print("\npreflight")
    print("-" * 66)
    blocking = False
    #: Without these two the API cannot start at all; the rest degrade.
    required = {"prepared dataset", "database"}

    for check in checks:
        mark = "ok  " if check.ok else ("FAIL" if check.name in required else "warn")
        print(f"  [{mark}] {check.name:<20} {check.detail}")
        if not check.ok:
            print(f"         fix: {check.fix}")
            if check.name in required:
                blocking = True
    print("-" * 66)
    return not blocking


def run_setup() -> int:
    """Produce every generated artifact from a clean checkout."""
    steps = [
        ("preparing data", [str(VENV_PYTHON), "scripts/prepare_data.py"]),
        ("training baseline", [str(VENV_PYTHON), "scripts/train_baseline.py"]),
        ("building index", [str(VENV_PYTHON), "scripts/build_index.py"]),
        ("loading database", [str(VENV_PYTHON), "scripts/init_db.py"]),
    ]
    for label, command in steps:
        print(f"\n=== {label} ===", flush=True)
        result = subprocess.run(command, cwd=REPO_ROOT)
        if result.returncode != 0:
            print(f"\n{label} failed", file=sys.stderr)
            return result.returncode
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", action="store_true", help="build artifacts first")
    parser.add_argument("--check", action="store_true", help="preflight only")
    parser.add_argument("--api-only", action="store_true")
    parser.add_argument("--api-port", type=int, default=API_PORT)
    args = parser.parse_args()

    if args.setup and (code := run_setup()):
        return code

    if not report(preflight()):
        print("\nCannot start: fix the FAIL rows above, or run with --setup.", file=sys.stderr)
        return 1
    if args.check:
        return 0

    processes: list[tuple[str, subprocess.Popen]] = []
    try:
        api = subprocess.Popen(
            [
                str(VENV_PYTHON), "-m", "uvicorn", "app.api.main:app",
                "--port", str(args.api_port), "--log-level", "warning",
            ],
            cwd=REPO_ROOT,
        )
        processes.append(("api", api))
        print(f"\napi        http://localhost:{args.api_port}")
        print(f"docs       http://localhost:{args.api_port}/docs")

        if not args.api_only:
            npm = shutil.which("npm") or shutil.which("npm.cmd")
            if npm is None:
                print("npm not found; starting the API only", file=sys.stderr)
            else:
                ui = subprocess.Popen(
                    [npm, "run", "dev", "--", "--port", str(UI_PORT)],
                    cwd=REPO_ROOT / "frontend",
                    shell=sys.platform == "win32",
                )
                processes.append(("ui", ui))
                print(f"ui         http://localhost:{UI_PORT}")

        print("\nCtrl-C to stop both.\n")
        while all(p.poll() is None for _, p in processes):
            time.sleep(1)

        for name, process in processes:
            if process.poll() is not None:
                print(f"\n{name} exited with code {process.returncode}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        # Stop everything together: leaving a stray uvicorn holding port 8000 is a confusing
        # way to start the next rehearsal.
        for _, process in processes:
            if process.poll() is None:
                process.terminate()
        for _, process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
