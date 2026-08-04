"""Central configuration. Everything that varies between machines lives here."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(REPO_ROOT / ".env")

DATA_RAW = REPO_ROOT / "data" / "raw"
DATA_PROCESSED = REPO_ROOT / "data" / "processed"
ARTIFACTS = REPO_ROOT / "artifacts"
MODELS_DIR = ARTIFACTS / "models"
METRICS_DIR = ARTIFACTS / "metrics"
SCHEMAS_DIR = ARTIFACTS / "schemas"
GRAPH_DIR = ARTIFACTS / "graph"
LLM_CACHE_DIR = ARTIFACTS / "llm_cache"


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "") or default)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    llm_backend: str = os.getenv("LLM_BACKEND", "deterministic")
    # repr=False: a dataclass repr appears in tracebacks, pytest failure output and log lines.
    # Without this the API key is printed verbatim the first time anything raises near it.
    openai_api_key: str = field(default=os.getenv("OPENAI_API_KEY", ""), repr=False)
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    llm_timeout_seconds: int = _int("LLM_TIMEOUT_SECONDS", 45)
    llm_max_retries: int = _int("LLM_MAX_RETRIES", 1)

    data_source: str = os.getenv("DATA_SOURCE", "fixture")
    guide_path: str = os.getenv("GUIDE_PATH", "")
    demo_incident_count: int = _int("DEMO_INCIDENT_COUNT", 200)

    db_path: str = os.getenv("DB_PATH", "artifacts/agentsphere.db")

    @property
    def resolved_db_path(self) -> Path:
        p = Path(self.db_path)
        return p if p.is_absolute() else REPO_ROOT / p


settings = Settings()


def ensure_dirs() -> None:
    for d in (
        DATA_RAW,
        DATA_PROCESSED,
        MODELS_DIR,
        METRICS_DIR,
        SCHEMAS_DIR,
        GRAPH_DIR,
        LLM_CACHE_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True)
