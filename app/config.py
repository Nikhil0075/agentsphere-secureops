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


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _float_or_none(name: str) -> float | None:
    """Unset means "do not send this parameter at all", which is not the same as sending 0.0."""
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    try:
        return float(value)
    except ValueError:
        return None


@dataclass(frozen=True)
class Settings:
    llm_backend: str = os.getenv("LLM_BACKEND", "replay")
    # repr=False: a dataclass repr appears in tracebacks, pytest failure output and log lines.
    # Without this the API key is printed verbatim the first time anything raises near it.
    openai_api_key: str = field(default=os.getenv("OPENAI_API_KEY", ""), repr=False)
    openai_support_model: str = os.getenv("OPENAI_SUPPORT_MODEL", "gpt-5.6-terra")
    openai_judge_model: str = os.getenv("OPENAI_JUDGE_MODEL", "gpt-5.6-sol")
    openai_reasoning_effort: str = os.getenv("OPENAI_REASONING_EFFORT", "medium")
    # 2026-08-08: Triage and Verifier now receive the evidence records they are asked to cite and
    # verify. Bumped so no cached response from the starved prompts can be replayed.
    agent_prompt_version: str = os.getenv("AGENT_PROMPT_VERSION", "2026-08-08")
    agent_tracing_enabled: bool = _bool("AGENT_TRACING_ENABLED", False)
    agent_trace_include_sensitive: bool = _bool("AGENT_TRACE_INCLUDE_SENSITIVE", False)
    llm_timeout_seconds: int = _int("LLM_TIMEOUT_SECONDS", 45)
    llm_max_retries: int = _int("LLM_MAX_RETRIES", 1)
    # Per-HTTP-request timeout is not the whole story: the SDK may take up to `max_turns`
    # requests, so a hung stage needs its own ceiling. 0 means "derive it from the timeout".
    llm_wall_clock_seconds: int = _int("LLM_WALL_CLOCK_SECONDS", 0)
    # Both default to None: the active models are reasoning models that reject these parameters,
    # so nothing is sent unless a run explicitly asks for it. Setting them does not make a
    # reasoning model deterministic -- see the Determinism section of the README.
    llm_temperature: float | None = _float_or_none("LLM_TEMPERATURE")
    llm_top_p: float | None = _float_or_none("LLM_TOP_P")

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
