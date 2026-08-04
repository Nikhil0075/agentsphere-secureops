"""Structured JSON logging for every agent call.

Two sinks, one record. The JSON lines go to stderr for a live run; the same fields go into the
``agent_runs`` table, which is what the UI timeline reads. Latency, token usage, retry count and
validation result are all captured — §6 lists exactly those as the observability requirement, and
a fallback that is not visible in the timeline may as well not have been recorded at all.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from typing import Any

from app.agents.schemas import AgentRunRecord

LOGGER_NAME = "agentsphere"

_configured = False


def _configure() -> logging.Logger:
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    if not _configured:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        _configured = True
    return logger


def log_event(event: str, **fields: Any) -> None:
    _configure().info(json.dumps({"event": event, **fields}, sort_keys=True, default=str))


def log_agent_call(workflow_id: str, incident_id: str, record: AgentRunRecord) -> None:
    log_event(
        "agent_call",
        workflow_id=workflow_id,
        incident_id=incident_id,
        **record.model_dump(mode="json"),
    )


def persist_agent_run(
    conn,
    workflow_id: str,
    incident_id: str,
    record: AgentRunRecord,
    output_json: str = "",
) -> str:
    """Write one agent run into ``agent_runs``. Returns the run id."""
    run_id = f"RUN-{uuid.uuid4().hex[:12]}"
    conn.execute(
        """
        INSERT INTO agent_runs (
            run_id, workflow_id, incident_id, agent, sequence, backend, model, status,
            attempts, latency_ms, prompt_tokens, completion_tokens, validation_error,
            output_json, output_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            workflow_id,
            incident_id,
            record.agent,
            record.sequence,
            record.backend,
            record.model,
            record.status,
            record.attempts,
            record.latency_ms,
            record.prompt_tokens,
            record.completion_tokens,
            record.validation_error,
            output_json,
            record.output_hash,
        ),
    )
    return run_id
