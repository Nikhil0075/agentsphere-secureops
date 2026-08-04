"""Common agent machinery: prompt assembly, strict validation, retry, fallback.

The contract every agent honours: **it always returns a schema-valid output object, and it always
reports honestly how it got there.** A model timeout, a malformed response or a validation failure
degrades to a conservative fallback and is recorded as such in the ``AgentRunRecord`` — it does not
abort the workflow and it does not quietly masquerade as a successful reasoning step.

That distinction is load-bearing. A fallback triage marked ``ok`` would corrupt the metrics; a
fallback triage marked ``fallback`` is a measurable degradation the Verifier and the metrics
dashboard can both see.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from pydantic import ValidationError

from app.agents.json_schema import to_openai_schema
from app.agents.llm import DeterministicClient, LLMClient, LLMError
from app.agents.schemas import AgentRunRecord, StrictModel, WorkflowState
from app.blockchain.hashing import hash_agent_output
from app.config import settings
from app.observability.logging import log_agent_call

SYSTEM_PREAMBLE = (
    "You are a specialised agent inside a Security Operations Centre triage system. "
    "You perform exactly one bounded role and you do not speculate beyond the evidence supplied. "
    "Cite evidence by its identifier. If the evidence does not support a conclusion, say so "
    "rather than inventing one. All remediation in this system is simulated; you never take an "
    "action, you only recommend one. Respond only with JSON matching the provided schema."
)


class Agent(ABC):
    """One bounded role, one frozen output contract."""

    #: Contract key; must match a key in ``AGENT_OUTPUT_MODELS``.
    name: str
    #: Frozen Pydantic model this agent must produce.
    output_model: type[StrictModel]
    #: Role instruction appended to the shared preamble.
    role: str = ""

    def __init__(self, client: LLMClient, sequence: int = 0) -> None:
        self.client = client
        self.sequence = sequence

    # --- to implement -------------------------------------------------------------------

    @abstractmethod
    def build_context(self, state: WorkflowState, **kwargs: Any) -> dict:
        """Structured facts this agent reasons over. Also what the deterministic backend sees."""

    @abstractmethod
    def build_prompt(self, context: dict) -> str:
        """Render the context as the user message."""

    @abstractmethod
    def fallback(self, context: dict) -> StrictModel:
        """A conservative, schema-valid output for when the model cannot be trusted.

        Conservative means: assume less, escalate more. A fallback that guesses confidently is
        worse than no agent at all.
        """

    def deterministic(self, context: dict) -> dict:
        """Rule-based output for the offline backend. Defaults to the fallback."""
        return self.fallback(context).model_dump(mode="json")

    # --- execution ----------------------------------------------------------------------

    @property
    def system_prompt(self) -> str:
        return f"{SYSTEM_PREAMBLE}\n\nYour role: {self.role}"

    def schema(self) -> dict:
        return to_openai_schema(self.output_model)

    def run(self, state: WorkflowState, **kwargs: Any) -> tuple[StrictModel, AgentRunRecord]:
        context = self.build_context(state, **kwargs)
        prompt = self.build_prompt(context)
        schema = self.schema()

        if isinstance(self.client, DeterministicClient):
            self.client.register(self.name, self.deterministic)
            self.client.set_context(context)

        attempts = 0
        started = time.perf_counter()
        last_error = ""
        max_attempts = max(1, settings.llm_max_retries + 1)

        while attempts < max_attempts:
            attempts += 1
            try:
                response = self.client.complete_structured(
                    system=self.system_prompt,
                    prompt=prompt,
                    schema=schema,
                    name=self.name,
                )
            except LLMError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                continue
            except Exception as exc:  # noqa: BLE001 - a transport error must not kill the run
                last_error = f"{type(exc).__name__}: {exc}"
                continue

            try:
                output = self.output_model.model_validate(response.data)
            except ValidationError as exc:
                last_error = f"schema validation failed: {exc.error_count()} error(s)"
                continue

            record = AgentRunRecord(
                agent=self.name,
                sequence=self.sequence,
                status="ok",
                attempts=attempts,
                latency_ms=response.latency_ms
                or int((time.perf_counter() - started) * 1000),
                backend=response.backend,
                model=response.model,
                prompt_tokens=response.prompt_tokens,
                completion_tokens=response.completion_tokens,
                output_hash=hash_agent_output(self.name, output),
            )
            log_agent_call(state.workflow_id, state.incident_id, record)
            return output, record

        # Every attempt failed. Degrade, and say so.
        output = self.fallback(context)
        record = AgentRunRecord(
            agent=self.name,
            sequence=self.sequence,
            status="fallback",
            attempts=attempts,
            latency_ms=int((time.perf_counter() - started) * 1000),
            backend=getattr(self.client, "backend", "unknown"),
            model=getattr(self.client, "model", ""),
            validation_error=last_error,
            output_hash=hash_agent_output(self.name, output),
        )
        log_agent_call(state.workflow_id, state.incident_id, record)
        return output, record
