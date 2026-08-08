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

import json
import time
from abc import ABC, abstractmethod
from typing import Any

from pydantic import ValidationError

from app.agents.json_schema import to_openai_schema
from app.agents.llm import DeterministicClient, LLMClient, LLMError
from app.agents.schemas import AgentRunRecord, StrictModel, WorkflowState
from app.blockchain.hashing import hash_agent_output
from app.config import settings
from app.data.schema import LABELS
from app.observability.logging import log_agent_call, log_event

#: Agents that run before any label-bearing prediction is in play. Their prompts must contain no
#: triage label string at all — that is invariant 2, and `_record_trace` makes it checkable.
PRE_DECISION_AGENTS = frozenset({"detection", "correlation", "investigation"})

#: Prompts are for display, not for storage. A pathological context should not put a megabyte of
#: JSON on the wire.
MAX_TRACE_CHARS = 20_000

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

    def reconcile(self, output: StrictModel, context: dict) -> StrictModel:
        """Apply deterministic checks to a model-produced output before it is accepted.

        Default is identity. It exists for agents whose correctness rests on checks that must run
        *regardless of backend* — the Verifier being the case that matters. Without this hook a
        structural check written in Python only ever runs on the offline path, which is exactly
        backwards: the live model is the one that needs constraining.

        Runs before hashing, so the hash covers the reconciled output that the system actually
        acted on.
        """
        return output

    def validate_grounding(self, output: StrictModel, context: dict) -> None:
        """Reject schema-valid outputs that cite facts outside their bounded context.

        Schema validity says the shape is right; it says nothing about whether the *contents* were
        observed. An `evidence_id` the model invented, a remediation action outside the catalogue
        and a fabricated incident id are all perfectly schema-valid.

        The Investigation checks below are the two most confabulation-prone fields in the whole
        contract, and they were the two unguarded ones. They use deliberately different allowlists:

        * ``similar_cases`` is **closed** -- the retriever's returned ids and nothing else. There
          is no legitimate route by which the model could know another incident's id.
        * ``mitre_mapping`` is a **union** -- the incident's own tagged techniques *plus* the known
          set. A model may legitimately map to a technique the detector missed; it may not map to
          one that does not exist.
        """
        payload = output.model_dump(mode="json")
        allowed_ids = set(
            context.get("evidence_ids")
            or context.get("evidence_bundle")
            or context.get("bundle")
            or []
        )
        cited: list[str] = []

        blanks = 0

        def walk(value: Any) -> None:
            nonlocal blanks
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "evidence_id":
                        if child:
                            cited.append(str(child))
                        elif child is not None:
                            blanks += 1
                    elif key in {"evidence_bundle", "supporting_evidence_ids"} and isinstance(
                        child, list
                    ):
                        for item in child:
                            if item:
                                cited.append(str(item))
                            else:
                                blanks += 1
                    else:
                        walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(payload)

        # A blank citation used to be dropped here, which let it reach the verifier's structural
        # check and get the whole decision rejected -- a live model emitted `[""]` and then `[":"]`
        # into a triage bundle. The contract's min_length applies to the list, not its items, and
        # the contract is frozen, so an empty id is caught here instead.
        if blanks:
            raise ValueError(f"{blanks} blank evidence citation(s)")

        unknown = sorted({value for value in cited if value not in allowed_ids})
        if unknown:
            raise ValueError(f"unknown evidence citation(s): {', '.join(unknown[:5])}")

        if self.name == "remediation":
            allowed_actions = set(context.get("applicable_ids") or [])
            action = str(payload.get("recommended_action", ""))
            if action not in allowed_actions:
                raise ValueError(f"action {action!r} is outside the applicable policy catalogue")

        if self.name == "detection":
            # Every entity in the incident, not just the top-N summary. The prompt's evidence
            # block exposes more than the summary does, so the narrower list rejected real
            # citations as invented -- it failed three of the six demo cases.
            allowed_entities = set(context.get("known_entities") or set())
            allowed_entities |= {str(item[1]) for item in context.get("top_entities") or []}
            reported = {
                str(entity.get("value", ""))
                for entity in payload.get("suspicious_entities") or []
                if entity.get("value")
            }
            unknown_entities = sorted(reported - allowed_entities)
            if unknown_entities:
                raise ValueError(
                    "detection reported entity(ies) outside the incident: "
                    f"{', '.join(unknown_entities[:5])}"
                )

        if self.name == "investigation":
            from app.agents import mitre

            retrieved = {
                str(case.get("incident_id", "")) for case in context.get("similar") or []
            }
            invented = sorted(
                {
                    incident_id
                    for case in payload.get("similar_cases") or []
                    if (incident_id := str(case.get("incident_id", "")))
                    and incident_id not in retrieved
                }
            )
            if invented:
                raise ValueError(
                    f"invented similar-case incident id(s): {', '.join(invented[:5])}"
                )

            tagged = {str(value) for value in context.get("techniques") or []}
            unknown = sorted(
                {
                    technique_id
                    for mapping in payload.get("mitre_mapping") or []
                    if (technique_id := str(mapping.get("technique_id", "")))
                    and technique_id not in tagged
                    and not mitre.is_known_technique(technique_id)
                }
            )
            if unknown:
                raise ValueError(
                    "MITRE technique(s) outside the incident and the known set: "
                    f"{', '.join(unknown[:5])}"
                )

    # --- execution ----------------------------------------------------------------------

    @property
    def system_prompt(self) -> str:
        return f"{SYSTEM_PREAMBLE}\n\nYour role: {self.role}"

    def schema(self) -> dict:
        return to_openai_schema(self.output_model)

    def _record_trace(self, sink: dict, context: dict, prompt: str) -> None:
        """Record what this agent was asked and what it was allowed to see.

        Kept for display, and specifically so invariant 2 can be *read* rather than trusted: the
        pre-decision agents' rendered prompts are scanned for the three triage label strings, and a
        hit is a leak.

        ``label_free`` covers the **user** prompt only, not the system prompt. Triage's role has to
        name the three labels — it is choosing between them — and that static role text is
        identical for every incident, so it cannot carry an answer. Scanning it would report a leak
        on a prompt that contains no incident-specific label at all. What the user prompt may
        legitimately contain, for Triage onwards, is the non-LLM baseline's *prediction*: a model
        output, not the ground truth.

        Must never raise: a display feature that can abort a workflow is worse than no display.
        """
        try:
            context_json = json.dumps(context, sort_keys=True, indent=2, default=str)
        except (TypeError, ValueError):
            context_json = repr(context)

        pre_decision = self.name in PRE_DECISION_AGENTS

        sink.update(
            {
                "agent": self.name,
                "system_prompt": self.system_prompt[:MAX_TRACE_CHARS],
                "user_prompt": prompt[:MAX_TRACE_CHARS],
                "context_json": context_json[:MAX_TRACE_CHARS],
                "context_keys": sorted(str(key) for key in context),
                "truncated": (
                    len(prompt) > MAX_TRACE_CHARS or len(context_json) > MAX_TRACE_CHARS
                ),
                "pre_decision": pre_decision,
                "label_free": not any(label in prompt for label in LABELS),
            }
        )

    def _evict(self, response: Any) -> None:
        """Drop a cached response this agent has just rejected.

        The client writes as soon as the response parses, which is before grounding is checked.
        Only validated output should survive in the cache: otherwise a single bad generation is
        replayed forever and the incident degrades identically on every run, which looks like a
        deterministic system fault rather than the one-off model failure it was.
        """
        key = getattr(response, "cache_key", "")
        cache = getattr(self.client, "cache", None)
        if not key or cache is None:
            return
        try:
            if cache.invalidate(key):
                log_event("cache_entry_invalidated", agent=self.name, reason="failed validation")
        except OSError:  # pragma: no cover - a locked file must not abort the run
            pass

    def run(
        self,
        state: WorkflowState,
        *,
        trace_sink: dict | None = None,
        **kwargs: Any,
    ) -> tuple[StrictModel, AgentRunRecord]:
        # `trace_sink` is keyword-only so it is bound before **kwargs and can never be forwarded
        # into build_context, where an unexpected key would end up in an agent's prompt.
        context = self.build_context(state, **kwargs)
        prompt = self.build_prompt(context)
        schema = self.schema()

        if trace_sink is not None:
            self._record_trace(trace_sink, context, prompt)

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
                    output_type=self.output_model,
                    tool_context=context,
                    reasoning_effort=kwargs.get("reasoning_effort"),
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
                self._evict(response)
                continue

            try:
                self.validate_grounding(output, context)
            except ValueError as exc:
                last_error = f"grounding validation failed: {exc}"
                self._evict(response)
                continue

            output = self.reconcile(output, context)

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
                cached=response.cached,
                trace_id=response.trace_id,
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
