"""The model boundary for live, replay and deterministic agent execution.

Live calls use the OpenAI Agents SDK (and therefore the Responses API) while the explicit Python
workflow remains authoritative. Replay is the presentation default: a validated response is used
when available, a configured live client may fill a miss, and the agent layer's existing
conservative fallback handles an unavailable live service.

The third backend is not a toy. §14.3 requires "a fallback mode works with no external API
dependency" and §13.3 lists venue network failure as a live risk, so the offline path has to be
built alongside the online one rather than bolted on the night before.

Cache keys include the model role, prompt version, prompt and schema. A model, prompt or contract
change can therefore never silently reuse a stale response.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from app.config import LLM_CACHE_DIR, settings
from app.observability.logging import log_event


class LLMError(RuntimeError):
    pass


class CacheMiss(LLMError):
    pass


@dataclass
class LLMResponse:
    data: dict[str, Any]
    backend: str
    model: str = ""
    latency_ms: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached: bool = False
    trace_id: str = ""
    #: Where this response lives in the cache, so a caller that finds it invalid can evict it.
    #: Empty for backends that do not cache.
    cache_key: str = ""


class LLMClient(Protocol):
    backend: str
    model: str

    def complete_structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: dict,
        name: str,
        output_type: type[Any] | None = None,
        tool_context: dict[str, Any] | None = None,
        reasoning_effort: str | None = None,
    ) -> LLMResponse: ...


def cache_key(
    model: str,
    system: str,
    prompt: str,
    schema: dict,
    prompt_version: str = "",
) -> str:
    payload = json.dumps(
        {
            "model": model,
            "prompt_version": prompt_version,
            "system": system,
            "prompt": prompt,
            "schema": schema,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


#: Bumped when the stored `meta` shape changes in a way replay must notice.
CACHE_SCHEMA_VERSION = 1


class ResponseCache:
    """Content-addressed store of model responses.

    Replay serves whatever JSON sits in this directory, so the directory is part of the trusted
    computing base of the demo. Two defences follow from that: every write is provenance-stamped
    (:meth:`put`), and every read is checked before it is believed
    (:func:`ResponseCache.is_trustworthy`).
    """

    def __init__(self, directory: Path | str = LLM_CACHE_DIR) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    @property
    def is_production(self) -> bool:
        return self.directory == Path(LLM_CACHE_DIR)

    def path_for(self, key: str) -> Path:
        return self.directory / f"{key}.json"

    def get(self, key: str) -> dict | None:
        path = self.path_for(key)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def invalidate(self, key: str) -> bool:
        """Drop an entry that turned out not to be usable.

        The write happens as soon as the response parses, which is before the agent has checked
        that it is *grounded*. Without eviction a response the agent will always reject stays in
        the cache forever, and every replay of that incident degrades in exactly the same way --
        which is how a live model returning `supporting_evidence_ids: [":"]` became a permanent
        fixture of one demo case.
        """
        path = self.path_for(key)
        if not path.exists():
            return False
        path.unlink()
        return True

    def put(self, key: str, data: dict, meta: dict | None = None) -> None:
        # Reads of the production cache under pytest are fine and necessary -- /api/dataset counts
        # its entries, and the arc replay gate reads it. Writes are the failure mode: two entries
        # in artifacts/llm_cache still carry a test double's exact token counts (120 in, 24 out,
        # latency 0), so a fake runner once wrote fabricated responses into the store the demo
        # replays from. Pruning fixes those two; only this guard stops the next one.
        if os.environ.get("PYTEST_CURRENT_TEST") and self.is_production:
            raise LLMError(
                "the production replay cache is not writable from tests; "
                "construct ResponseCache(tmp_path) instead"
            )

        stamped = dict(meta or {})
        stamped.setdefault("cache_schema", CACHE_SCHEMA_VERSION)
        stamped.setdefault("written_at", datetime.now(timezone.utc).isoformat())
        stamped.setdefault("written_by", "AgentsSDKClient")
        self.path_for(key).write_text(
            json.dumps({"data": data, "meta": stamped}, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    @staticmethod
    def is_trustworthy(
        entry: dict, model: str, prompt_version: str, strict_latency: bool = True
    ) -> tuple[bool, str]:
        """Whether a cache hit may be served, and why not when it may not.

        A key collision is not the risk here -- sha256 over the full prompt makes that
        vanishingly unlikely. The risk is an entry written by something other than a real live
        run: a stale model generation, a pre-versioning write, or a test double.
        """
        meta = entry.get("meta") or {}

        stored_version = str(meta.get("prompt_version", ""))
        if not stored_version:
            return False, "entry predates prompt versioning"
        if stored_version != prompt_version:
            return False, f"prompt_version {stored_version} != {prompt_version}"

        stored_model = str(meta.get("model", ""))
        if stored_model and stored_model != model:
            return False, f"model {stored_model} != {model}"

        # A real network call cannot complete in under a millisecond. Zero latency alongside real
        # token counts is the fingerprint of a fake runner, not of a fast response.
        #
        # Only enforced against the production store. A test writing through the real client into
        # a tmp cache produces exactly this signature legitimately -- and the point of the check is
        # to keep such entries out of artifacts/llm_cache, not to ban them everywhere.
        if strict_latency:
            latency = int(meta.get("latency_ms", 0) or 0)
            tokens = int(meta.get("prompt_tokens", 0) or 0) + int(
                meta.get("completion_tokens", 0) or 0
            )
            if latency == 0 and tokens > 0:
                return False, "zero latency with non-zero tokens; not a live response"

        return True, ""

    def __len__(self) -> int:
        return sum(
            1
            for path in self.directory.glob("*.json")
            if len(path.stem) == 64 and all(char in "0123456789abcdef" for char in path.stem)
        )


# --- model roles and execution modes ---------------------------------------------------------

SUPPORT_AGENTS = frozenset({"detection", "correlation", "investigation", "remediation"})
JUDGE_AGENTS = frozenset({"triage", "verifier"})


def normalize_mode(mode: str | None) -> str:
    value = (mode or settings.llm_backend or "replay").strip().lower()
    aliases = {"cache": "replay", "openai": "live"}
    value = aliases.get(value, value)
    if value not in {"replay", "live", "deterministic"}:
        raise LLMError(
            f"unknown execution mode {mode!r}; expected replay, live or deterministic"
        )
    return value


def model_for_agent(name: str) -> str:
    return settings.openai_judge_model if name in JUDGE_AGENTS else settings.openai_support_model


def model_profile() -> dict[str, str]:
    return {
        "support": settings.openai_support_model,
        "judge": settings.openai_judge_model,
        "reasoning": settings.openai_reasoning_effort,
        "prompt_version": settings.agent_prompt_version,
    }


def _bounded_tools(context: dict[str, Any] | None) -> list[Any]:
    """SDK tools over already-whitelisted workflow context, never over raw dataset rows."""
    if not context:
        return []

    from agents import function_tool

    allowed_ids = list(
        context.get("evidence_ids")
        or context.get("evidence_bundle")
        or context.get("bundle")
        or []
    )[:50]
    similar = list(context.get("similar") or [])[:10]
    graph = {
        "clusters": list(context.get("clusters") or [])[:10],
        "timeline": list(context.get("timeline") or [])[:20],
        "relationships": list(context.get("relationships") or [])[:50],
        "entity_counts": context.get("entity_counts") or {},
    }

    def lookup_evidence(evidence_ids: list[str]) -> dict[str, Any]:
        """Validate up to 20 evidence identifiers against this incident's evidence bundle."""
        requested = [str(value) for value in evidence_ids[:20]]
        allowed = set(allowed_ids)
        return {
            "valid": [value for value in requested if value in allowed],
            "unknown": [value for value in requested if value not in allowed],
            "available_count": len(allowed_ids),
        }

    tools: list[Any] = [
        function_tool(
            lookup_evidence,
            name_override="lookup_evidence",
            description_override=(
                "Read-only validation of evidence IDs from the current incident; returns no "
                "ground-truth label or dataset split."
            ),
        )
    ]

    if similar:
        def search_similar(limit: int = 5) -> list[dict[str, Any]]:
            """Return at most ten already-retrieved similar incidents with labels withheld."""
            bounded = max(1, min(int(limit), 10))
            return similar[:bounded]

        tools.append(function_tool(search_similar, name_override="search_similar"))

    if any(graph.values()):
        def graph_context() -> dict[str, Any]:
            """Return the precomputed graph context for the current incident.

            Takes no parameters on purpose. It used to accept max_hops and hub_degree, clamp them,
            and echo them back as `requested_*` -- while returning the identical precomputed slice
            either way. A tool that accepts a knob it does not turn invites the model to report
            having widened a search it never widened. The depth and hub caps were applied when the
            slice was built and cannot be relaxed from here.
            """
            return dict(graph)

        tools.append(function_tool(graph_context, name_override="get_graph_context"))

    return tools


# --- backends -------------------------------------------------------------------------------

#: The SDK's tool loop budget. One stage may therefore make up to this many HTTP requests.
_MAX_TURNS = 4

#: Single worker, daemon threads: this only ever runs one stage at a time, and a thread left
#: behind by a timed-out call must not keep the interpreter alive.
_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="agentsphere-llm")

_SAMPLING_REJECTION_MARKERS = ("temperature", "top_p", "unsupported", "not supported")


def _rejects_sampling(exc: Exception) -> bool:
    """Whether a failure is the model refusing temperature/top_p rather than a real error."""
    if type(exc).__name__ not in {"BadRequestError", "UnprocessableEntityError"}:
        return False
    message = str(exc).lower()
    return any(marker in message for marker in _SAMPLING_REJECTION_MARKERS)


class AgentsSDKClient:
    """Live structured-output calls through the OpenAI Agents SDK and Responses API."""

    backend = "live"

    def __init__(
        self,
        api_key: str | None = None,
        support_model: str | None = None,
        judge_model: str | None = None,
        timeout: int | None = None,
        cache: ResponseCache | None = None,
    ) -> None:
        # `None` means "take it from config"; an explicit "" means "there is no key" and must
        # not silently fall back to one.
        key = settings.openai_api_key if api_key is None else api_key
        if not key:
            raise LLMError(
                "live execution requires OPENAI_API_KEY in .env. "
                "Use replay or deterministic mode to run without a key."
            )
        self.support_model = support_model or settings.openai_support_model
        self.judge_model = judge_model or settings.openai_judge_model
        self.model = f"{self.support_model}|{self.judge_model}"
        self.timeout = timeout or settings.llm_timeout_seconds
        self.cache = cache if cache is not None else ResponseCache()
        # A stage may take up to `max_turns` HTTP requests, so the per-request timeout is not a
        # ceiling on the stage. This is.
        self.wall_clock = settings.llm_wall_clock_seconds or self.timeout * _MAX_TURNS
        self._sampling_supported = True

        self._configure_sdk(key)

    def _configure_sdk(self, key: str) -> None:
        """Install an explicitly configured client so the timeout is actually applied.

        `set_default_openai_key` builds a client with the SDK's own defaults: no timeout of ours,
        and internal retries. `llm_timeout_seconds` was read into `self.timeout` and then never
        passed to anything, so a hung request could hang the demo indefinitely.

        `max_retries=0` is deliberate. SDK-internal retries are invisible to
        `AgentRunRecord.attempts`, so a "45 second timeout" would silently become 135 seconds and
        the record would still say one attempt. Retrying is `base.Agent.run`'s job, where it is
        counted.
        """
        try:
            from agents import (
                set_default_openai_client,
                set_tracing_disabled,
                set_tracing_export_api_key,
            )
            from openai import AsyncOpenAI

            self._client = AsyncOpenAI(
                api_key=key, timeout=float(self.timeout), max_retries=0
            )
            # The SDK exports traces by default. Local/offline venues often allow the model
            # request but block the separate trace exporter, which otherwise creates a background
            # retry loop after a completed workflow. `use_for_tracing=False` only avoids taking
            # the model client's key for export; it does not disable the SDK's global trace
            # provider. Disable that provider explicitly so an opted-out process cannot enqueue
            # trace batches at all. Trace export is therefore explicit opt-in.
            set_tracing_disabled(not settings.agent_tracing_enabled)
            set_default_openai_client(
                self._client, use_for_tracing=settings.agent_tracing_enabled
            )
            if settings.agent_tracing_enabled:
                set_tracing_export_api_key(key)
        except ImportError:  # pragma: no cover - older SDK without the client hooks
            from agents import set_default_openai_key

            self._client = None
            set_default_openai_key(key, use_for_tracing=settings.agent_tracing_enabled)

    def model_for(self, name: str) -> str:
        return self.judge_model if name in JUDGE_AGENTS else self.support_model

    @staticmethod
    def _model_settings(model_settings_cls, reasoning_cls, effort: str, *, sampling: bool):
        """Reasoning effort always; sampling parameters only when explicitly configured.

        The README used to claim "temperature 0". Nothing set it, and the active models would
        reject it if anything did -- reasoning models do not expose the sampling knobs. Sending
        nothing by default keeps that honest.
        """
        kwargs: dict[str, Any] = {"reasoning": reasoning_cls(effort=effort)}
        if sampling and settings.llm_temperature is not None:
            kwargs["temperature"] = settings.llm_temperature
        if sampling and settings.llm_top_p is not None:
            kwargs["top_p"] = settings.llm_top_p
        return model_settings_cls(**kwargs)

    def _run_bounded(self, runner, sdk_agent, prompt: str, run_config, name: str):
        """Run one stage under a wall-clock ceiling.

        `Runner.run_sync` takes no timeout, and the transport timeout is per HTTP request while a
        stage may make `max_turns` of them. Without this a single hung call hangs the demo.

        The in-flight call cannot be cancelled -- `future.result` only stops waiting. The worker
        is a daemon thread, so an orphan dies with the process rather than holding exit. Raising
        `LLMError` is the point: `base.Agent.run` catches it, retries once, then degrades to a
        fallback recorded as `status="fallback"`, which is exactly the contract in invariant 9.
        """
        future = _EXECUTOR.submit(
            runner.run_sync, sdk_agent, prompt, max_turns=_MAX_TURNS, run_config=run_config
        )
        try:
            return future.result(timeout=self.wall_clock)
        except FuturesTimeout as exc:
            raise LLMError(
                f"{name}: exceeded the {self.wall_clock}s wall-clock budget"
            ) from exc

    def complete_structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: dict,
        name: str,
        output_type: type[Any] | None = None,
        tool_context: dict[str, Any] | None = None,
        reasoning_effort: str | None = None,
    ) -> LLMResponse:
        if output_type is None:
            raise LLMError(f"{name}: Agents SDK execution requires a typed output contract")

        from agents import Agent as SDKAgent
        from agents import ModelSettings, RunConfig, Runner, gen_trace_id
        from agents.model_settings import Reasoning

        model = self.model_for(name)
        effort = reasoning_effort or settings.openai_reasoning_effort
        trace_id = gen_trace_id() if settings.agent_tracing_enabled else ""
        tools = _bounded_tools(tool_context)

        def build_agent(sampling: bool):
            return SDKAgent(
                name=f"AgentSphere {name.title()}",
                instructions=system,
                model=model,
                model_settings=self._model_settings(
                    ModelSettings, Reasoning, effort, sampling=sampling
                ),
                output_type=output_type,
                tools=tools,
            )

        run_config = RunConfig(
            workflow_name=f"AgentSphere/{name}",
            trace_id=trace_id or None,
            tracing_disabled=not settings.agent_tracing_enabled,
            trace_include_sensitive_data=settings.agent_trace_include_sensitive,
            trace_metadata={
                "agent": name,
                "model": model,
                "prompt_version": settings.agent_prompt_version,
            },
        )

        started = time.perf_counter()
        try:
            result = self._run_bounded(Runner, build_agent(self._sampling_supported), prompt, run_config, name)
        except LLMError:
            raise
        except Exception as exc:  # noqa: BLE001 - inspected, then re-raised or retried once
            if not (self._sampling_supported and _rejects_sampling(exc)):
                raise
            # A model that refuses temperature/top_p should not fail the stage over it. Drop the
            # parameters, remember that for the rest of the process, and say so.
            self._sampling_supported = False
            log_event("sampling_params_rejected", agent=name, model=model, error=str(exc)[:200])
            result = self._run_bounded(Runner, build_agent(False), prompt, run_config, name)
        latency = int((time.perf_counter() - started) * 1000)
        output = result.final_output_as(output_type, raise_if_incorrect_type=True)
        data = output.model_dump(mode="json") if hasattr(output, "model_dump") else dict(output)
        usage = result.context_wrapper.usage
        meta = {
            "model": model,
            "latency_ms": latency,
            "prompt_tokens": getattr(usage, "input_tokens", 0),
            "completion_tokens": getattr(usage, "output_tokens", 0),
            "trace_id": trace_id,
            "prompt_version": settings.agent_prompt_version,
        }
        key = cache_key(model, system, prompt, schema, settings.agent_prompt_version)
        self.cache.put(key, data, meta)

        return LLMResponse(
            data=data,
            cache_key=key,
            backend=self.backend,
            model=model,
            latency_ms=latency,
            prompt_tokens=meta["prompt_tokens"],
            completion_tokens=meta["completion_tokens"],
            trace_id=trace_id,
        )


# Kept as a public alias for existing imports and one compatibility window.
OpenAIClient = AgentsSDKClient


class ReplayClient:
    """Validated routed replay. Hermetic by default: a miss never reaches the network.

    ``allow_live_fill`` used to be implicit -- the client constructed a live backend whenever an
    ``OPENAI_API_KEY`` was present, and quietly filled a miss through it. That made "replay" a
    mode that could, mid-demo, become a paid 8-25 second call returning a label nobody had
    rehearsed. Filling is now opt-in and belongs to exactly two callers:
    ``scripts/prewarm_replay.py`` and ``scripts/measure_variance.py``.
    """

    backend = "replay"

    def __init__(
        self,
        cache: ResponseCache | None = None,
        live: AgentsSDKClient | None = None,
        api_key: str | None = None,
        allow_live_fill: bool = False,
    ) -> None:
        self.cache = cache if cache is not None else ResponseCache()
        self.model = f"{settings.openai_support_model}|{settings.openai_judge_model}"
        self.allow_live_fill = allow_live_fill

        # Note the ordering: with filling off, even an explicitly injected live client is dropped.
        # Hermetic has to mean hermetic, or the guarantee is only as good as every caller.
        self.live = None
        if allow_live_fill:
            self.live = live
            if self.live is None:
                key = settings.openai_api_key if api_key is None else api_key
                if not key:
                    raise LLMError(
                        "allow_live_fill=True requires OPENAI_API_KEY in .env"
                    )
                self.live = AgentsSDKClient(api_key=key, cache=self.cache)

    def complete_structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: dict,
        name: str,
        output_type: type[Any] | None = None,
        tool_context: dict[str, Any] | None = None,
        reasoning_effort: str | None = None,
    ) -> LLMResponse:
        model = model_for_agent(name)
        key = cache_key(model, system, prompt, schema, settings.agent_prompt_version)
        hit = self.cache.get(key)

        if hit is not None:
            trusted, reason = ResponseCache.is_trustworthy(
                hit,
                model,
                settings.agent_prompt_version,
                strict_latency=self.cache.is_production,
            )
            if not trusted:
                # Treated as a miss, but loudly. A silently rejected entry looks identical to an
                # absent one, and the operator would go looking for the wrong problem.
                log_event("replay_cache_rejected", agent=name, model=model, reason=reason)
                hit = None

        if hit is not None:
            meta = hit.get("meta") or {}
            return LLMResponse(
                data=hit["data"],
                cache_key=key,
                backend=self.backend,
                model=model,
                latency_ms=int(meta.get("latency_ms", 0) or 0),
                prompt_tokens=int(meta.get("prompt_tokens", 0) or 0),
                completion_tokens=int(meta.get("completion_tokens", 0) or 0),
                cached=True,
                trace_id=str(meta.get("trace_id", "") or ""),
            )

        if self.live is not None:
            return self.live.complete_structured(
                system=system,
                prompt=prompt,
                schema=schema,
                name=name,
                output_type=output_type,
                tool_context=tool_context,
                reasoning_effort=reasoning_effort,
            )

        raise CacheMiss(
            f"{name}: replay cache miss for {model} at prompt version "
            f"{settings.agent_prompt_version}. Run: python scripts/prewarm_replay.py"
            " --dry-run, then rerun with an explicit --max-live-stages budget"
        )


class DeterministicClient:
    """Rule-based agents. No network, no key, always schema-valid.

    Each agent registers a generator keyed by its name. The generator receives the context the
    agent assembled, so these are genuine heuristics over real evidence rather than canned text —
    which is what makes the offline demo defensible rather than a mock.
    """

    backend = "deterministic"

    def __init__(self, model: str = "deterministic-rules-v1") -> None:
        self.model = model
        self._generators: dict[str, Callable[[dict], dict]] = {}
        self._context: dict[str, Any] = {}

    def register(self, name: str, generator: Callable[[dict], dict]) -> None:
        self._generators[name] = generator

    def set_context(self, context: dict) -> None:
        """Structured facts the generators reason over, set by the agent before it calls."""
        self._context = context

    def complete_structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: dict,
        name: str,
        output_type: type[Any] | None = None,
        tool_context: dict[str, Any] | None = None,
        reasoning_effort: str | None = None,
    ) -> LLMResponse:
        generator = self._generators.get(name)
        if generator is None:
            raise LLMError(f"no deterministic generator registered for {name!r}")
        started = time.perf_counter()
        data = generator(self._context)
        return LLMResponse(
            data=data,
            backend=self.backend,
            model=self.model,
            latency_ms=int((time.perf_counter() - started) * 1000),
        )


@dataclass
class FailingClient:
    """Test double that fails a set number of times before succeeding.

    Lives here rather than in the tests so the retry and fallback paths are exercised through the
    same interface the real backends use.
    """

    backend: str = "failing"
    model: str = "failing"
    failures: int = 1
    payload: dict = field(default_factory=dict)
    calls: int = 0
    error: type[Exception] = LLMError

    def complete_structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: dict,
        name: str,
        output_type: type[Any] | None = None,
        tool_context: dict[str, Any] | None = None,
        reasoning_effort: str | None = None,
    ):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error(f"{name}: simulated backend failure {self.calls}")
        return LLMResponse(data=dict(self.payload), backend=self.backend, model=self.model)


def build_client(backend: str | None = None) -> LLMClient:
    """Construct the configured backend."""
    mode = normalize_mode(backend)
    if mode == "live":
        return AgentsSDKClient()
    if mode == "replay":
        return ReplayClient()
    if mode == "deterministic":
        return DeterministicClient()
    raise AssertionError(f"unreachable mode {mode}")
