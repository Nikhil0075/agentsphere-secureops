"""The LLM boundary.

One interface, three backends, chosen by ``LLM_BACKEND``:

``openai``
    Live structured-output calls. Responses are written to the cache as they arrive.
``cache``
    Replay from ``artifacts/llm_cache/`` only. No network. A cache miss is an error, because
    silently falling back to something else would make a "reproduced" run a lie.
``deterministic``
    Rule-based agents. No network, no key, schema-valid output every time.

The third backend is not a toy. §14.3 requires "a fallback mode works with no external API
dependency" and §13.3 lists venue network failure as a live risk, so the offline path has to be
built alongside the online one rather than bolted on the night before.

Cache keys are ``sha256(model + prompt + schema)``. Including the schema matters: if a contract
changes, the old response is no longer valid for the new shape, and a key that ignored the schema
would serve it anyway.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from app.config import LLM_CACHE_DIR, settings


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


class LLMClient(Protocol):
    backend: str
    model: str

    def complete_structured(
        self, *, system: str, prompt: str, schema: dict, name: str
    ) -> LLMResponse: ...


def cache_key(model: str, system: str, prompt: str, schema: dict) -> str:
    payload = json.dumps(
        {"model": model, "system": system, "prompt": prompt, "schema": schema},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ResponseCache:
    """Content-addressed store of model responses."""

    def __init__(self, directory: Path | str = LLM_CACHE_DIR) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

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

    def put(self, key: str, data: dict, meta: dict | None = None) -> None:
        self.path_for(key).write_text(
            json.dumps({"data": data, "meta": meta or {}}, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def __len__(self) -> int:
        return len(list(self.directory.glob("*.json")))


# --- backends -------------------------------------------------------------------------------

class OpenAIClient:
    """Live structured-output calls, with the cache written through."""

    backend = "openai"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
        cache: ResponseCache | None = None,
    ) -> None:
        # `None` means "take it from config"; an explicit "" means "there is no key" and must
        # not silently fall back to one.
        key = settings.openai_api_key if api_key is None else api_key
        if not key:
            raise LLMError(
                "LLM_BACKEND=openai requires OPENAI_API_KEY in .env. "
                "Use LLM_BACKEND=deterministic to run without a key."
            )
        from openai import OpenAI

        self.model = model or settings.openai_model
        self.timeout = timeout or settings.llm_timeout_seconds
        self.cache = cache or ResponseCache()
        self._client = OpenAI(api_key=key, timeout=self.timeout)

    def complete_structured(
        self, *, system: str, prompt: str, schema: dict, name: str
    ) -> LLMResponse:
        key = cache_key(self.model, system, prompt, schema)
        hit = self.cache.get(key)
        if hit is not None:
            return LLMResponse(
                data=hit["data"], backend=self.backend, model=self.model, cached=True
            )

        started = time.perf_counter()
        completion = self._client.chat.completions.create(
            model=self.model,
            temperature=0,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {"name": name, "strict": True, "schema": schema},
            },
        )
        latency = int((time.perf_counter() - started) * 1000)

        content = completion.choices[0].message.content or "{}"
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise LLMError(f"{name}: model returned non-JSON content") from exc

        usage = completion.usage
        meta = {
            "model": self.model,
            "latency_ms": latency,
            "prompt_tokens": getattr(usage, "prompt_tokens", 0),
            "completion_tokens": getattr(usage, "completion_tokens", 0),
        }
        self.cache.put(key, data, meta)

        return LLMResponse(
            data=data,
            backend=self.backend,
            model=self.model,
            latency_ms=latency,
            prompt_tokens=meta["prompt_tokens"],
            completion_tokens=meta["completion_tokens"],
        )


class CacheOnlyClient:
    """Replay a previous run exactly. A miss is an error, not a fallback."""

    backend = "cache"

    def __init__(self, model: str | None = None, cache: ResponseCache | None = None) -> None:
        self.model = model or settings.openai_model
        self.cache = cache or ResponseCache()

    def complete_structured(
        self, *, system: str, prompt: str, schema: dict, name: str
    ) -> LLMResponse:
        key = cache_key(self.model, system, prompt, schema)
        hit = self.cache.get(key)
        if hit is None:
            raise CacheMiss(
                f"{name}: no cached response for this prompt under model {self.model}. "
                "Run once with LLM_BACKEND=openai to populate the cache."
            )
        return LLMResponse(
            data=hit["data"], backend=self.backend, model=self.model, cached=True
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
        self, *, system: str, prompt: str, schema: dict, name: str
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

    def complete_structured(self, *, system: str, prompt: str, schema: dict, name: str):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error(f"{name}: simulated backend failure {self.calls}")
        return LLMResponse(data=dict(self.payload), backend=self.backend, model=self.model)


def build_client(backend: str | None = None) -> LLMClient:
    """Construct the configured backend."""
    backend = (backend or settings.llm_backend).lower()
    if backend == "openai":
        return OpenAIClient()
    if backend == "cache":
        return CacheOnlyClient()
    if backend == "deterministic":
        return DeterministicClient()
    raise LLMError(
        f"unknown LLM_BACKEND {backend!r}; expected openai, cache or deterministic"
    )
