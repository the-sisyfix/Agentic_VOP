"""LangChain chat-model factory with per-call token-usage tracing.

Public API:

    llm = get_chat_llm(run_id, "master", model="gpt-4o", temperature=0.1)
    plan = llm.with_structured_output(MasterPlan).invoke(messages)

Provider is inferred from the model name prefix:
  - "gpt-*", "o1-*", "o3-*" → OpenAI (ChatOpenAI)
  - "claude-*"              → Anthropic (ChatAnthropic)
  - "gemini-*"              → Google (ChatGoogleGenerativeAI)

A custom callback handler (`_TokenUsageCallback`) attaches to every call so
the Agents page still receives live TOKEN_USAGE events via `emit_trace()`.
The callback reads from LangChain's standardized `usage_metadata` field,
which all three providers populate uniformly.

Capture level: per individual LLM invocation — every `.invoke()` (or async
equivalent) is tracked separately, including parallel worker calls in
Sub-Agent 1 / Sub-Agent 2.
"""

import threading
import time
from .trace import emit_trace  # noqa: PLC0415
from collections import defaultdict
from typing import Any

import httpx
from langchain_anthropic import ChatAnthropic
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, SystemMessage
from langchain_core.outputs import LLMResult
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI

from ..config import settings


# =============================================================================
# Transparent Anthropic prompt-caching
# =============================================================================
# Anthropic's prompt-caching feature (https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching)
# charges 10% of normal input cost for cached blocks reused within ~5 min.
# We tag the first large SystemMessage with `cache_control: ephemeral` so the
# system prompt — reused across every call for a given agent — gets cached.
#
# This is TRANSPARENT: the model sees the same prompt and produces the same
# output, Anthropic just bills less. No downstream behavior changes.
#
# Gated by env flag `ANTHROPIC_PROMPT_CACHING` (default "1" = ON). Set to "0"
# to disable without a code change if the wrapper ever causes issues.

import os as _os  # noqa: PLC0415

_PROMPT_CACHE_MIN_CHARS = 2048  # ~500 tokens; Anthropic's min cacheable size
_PROMPT_CACHE_ENABLED = _os.environ.get("ANTHROPIC_PROMPT_CACHING", "1") == "1"


def _mark_system_cacheable(messages: list[BaseMessage]) -> list[BaseMessage]:
    """Mark the first large SystemMessage with Anthropic's cache_control hint.

    Returns a new message list — never mutates the caller's. If no message
    qualifies (too short, no SystemMessage, or already a list-of-blocks),
    returns the input unchanged.
    """
    if not _PROMPT_CACHE_ENABLED or not messages:
        return messages
    out: list[BaseMessage] = []
    marked = False
    for m in messages:
        if (
            not marked
            and isinstance(m, SystemMessage)
            and isinstance(m.content, str)
            and len(m.content) >= _PROMPT_CACHE_MIN_CHARS
        ):
            out.append(
                SystemMessage(
                    content=[
                        {
                            "type": "text",
                            "text": m.content,
                            "cache_control": {"type": "ephemeral"},
                        }
                    ]
                )
            )
            marked = True
        else:
            out.append(m)
    return out


class _CachingChatAnthropic(ChatAnthropic):
    """ChatAnthropic subclass that auto-marks the system prompt as cacheable.

    Overrides `_generate` / `_agenerate` — the lowest-level sync/async hooks
    that all other paths (`invoke`, `stream`, `batch`, `with_structured_output`)
    eventually funnel into. Transparent to callers.
    """

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):  # type: ignore[override]
        return super()._generate(
            _mark_system_cacheable(messages), stop=stop, run_manager=run_manager, **kwargs
        )

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):  # type: ignore[override]
        return await super()._agenerate(
            _mark_system_cacheable(messages), stop=stop, run_manager=run_manager, **kwargs
        )


# =============================================================================
# Google Gemini — schema flattening + reasoning-content extraction
# =============================================================================
# Problem 1: Google's function-declarations API doesn't support JSON-Schema
# `$ref` / `$defs` (schema references). LangChain's langchain-google-genai
# silently STRIPS these from Pydantic schemas → Gemini receives an incomplete
# schema with dangling references → emits malformed output → Pydantic rejects.
#
# Problem 2: Gemini 3.1 Pro returns content as a list of blocks with signature
# wrappers (`[{"type":"text","text":"...","extras":{...}}]`), not a plain
# string — same pattern as Claude. Our agent_v2 extractor needs the raw text.
#
# Fix: wrap ChatGoogleGenerativeAI with a benchmark-safe subclass that
#   (a) inlines all $defs before structured_output / bind_tools goes to Google
#   (b) handles the content-list format transparently
# OpenAI + Anthropic providers are completely untouched.

import copy as _copy  # noqa: PLC0415, E402


def _inline_defs(schema: dict) -> dict:
    """Resolve all #/$defs/* references by inlining the referenced definitions.

    Returns a copy with `$defs` removed and all `$ref` sites replaced with
    their actual definition. Does NOT mutate the input. Also drops the
    `additionalProperties: false` key that Google's adapter likewise strips.
    """
    if not isinstance(schema, dict):
        return schema
    schema = _copy.deepcopy(schema)
    defs = schema.pop("$defs", {}) or schema.pop("definitions", {}) or {}

    def _resolve(obj):
        if isinstance(obj, dict):
            # Drop additionalProperties — Google doesn't support it
            obj = {k: v for k, v in obj.items() if k != "additionalProperties"}
            if "$ref" in obj and isinstance(obj["$ref"], str):
                ref = obj["$ref"]
                if ref.startswith("#/$defs/"):
                    name = ref[len("#/$defs/") :]
                elif ref.startswith("#/definitions/"):
                    name = ref[len("#/definitions/") :]
                else:
                    name = None
                if name and name in defs:
                    inlined = _resolve(defs[name])
                    # Preserve any sibling keys (title, description) on the $ref dict
                    extras = {k: v for k, v in obj.items() if k != "$ref"}
                    if isinstance(inlined, dict):
                        merged = {**inlined, **extras}
                        return merged
                    return inlined
            return {k: _resolve(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_resolve(v) for v in obj]
        return obj

    return _resolve(schema)


_GEMINI_REASONING_HEADROOM = 4000
"""Gemini 3.x models (flash + pro) consume output tokens on built-in reasoning
BEFORE emitting any visible text. prompt_db usually sets max_tokens=1000
which gets fully burned on reasoning → text block comes back empty →
structured_output returns None. We bump max_output_tokens to this floor
for Gemini only — production prod agents don't use Google provider so this
has zero prod impact."""


class _SchemaFlatteningChatGoogle(ChatGoogleGenerativeAI):
    """ChatGoogleGenerativeAI subclass that pre-flattens Pydantic schemas.

    Google's function-declarations API chokes on $defs. This wrapper inlines
    them BEFORE handing the schema to LangChain's Google adapter.

    Also auto-bumps max_output_tokens to leave reasoning headroom (Gemini 3.x
    burns a lot of hidden reasoning tokens before writing text).

    Overrides:
      - `with_structured_output`: if schema is a Pydantic class, convert to
        a flattened JSON-schema dict first; LangChain accepts both forms.
      - `bind_tools`: iterates tools and flattens each tool's args_schema.

    Transparent for already-flat schemas (OpenAI/Anthropic callers never
    reach this class anyway).
    """

    def __init__(self, *args, **kwargs):
        # Ensure every Gemini call has enough tokens for reasoning + output
        current = kwargs.get("max_output_tokens") or 0
        if current < _GEMINI_REASONING_HEADROOM:
            kwargs["max_output_tokens"] = _GEMINI_REASONING_HEADROOM
        super().__init__(*args, **kwargs)

    # ─── 429 retry-with-backoff ──────────────────────────────────────────
    # gemini-3.1-pro-preview has a tight per-minute RPM tier; SA-3 agentic
    # bursts (5-10 LLM calls per fixture back-to-back) occasionally trip it
    # with `RESOURCE_EXHAUSTED` even on paid tiers. Transparent retry here
    # with linear backoff (60s / 90s / 120s) covers the RPM window reset
    # without the caller noticing. Only this Google subclass; OpenAI's and
    # Anthropic's paths are untouched.
    _GOOGLE_429_MAX_RETRIES = 3
    _GOOGLE_429_BACKOFF_SECONDS = (60.0, 90.0, 120.0)

    def _is_rate_limit_error(self, exc: Exception) -> bool:
        msg = str(exc)
        return "RESOURCE_EXHAUSTED" in msg or "429" in msg

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):  # type: ignore[override]
        import time as _time  # noqa: PLC0415

        for attempt in range(self._GOOGLE_429_MAX_RETRIES + 1):
            try:
                return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)
            except Exception as e:  # noqa: BLE001
                if attempt < self._GOOGLE_429_MAX_RETRIES and self._is_rate_limit_error(e):
                    _time.sleep(self._GOOGLE_429_BACKOFF_SECONDS[attempt])
                    continue
                raise

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):  # type: ignore[override]
        import asyncio as _asyncio  # noqa: PLC0415

        for attempt in range(self._GOOGLE_429_MAX_RETRIES + 1):
            try:
                return await super()._agenerate(
                    messages, stop=stop, run_manager=run_manager, **kwargs
                )
            except Exception as e:  # noqa: BLE001
                if attempt < self._GOOGLE_429_MAX_RETRIES and self._is_rate_limit_error(e):
                    await _asyncio.sleep(self._GOOGLE_429_BACKOFF_SECONDS[attempt])
                    continue
                raise

    def with_structured_output(self, schema, **kwargs):  # type: ignore[override]
        # If schema is a Pydantic class, flatten its JSON representation
        # (Google doesn't support $defs/$ref). Then wrap the inner Runnable
        # so dict output gets re-validated back into the original Pydantic
        # instance — callers expecting `.model_dump()` keep working.
        if hasattr(schema, "model_json_schema"):
            try:
                from langchain_core.runnables import RunnableLambda  # noqa: PLC0415

                orig_cls = schema
                flat_dict = _inline_defs(orig_cls.model_json_schema())
                flat_dict.setdefault("title", orig_cls.__name__)
                inner = super().with_structured_output(flat_dict, **kwargs)

                def _parse_stringified_json(value):
                    """Gemini sometimes serializes nested objects as JSON strings
                    (e.g. asset_identity='{"file": "..."}' instead of
                    {"file": "..."}). Recursively try to parse string values
                    that look like JSON into actual dicts/lists. Leaves
                    non-JSON strings untouched.
                    """
                    import json as _json  # noqa: PLC0415

                    if isinstance(value, str):
                        s = value.strip()
                        if (s.startswith("{") and s.endswith("}")) or (
                            s.startswith("[") and s.endswith("]")
                        ):
                            try:
                                return _parse_stringified_json(_json.loads(s))
                            except Exception:  # noqa: BLE001
                                return value
                        return value
                    if isinstance(value, dict):
                        return {k: _parse_stringified_json(v) for k, v in value.items()}
                    if isinstance(value, list):
                        return [_parse_stringified_json(v) for v in value]
                    return value

                def _coerce_to_pydantic(result):
                    if isinstance(result, dict):
                        try:
                            return orig_cls.model_validate(result)
                        except Exception:  # noqa: BLE001
                            # Try again after auto-parsing stringified JSON
                            # for nested object/list fields (Gemini habit).
                            try:
                                repaired = _parse_stringified_json(result)
                                return orig_cls.model_validate(repaired)
                            except Exception:  # noqa: BLE001
                                # Validation failed — return None so callers
                                # consistently see "schema_valid=False" instead
                                # of a surprise dict. Matches OpenAI/Anthropic
                                # behavior when structured_output fails.
                                return None
                    return result

                return inner | RunnableLambda(_coerce_to_pydantic)
            except Exception:  # noqa: BLE001, S110
                pass  # Fall back to original behavior on any flatten error
        return super().with_structured_output(schema, **kwargs)

    def bind_tools(self, tools, **kwargs):  # type: ignore[override]
        flattened_tools = []
        for t in tools:
            # LangChain tools have an args_schema (Pydantic class) attribute
            if hasattr(t, "args_schema") and t.args_schema is not None:
                try:
                    orig_cls = t.args_schema
                    if hasattr(orig_cls, "model_json_schema"):
                        # Attach a flattened cached schema so LangChain's
                        # internal schema fetcher uses the inlined version
                        flat = _inline_defs(orig_cls.model_json_schema())
                        flat.setdefault("title", orig_cls.__name__)
                        t = _copy.copy(t)  # don't mutate the original
                        # Many LangChain tool classes let us override the json schema
                        # by setting args_schema to a dict (StructuredTool pattern)
                        try:
                            t.args_schema = flat  # type: ignore[assignment]
                        except Exception:  # noqa: BLE001, S110
                            pass
                except Exception:  # noqa: BLE001, S110
                    pass
            flattened_tools.append(t)
        return super().bind_tools(flattened_tools, **kwargs)


# =============================================================================
# In-memory token accumulator
# =============================================================================
# Keyed by run_id → agent → running totals. Populated by _TokenUsageCallback
# on every LLM call regardless of the trace_token_usage flag, so the final
# TOKEN_SUMMARY event always has accurate numbers even when per-call DB events
# are suppressed.

_token_accumulator: dict[str, dict[str, dict[str, int]]] = defaultdict(
    lambda: defaultdict(lambda: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
)
_token_accumulator_lock = threading.Lock()


def accumulate_tokens(run_id: str, agent: str, usage: dict[str, int]) -> None:
    with _token_accumulator_lock:
        bucket = _token_accumulator[run_id][agent]
        bucket["prompt_tokens"] += usage["prompt_tokens"]
        bucket["completion_tokens"] += usage["completion_tokens"]
        bucket["total_tokens"] += usage["total_tokens"]


def get_accumulated_tokens(run_id: str, agent: str) -> dict[str, int]:
    with _token_accumulator_lock:
        return dict(
            _token_accumulator[run_id].get(
                agent, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
            )
        )


def clear_accumulated_tokens(run_id: str) -> None:
    """Free memory after the run ends (success, failure, or cancellation)."""
    with _token_accumulator_lock:
        _token_accumulator.pop(run_id, None)


class _TokenUsageCallback(BaseCallbackHandler):
    """Emits a TOKEN_USAGE trace event after every LLM call.

    LangChain calls `on_llm_end(response, **kwargs)` when an LLM finishes.
    We pull token counts out of `response.llm_output["token_usage"]`
    (OpenAI format) and forward them via `emit_trace()` so the frontend
    sees identical events to the previous SDK-proxy implementation.
    """

    def __init__(
        self,
        run_id: str,
        agent: str,
        model: str,
        emit_fn: Any = None,
    ) -> None:
        self._run_id = run_id
        self._agent = agent
        self._model = model
        # Dependency-injected emit function; defaults to public-schema emit_trace.
        # Non-default callers (demo pipeline, tests) pass their own to route the
        # trace event to a different sink without touching this class.
        self._emit_fn = emit_fn

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:  # noqa: ARG002
        usage = self._extract_usage(response)
        if usage is None:
            return

        # Always accumulate in memory so TOKEN_SUMMARY is accurate even when
        # per-call DB events are suppressed by trace_token_usage=false.
        accumulate_tokens(self._run_id, self._agent, usage)

        if not settings.trace_token_usage:
            return

        emit = self._emit_fn or emit_trace
        emit(
            self._run_id,
            self._agent,
            "MESSAGE",
            (
                f"LLM call — prompt: {usage['prompt_tokens']} tokens, "
                f"completion: {usage['completion_tokens']} tokens, "
                f"total: {usage['total_tokens']} tokens"
            ),
            payload={
                "event_subtype": "TOKEN_USAGE",
                "model": self._model,
                "prompt_tokens": usage["prompt_tokens"],
                "completion_tokens": usage["completion_tokens"],
                "total_tokens": usage["total_tokens"],
            },
        )

    @staticmethod
    def _extract_usage(response: LLMResult) -> dict[str, int] | None:
        """Pull token counts from LLMResult.

        LangChain places provider-specific data in `response.llm_output`.
        For ChatOpenAI this is `{"token_usage": {...}, "model_name": ...}`.
        On structured-output calls the same dict is populated.
        """
        llm_output = response.llm_output or {}
        usage = llm_output.get("token_usage") or {}
        if not usage:
            # Fall back to per-generation usage_metadata (newer LangChain versions).
            for gen_list in response.generations:
                for gen in gen_list:
                    msg = getattr(gen, "message", None)
                    meta = getattr(msg, "usage_metadata", None) if msg else None
                    if meta:
                        return {
                            "prompt_tokens": meta.get("input_tokens", 0),
                            "completion_tokens": meta.get("output_tokens", 0),
                            "total_tokens": meta.get("total_tokens", 0),
                        }
            return None
        return {
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
        }


_RETRYABLE_HTTP_STATUS_CODES = {429, 500, 502, 503, 504}
_FATAL_LLM_ERROR_PHRASES = (
    "invalid api key",
    "unauthorized",
    "permission",
    "forbidden",
    "authentication failed",
    "not found",
    "model not found",
    "invalid model",
    "unsupported model",
    "unknown provider",
    "invalid request",
)


def _is_fatal_llm_error(exc: Exception) -> bool:
    """Classify obvious non-retryable LLM errors so we fail fast."""
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code if exc.response is not None else None
        return status is not None and status not in _RETRYABLE_HTTP_STATUS_CODES

    msg = str(exc).lower()
    return any(phrase in msg for phrase in _FATAL_LLM_ERROR_PHRASES)


def invoke_structured_with_retry(
    *,
    run_id: str,
    agent: str,
    schema: type,
    messages: list,
    attempts: list[tuple[float, str, int]],
    method: str = "function_calling",
    emit_fn: Any = None,
) -> Any:
    """Invoke ChatOpenAI.with_structured_output with tiered retry.

    Each entry in `attempts` is `(temperature, model, max_tokens)`. The helper
    tries them in order and returns the first non-None structured result. A
    None return from `.invoke()` (model failed to call the tool — usually a
    max_tokens overflow) is converted into a retryable exception. The final
    exception propagates if every attempt fails.

    Per-attempt `max_tokens` lets callers escalate the completion budget on
    each retry — useful for inputs where the model occasionally needs more
    headroom to finish the structured-output tool call.

    `method="function_calling"` is the default because it tolerates
    `dict[str, Any]` fields in the schema; pass `method="json_schema"`
    to opt into strict mode for schemas without free-form objects.
    """
    emit = emit_fn or emit_trace
    last_err: Exception | None = None
    for idx, (temperature, model, max_tokens) in enumerate(attempts, start=1):
        try:
            llm = get_chat_llm(
                run_id=run_id,
                agent=agent,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                emit_fn=emit_fn,
            )
            structured_llm = llm.with_structured_output(schema, method=method)
            result = structured_llm.invoke(messages)
            if result is None:
                raise ValueError(
                    "LLM did not invoke the structured-output tool "
                    "(likely hit max_tokens responding in prose)"
                )
            return result
        except Exception as e:  # noqa: BLE001
            emit(
                run_id,
                agent,
                "MESSAGE",
                f"LLM retry {idx}/{len(attempts)} "
                f"({model}, temp={temperature}): "
                f"{type(e).__name__}: {str(e)[:120]}",
            )
            if _is_fatal_llm_error(e):
                raise e
            if idx >= len(attempts):
                break
            time.sleep(0.5 * idx)

    assert last_err is not None  # nosec B101
    raise last_err


def _infer_provider(model: str) -> str:
    """Map a model name to its provider via prefix matching.

    Unknown prefixes default to OpenAI so older configs keep working.
    """
    name = model.lower()
    if name.startswith("claude-"):
        return "anthropic"
    if name.startswith("gemini-"):
        return "google"
    return "openai"


def get_chat_llm(
    run_id: str,
    agent: str,
    model: str,
    temperature: float = 0.1,
    max_tokens: int | None = None,
    emit_fn: Any = None,
) -> BaseChatModel:
    """Return a configured chat model (OpenAI / Anthropic / Google) that
    traces token usage per call.

    Provider is inferred from the model-name prefix (see `_infer_provider`),
    so callers don't need to pass it explicitly — switching a `prompt_db.model`
    row from "gpt-4o" to "claude-opus-4-7" routes through Anthropic.

    All three return types share `with_structured_output()` and `.invoke()`
    via LangChain's `BaseChatModel`, so the downstream retry helper works
    uniformly across providers.

    Args:
        run_id: agent_runs.run_id — passed into the callback for trace correlation.
        agent: "master" | "sub-agent-1" | "sub-agent-2" — labels the trace event.
        model: model name from prompt_db (e.g. "gpt-4o", "claude-opus-4-7", "gemini-2.0-pro").
        temperature: sampling temperature; retry helper escalates per attempt.
        max_tokens: completion cap; loaded from prompt_db.parameters when present.
    """
    callback = _TokenUsageCallback(run_id=run_id, agent=agent, model=model, emit_fn=emit_fn)
    provider = _infer_provider(model)

    if provider == "anthropic":
        if not settings.anthropic_api_key:
            raise RuntimeError(f"Model '{model}' requires ANTHROPIC_API_KEY in the environment.")
        # Anthropic requires max_tokens; default to a sane ceiling if unset.
        # _CachingChatAnthropic is a transparent subclass that adds Anthropic's
        # cache_control hint to large system prompts — same inputs, same
        # outputs, lower input-token billing on reuse within ~5 min.
        return _CachingChatAnthropic(
            api_key=settings.anthropic_api_key,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens or 4096,
            # langchain-anthropic uses `default_request_timeout`, not `timeout`.
            # The 60s SDK default was dropping Sonnet's longer agentic/reasoning
            # responses on SA-3. 180s is well under the 10-min API hard ceiling.
            default_request_timeout=180.0,
            max_retries=10,
            callbacks=[callback],
        )

    if provider == "google":
        if not settings.google_api_key:
            raise RuntimeError(f"Model '{model}' requires GOOGLE_API_KEY in the environment.")
        # _SchemaFlatteningChatGoogle inlines $defs before passing schemas to
        # Google's function-declarations API — same inputs semantically,
        # just serialized without refs that Google can't resolve. Transparent
        # for callers; OpenAI + Anthropic paths above are unchanged.
        return _SchemaFlatteningChatGoogle(
            google_api_key=settings.google_api_key,
            model=model,
            temperature=temperature,
            max_output_tokens=max_tokens,
            timeout=120.0,
            max_retries=10,
            callbacks=[callback],
        )

    return ChatOpenAI(
        api_key=settings.openai_api_key,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=120.0,
        max_retries=10,
        callbacks=[callback],
    )
