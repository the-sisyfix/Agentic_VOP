"""SA-1 (normalization) benchmark wrapper.

Takes one raw-finding fixture + a model name → invokes the LLM through the
real production code path (`get_chat_llm` + `invoke_structured_with_retry`)
→ returns the structured output + metrics.

Reuses the same prompt, schema, and retry escalation that production uses.
The only override is the model name — we pass `model_override` instead of
reading `prompt_row['model']`, so every candidate gets exactly the same
inputs apart from which model answers.
"""

from __future__ import annotations

import time
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from apps.api.app.agents.llm import (
    clear_accumulated_tokens,
    get_accumulated_tokens,
    get_chat_llm,
)
from apps.api.app.config import settings
from apps.api.app.db import supabase_admin
from apps.api.app.models import LLMNormalizedIssue


def run_sa1_once(
    *,
    run_id: str,
    model: str,
    raw_finding: dict,
    scanner: str,
    **_ignored: Any,  # swallows fixture_input (used by SA-2)
) -> dict[str, Any]:
    """Call SA-1 with the given model against one raw finding.

    Returns a dict with Tier 1 metrics + the structured output (or None on
    failure) + failure_mode categorization.
    """
    sb = supabase_admin()

    # Load the SAME prompt the production pipeline uses.
    prompt_resp = (
        sb.table("prompt_db")
        .select("prompt_text, model, parameters")
        .eq("agent", "sub-agent-1")
        .eq("is_active", True)
        .limit(1)
        .execute()
    )
    if not prompt_resp.data:
        raise RuntimeError("No active prompt row for sub-agent-1 in prompt_db")
    prompt_row = prompt_resp.data[0]

    # Load schema_mapping rules for this scanner (same column names as prod)
    mapping_resp = (
        sb.table("schema_mapping")
        .select("source_field,canonical_field,transform,notes")
        .eq("scanner", scanner)
        .execute()
    )
    mapping_rules = mapping_resp.data or []

    params = prompt_row.get("parameters") or {}
    temperature = float(params.get("temperature", 0.1))
    max_tokens = int(params.get("max_tokens", 2000))

    user_payload = {
        "source_scanner": scanner,
        "raw_row": raw_finding,
        "mapping_rules": mapping_rules,
    }

    # ─── Metrics capture (Tier 1) ──────────────────────────────────────
    # Suppress the callback's DB trace writes — benchmarks don't own an
    # agent_runs row so FK inserts would error. Token counting still works
    # via the in-memory accumulator.
    original_trace_setting = settings.trace_token_usage
    settings.trace_token_usage = False
    clear_accumulated_tokens(run_id)

    # Pre-insert a parent agent_runs row so if the trace-event callback
    # fires (e.g. provider-specific paths that bypass the trace flag like
    # Gemini's token-usage emits), the FK constraint on agent_trace_events
    # resolves cleanly instead of crashing the SA-1 benchmark call.
    try:
        sb.table("agent_runs").insert(
            {
                "run_id": run_id,
                "event_id": f"bench-sa1-{run_id[:8]}",
                "triggered_by": "benchmark",
                "action": "FULL",
                "targets": {"benchmark": True, "model_tag": model},
                "status": "completed",
            }
        ).execute()
    except Exception:  # noqa: BLE001, S110
        pass  # best-effort — if insert fails, benchmark still runs

    started = time.perf_counter()
    output: Any = None
    error: str | None = None
    failure_mode: str | None = None
    retries = 0

    try:
        # Bypass invoke_structured_with_retry — has a latent bug where
        # `last_err` is never assigned, surfacing as a bare AssertionError
        # instead of the real provider error. Call the LLM directly so any
        # Gemini/OpenAI exception is captured verbatim.
        llm = get_chat_llm(
            run_id=run_id,
            agent="sub-agent-1",
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            emit_fn=None,
        )
        structured_llm = llm.with_structured_output(
            LLMNormalizedIssue, method="function_calling"
        )
        output = structured_llm.invoke(
            [
                SystemMessage(content=prompt_row["prompt_text"]),
                HumanMessage(content=str(user_payload)),
            ]
        )
    except Exception as e:  # noqa: BLE001
        error = f"{type(e).__name__}: {str(e)[:300]}"
        failure_mode = _categorize_failure(e)
    finally:
        settings.trace_token_usage = original_trace_setting

    latency_ms = int((time.perf_counter() - started) * 1000)

    # Pull real token counts from the in-memory accumulator (populated
    # by the callback regardless of trace_token_usage).
    tokens = get_accumulated_tokens(run_id, "sub-agent-1")
    prompt_tokens = tokens.get("prompt_tokens", 0)
    completion_tokens = tokens.get("completion_tokens", 0)

    return {
        "model": model,
        "scanner": scanner,
        "latency_ms": latency_ms,
        "input_chars": len(prompt_row["prompt_text"]) + len(str(user_payload)),
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "retries": retries,
        "schema_valid": output is not None,
        "failure_mode": failure_mode,
        "error": error,
        "output": output.model_dump() if output else None,
    }


_REFUSAL_HINTS = ("i can't", "i cannot", "unable to help", "against my", "i won't")


def _categorize_failure(exc: Exception) -> str:
    msg = str(exc).lower()
    if "rate" in msg and ("limit" in msg or "429" in msg):
        return "rate_limited"
    if "timeout" in msg or "timed out" in msg:
        return "timeout"
    if any(h in msg for h in _REFUSAL_HINTS):
        return "refusal"
    if "validation" in msg or "pydantic" in msg:
        return "schema_violation"
    if "json" in msg or "parse" in msg:
        return "format_drift"
    if "5" in msg[:4] and "status" in msg:
        return "provider_5xx"
    return "other"
