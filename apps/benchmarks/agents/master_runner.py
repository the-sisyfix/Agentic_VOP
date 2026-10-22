"""Master (planning/orchestration) benchmark wrapper.

Single LLM call that produces a MasterPlan from a trigger + available tools.
Mirrors `master._plan_node` but swaps in the benchmark model and strips the
DB trace emission.

Fixture shape (one JSON per file in fixtures/raw/):
    {
        "fixture_id": "...",
        "scanner": "n/a",      # master is scanner-independent; kept for CSV grouping
        "agent": "master",
        "input": {
            "trigger": {
                "event_id":    "EVT-...",
                "action":      "FULL",
                "persona":     "admin",
                "targets":     { "scanners": [...] }
            },
            "available_tools": ["sub-agent-1", "sub-agent-2", "sub-agent-3", "sub-agent-4"]
        }
    }
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
from apps.api.app.models import MasterPlan


def run_master_once(
    *,
    run_id: str,
    model: str,
    raw_finding: dict,  # ignored
    scanner: str,
    fixture_input: dict | None = None,
    **_ignored: Any,
) -> dict[str, Any]:
    """Call Master with the given model against a trigger + tool list fixture."""
    if not fixture_input or "trigger" not in fixture_input:
        raise ValueError(
            "Master fixtures must provide an 'input' block with 'trigger' and 'available_tools'"
        )

    sb = supabase_admin()
    prompt_resp = (
        sb.table("prompt_db")
        .select("prompt_text, model, parameters")
        .eq("agent", "master")
        .eq("is_active", True)
        .limit(1)
        .execute()
    )
    if not prompt_resp.data:
        raise RuntimeError("No active prompt row for master in prompt_db")
    prompt_row = prompt_resp.data[0]

    params = prompt_row.get("parameters") or {}
    temperature = float(params.get("temperature", 0.1))
    max_tokens = int(params.get("max_tokens", 1000))

    original_trace_setting = settings.trace_token_usage
    settings.trace_token_usage = False
    clear_accumulated_tokens(run_id)

    # Pre-insert a parent agent_runs row so FK writes from the token
    # callback resolve cleanly. Mirrors sa4_runner.
    try:
        sb.table("agent_runs").insert(
            {
                "run_id": run_id,
                "event_id": f"bench-master-{run_id[:8]}",
                "triggered_by": "benchmark",
                "action": "FULL",
                "targets": {"benchmark": True, "model_tag": model},
                "status": "completed",
            }
        ).execute()
    except Exception:  # noqa: BLE001, S110
        pass

    started = time.perf_counter()
    output: Any = None
    error: str | None = None
    failure_mode: str | None = None

    try:
        # Bypass invoke_structured_with_retry — call LLM directly (see
        # sa4_runner for rationale about the latent `last_err` bug).
        llm = get_chat_llm(
            run_id=run_id,
            agent="master",
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            emit_fn=None,
        )
        structured_llm = llm.with_structured_output(
            MasterPlan, method="function_calling"
        )
        output = structured_llm.invoke(
            [
                SystemMessage(content=prompt_row["prompt_text"]),
                HumanMessage(content=str(fixture_input)),
            ]
        )
    except Exception as e:  # noqa: BLE001
        error = f"{type(e).__name__}: {str(e)[:300]}"
        failure_mode = _categorize_failure(e)
    finally:
        settings.trace_token_usage = original_trace_setting

    latency_ms = int((time.perf_counter() - started) * 1000)
    tokens = get_accumulated_tokens(run_id, "master")

    return {
        "model": model,
        "scanner": scanner,
        "latency_ms": latency_ms,
        "input_chars": len(prompt_row["prompt_text"]) + len(str(fixture_input)),
        "prompt_tokens": tokens.get("prompt_tokens", 0),
        "completion_tokens": tokens.get("completion_tokens", 0),
        "retries": 0,
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
