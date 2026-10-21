"""SA-2 (enrichment) benchmark wrapper.

Takes one pre-populated enrichment-input fixture + a model name → invokes
the LLM through the real production code path → returns the structured
output + metrics.

Shape of a SA-2 fixture (one JSON per file in fixtures/raw/):
    {
        "fixture_id": "...",
        "scanner": "...",       # for CSV grouping only
        "agent": "sa2",         # routes the runner CLI to this wrapper
        "input": {
            "issue":      {...},   # a normalized issue (SA-1 output shape)
            "epss":       {...},   # EPSS fields or {}
            "nvd":        {...},   # NVD fields or {}
            "in_kev":     false,
            "mitre":      {...},   # CWE/CAPEC/ATT&CK chain or {}
            "asset":      {...},   # resolved asset or {}
            "scoring":    {...}    # formula output (derived_risk/priority/etc.)
        }
    }

Pre-populating the enrichment inputs (EPSS, NVD, MITRE, scoring) lets us
isolate what we're measuring — the LLM's prose/judgment given fixed inputs.
Otherwise variance in EPSS lookups would pollute the signal.
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
from apps.api.app.models import LLMEnrichmentDecision


def run_sa2_once(
    *,
    run_id: str,
    model: str,
    raw_finding: dict,  # ignored for sa2 — kept for runner-signature uniformity
    scanner: str,
    fixture_input: dict | None = None,
) -> dict[str, Any]:
    """Call SA-2 with the given model against a pre-populated enrichment input.

    Returns Tier-1 metrics + the structured enrichment decision (or None).
    """
    if not fixture_input:
        raise ValueError(
            "SA-2 fixtures must provide an 'input' block (issue + epss + nvd + mitre + asset + scoring)"
        )

    sb = supabase_admin()

    # Load the SAME SA-2 prompt production uses.
    prompt_resp = (
        sb.table("prompt_db")
        .select("prompt_text, model, parameters")
        .eq("agent", "sub-agent-2")
        .eq("is_active", True)
        .limit(1)
        .execute()
    )
    if not prompt_resp.data:
        raise RuntimeError("No active prompt row for sub-agent-2 in prompt_db")
    prompt_row = prompt_resp.data[0]

    params = prompt_row.get("parameters") or {}
    temperature = float(params.get("temperature", 0.2))
    max_tokens = int(params.get("max_tokens", 500))

    # ─── Metrics capture (Tier 1) ──────────────────────────────────────
    original_trace_setting = settings.trace_token_usage
    settings.trace_token_usage = False
    clear_accumulated_tokens(run_id)

    # Pre-insert a parent agent_runs row (same pattern as master/sa1/sa4
    # runners) so trace-event FK constraints resolve for provider-specific
    # token-usage callbacks that bypass the trace flag.
    try:
        sb.table("agent_runs").insert(
            {
                "run_id": run_id,
                "event_id": f"bench-sa2-{run_id[:8]}",
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
    retries = 0

    try:
        # Bypass invoke_structured_with_retry — same latent bug as sa1_runner
        # (last_err never assigned → bare AssertionError). Direct invoke.
        llm = get_chat_llm(
            run_id=run_id,
            agent="sub-agent-2",
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            emit_fn=None,
        )
        structured_llm = llm.with_structured_output(
            LLMEnrichmentDecision, method="function_calling"
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

    tokens = get_accumulated_tokens(run_id, "sub-agent-2")

    return {
        "model": model,
        "scanner": scanner,
        "latency_ms": latency_ms,
        "input_chars": len(prompt_row["prompt_text"]) + len(str(fixture_input)),
        "prompt_tokens": tokens.get("prompt_tokens", 0),
        "completion_tokens": tokens.get("completion_tokens", 0),
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
