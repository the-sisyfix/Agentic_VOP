"""SA-4 (fixer / pre-flight rewriter) benchmark wrapper.

Day-1 scope: benchmarks the SA-4 pre-flight rewrite LLM call — the one that
reads env2 snapshot + proposed remediation steps and produces rewrites /
confirmations. Mirrors `preflight.run_preflight_rewrite` single LLM call.

The FULL sandbox-oracle version (dispatch SA-4 against env2, capture
rescan-verified success) is intentionally not wired here — it's slow and
needs env2 access. Lands later as `sa4_sandbox_runner.py` with the
end-to-end rescan metrics.

Fixture shape (one JSON per file in fixtures/raw/):
    {
        "fixture_id": "...",
        "scanner": "...",
        "agent": "sa4",
        "input": {
            "pathway": {
                "remediation_steps": [{"step": "..."}, ...]
            },
            "snapshot_text": "ENV2 SNAPSHOT:\\n- docker: online\\n- ...",
            "issue": {
                "id": 123,
                "source_vuln_id": "CVE-2022-0778",
                "title": "...",
                "severity": "high",
                "asset_identity": {"resource": "vuln-lab-image:latest"}
            }
        }
    }
"""

from __future__ import annotations

import time
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from apps.api.app.agents.fixer.preflight import PreflightRewritePlan, _SYSTEM_PROMPT
from apps.api.app.agents.llm import (
    clear_accumulated_tokens,
    get_accumulated_tokens,
    get_chat_llm,
)
from apps.api.app.config import settings
from apps.api.app.db import supabase_admin


def run_sa4_once(
    *,
    run_id: str,
    model: str,
    raw_finding: dict,  # ignored
    scanner: str,
    fixture_input: dict | None = None,
    **_ignored: Any,
) -> dict[str, Any]:
    """Call SA-4 pre-flight rewriter with the given model."""
    if not fixture_input:
        raise ValueError(
            "SA-4 fixtures must provide an 'input' block with 'pathway', 'snapshot_text', 'issue'"
        )

    pathway = fixture_input.get("pathway") or {}
    snapshot_text = fixture_input.get("snapshot_text") or ""
    issue = fixture_input.get("issue") or {}

    steps = pathway.get("remediation_steps") or []
    steps_prose = "\n\n".join(
        f"[step_index={i}]\n{(s.get('step') or '')[:1500]}" for i, s in enumerate(steps)
    )

    finding_pairs = {
        "id": issue.get("id"),
        "source_vuln_id": issue.get("source_vuln_id"),
        "title": issue.get("title"),
        "severity": issue.get("severity"),
        "resource": (issue.get("asset_identity") or {}).get("resource"),
    }
    finding_summary = "\n".join(
        f"  - {k}: {str(v)[:200]}" for k, v in finding_pairs.items() if v
    )

    user_text = (
        f"FINDING:\n{finding_summary}\n\n"
        f"{snapshot_text}\n\n"
        f"REMEDIATION_STEPS (indexed 0..{max(len(steps) - 1, 0)}):\n\n{steps_prose}\n"
    )

    original_trace_setting = settings.trace_token_usage
    settings.trace_token_usage = False
    clear_accumulated_tokens(run_id)

    # Pre-insert a parent agent_runs row so if the token-callback FALLS BACK
    # to writing a trace event (because trace_token_usage wasn't disabled
    # in time), the FK to agent_runs.run_id resolves and no APIError
    # cascades back as a benchmark failure.
    try:
        supabase_admin().table("agent_runs").insert(
            {
                "run_id": run_id,
                "event_id": f"bench-sa4-{run_id[:8]}",
                "triggered_by": "benchmark",
                "action": "FULL",
                "targets": {"benchmark": True, "model_tag": model},
                "status": "completed",
            }
        ).execute()
    except Exception:  # noqa: BLE001, S110
        pass  # best-effort — if the insert fails, benchmark still runs

    started = time.perf_counter()
    output: Any = None
    error: str | None = None
    failure_mode: str | None = None

    try:
        # Bypass invoke_structured_with_retry (has a latent bug where
        # `last_err` is never assigned, masking the real error). Call the
        # LLM directly so we see any underlying OpenAI exception verbatim.
        llm = get_chat_llm(
            run_id=run_id,
            agent="sub-agent-4",
            model=model,
            temperature=0.1,
            max_tokens=3000,
            emit_fn=None,
        )
        structured_llm = llm.with_structured_output(
            PreflightRewritePlan, method="function_calling"
        )
        output = structured_llm.invoke(
            [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=user_text)]
        )
    except Exception as e:  # noqa: BLE001
        error = f"{type(e).__name__}: {str(e)[:300]}"
        failure_mode = _categorize_failure(e)
    finally:
        settings.trace_token_usage = original_trace_setting

    latency_ms = int((time.perf_counter() - started) * 1000)
    tokens = get_accumulated_tokens(run_id, "sub-agent-4")

    # SA-4 extras: how many rewrites proposed, how many high-confidence
    rewrites_total = 0
    rewrites_high_conf = 0
    if output is not None:
        rewrites_total = len(output.rewrites or [])
        rewrites_high_conf = sum(
            1 for r in (output.rewrites or []) if r.confidence == "high"
        )

    return {
        "model": model,
        "scanner": scanner,
        "latency_ms": latency_ms,
        "input_chars": len(_SYSTEM_PROMPT) + len(user_text),
        "prompt_tokens": tokens.get("prompt_tokens", 0),
        "completion_tokens": tokens.get("completion_tokens", 0),
        "retries": 0,
        "schema_valid": output is not None,
        "failure_mode": failure_mode,
        "error": error,
        "output": output.model_dump() if output else None,
        "rewrites_total": rewrites_total,
        "rewrites_high_conf": rewrites_high_conf,
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
