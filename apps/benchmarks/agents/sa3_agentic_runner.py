"""SA-3 AGENTIC runner — tool-calling loop with per-tool metric capture.

This wraps the production `run_agentic_planner` from agent_v2.py (not the
simpler hybrid single-call path used by sa3_runner.py). The agentic path
goes through a multi-turn tool loop:

   LLM asks for web_search → runs it → feeds result back
   LLM asks for url_fetch  → runs it → feeds result back
   LLM asks for file_fetch → runs it → feeds result back
   ... until LLM proposes a RemediationPackage within budget

The additional metrics we capture (Nikhil's agent-specific ask):
  tool_call_count          — total tool invocations
  tools_used               — list of distinct tool names
  web_search_calls         — how many web searches
  url_fetch_calls          — how many URL fetches
  file_fetch_calls         — how many file fetches
  tool_budget_remaining    — unused budget
  tool_cost_usd_accrued    — $ accrued on tool calls (web_search ≈ $0.015 ea)

Budget capture mechanism: monkey-patch AgentBudget to also register the
instance in a module-level dict keyed by run_id. Benchmarks run serially,
so there's no race. After `run_agentic_planner` returns, we read the
budget back.
"""

from __future__ import annotations

import time
from typing import Any

from apps.api.app.agents.remediation import agent_v2, prompt_router, tools
from apps.api.app.agents.remediation.tools.budget import AgentBudget
from apps.api.app.config import settings
from apps.api.app.db import supabase_admin

# ─── Budget capture via monkey-patch ─────────────────────────────────────
_BUDGETS_BY_RUN: dict[str, AgentBudget] = {}
_original_record_call = AgentBudget.record_call
_patched = False


# ─── Model-override via monkey-patch of load_sa3_prompt ──────────────────
# run_agentic_planner reads the model name from `prompt_row["model"]` which
# comes from `prompt_router.load_sa3_prompt`. To actually swap the model
# per benchmark call, we wrap that function so the returned prompt_row's
# `model` field is overridden with whatever `--model` was passed.
#
# Also overrides the `fallback_model` in `parameters` so the retry chain
# doesn't silently fall back to a different model mid-run.
_original_load_sa3_prompt = prompt_router.load_sa3_prompt
_model_override: list[str | None] = [None]
_prompt_patched = False


def _install_prompt_patch() -> None:
    """Wrap load_sa3_prompt so it swaps the model in the returned row."""
    global _prompt_patched
    if _prompt_patched:
        return

    def _patched_load_sa3_prompt(*args, **kwargs):
        prompt_row = _original_load_sa3_prompt(*args, **kwargs)
        override = _model_override[0]
        if override and isinstance(prompt_row, dict):
            prompt_row = dict(prompt_row)
            prompt_row["model"] = override
            params = dict(prompt_row.get("parameters") or {})
            params["fallback_model"] = override

            # BENCHMARK-ONLY max_tokens bump. Production uses 6000, which is
            # enough for GPT-4o's concise RemediationPackage outputs. Claude
            # Opus and Sonnet produce more verbose JSON and get truncated at
            # 6000, causing EOF-while-parsing errors downstream and dropping
            # schema_valid to False even when the plan is otherwise good.
            # 16000 is well under all three Claude models' output ceilings
            # (32k for Opus) and doesn't change OpenAI behavior — gpt-4o
            # still stops at ~2000-4000 tokens on its own. Apples-to-apples.
            params["max_tokens"] = max(int(params.get("max_tokens", 6000)), 16000)
            prompt_row["parameters"] = params

            # BENCHMARK-ONLY (Claude): Sonnet runs long on prose fields and
            # trips Pydantic max_length validators (finding/root_cause/impact
            # ≤400, execution_strategy / rollback.explanation ≤600). GPT-4o
            # and Gemini naturally stay under these limits so they don't need
            # the hint. Appending the limits to the system prompt costs ~70
            # tokens and prevents the "write-then-fail-validation" cycle.
            # ONLY applied when the override model is Claude.
            if "claude" in override.lower() and prompt_row.get("prompt_text"):
                length_hint = (
                    "\n\n## HARD LENGTH LIMITS (schema will reject if exceeded)\n"
                    "- `finding`: max 400 chars — one tight paragraph.\n"
                    "- `root_cause`: max 400 chars — one tight paragraph.\n"
                    "- `impact`: max 400 chars — one tight paragraph.\n"
                    "- `pathways[].execution_strategy`: max 600 chars.\n"
                    "- `pathways[].rollback_plan.objective`: max 400 chars.\n"
                    "- `pathways[].rollback_plan.explanation`: max 600 chars.\n"
                    "- `pathways[].rollback_plan.recommended_recovery`: max 400 chars.\n"
                    "If a field would exceed its limit, TRUNCATE to key facts; "
                    "do not emit an over-length string — the schema parser will "
                    "reject the entire package and your work will be discarded."
                )
                prompt_row["prompt_text"] = prompt_row["prompt_text"] + length_hint
        return prompt_row

    prompt_router.load_sa3_prompt = _patched_load_sa3_prompt
    # agent_v2 imported the function by name at module-load time → also
    # patch the reference in that module so the already-loaded run_agentic
    # path sees the override.
    try:
        agent_v2.load_sa3_prompt = _patched_load_sa3_prompt  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001, S110
        pass
    _prompt_patched = True


def _install_budget_patch() -> None:
    """Attach a side-effect to AgentBudget.record_call so we can read the
    budget state back after the agentic call completes. Idempotent."""
    global _patched
    if _patched:
        return

    _current_run_id: list[str] = ["unknown"]

    def _patched_record_call(self, tool: str) -> None:
        _original_record_call(self, tool)
        _BUDGETS_BY_RUN[_current_run_id[0]] = self

    # Expose a setter so the runner can tag the run_id before each dispatch.
    def _set_run_id(run_id: str) -> None:
        _current_run_id[0] = run_id

    AgentBudget.record_call = _patched_record_call  # type: ignore[method-assign]
    _install_budget_patch._set_run_id = _set_run_id  # type: ignore[attr-defined]
    _patched = True


def run_sa3_agentic_once(
    *,
    run_id: str,
    model: str,
    raw_finding: dict,
    scanner: str,
    fixture_input: dict | None = None,
    **_ignored: Any,
) -> dict[str, Any]:
    """Call SA-3 agentic planner against a derived SA-3 fixture.

    The `model` argument IS honored: we monkey-patch load_sa3_prompt so the
    prompt_row returned to run_agentic_planner has its `model` field
    overridden. Pass claude-sonnet-4-6 or gemini-2.0-pro and the agentic
    tool loop will actually use that model.
    """
    if not fixture_input or "issue" not in fixture_input:
        raise ValueError(
            "SA-3 agentic fixtures must provide an 'input' block with 'issue', 'asset', 'family'"
        )

    issue = fixture_input["issue"]
    asset = fixture_input.get("asset") or {}
    family = fixture_input.get("family") or "os_vulnerability"

    sb = supabase_admin()
    _install_budget_patch()
    _install_budget_patch._set_run_id(run_id)  # type: ignore[attr-defined]
    _install_prompt_patch()
    _model_override[0] = model  # swap the model seen by run_agentic_planner

    original_trace = settings.trace_token_usage
    settings.trace_token_usage = False

    # Pre-insert a parent agent_runs row (same pattern as master/sa1/sa2/sa4
    # runners) so trace-event FK constraints resolve for provider-specific
    # token-usage callbacks that bypass the trace flag.
    try:
        sb.table("agent_runs").insert(
            {
                "run_id": run_id,
                "event_id": f"bench-sa3-{run_id[:8]}",
                "triggered_by": "benchmark",
                "action": "FULL",
                "targets": {"benchmark": True, "model_tag": model},
                "status": "completed",
            }
        ).execute()
    except Exception:  # noqa: BLE001, S110
        pass

    started = time.perf_counter()
    result: Any = None
    plan: Any = None  # the LLMRemediationOutput part of the tuple
    error: str | None = None
    failure_mode: str | None = None

    # BENCHMARK-ONLY: raise the SA-3 tool-call cap from the production default
    # (16) so Claude Sonnet has headroom to converge on CVE-shaped findings
    # where it tends to over-search. Scoped to this function only; restored in
    # finally. OpenAI and Gemini converge in <10 calls so this is a no-op for
    # them.
    _bench_sa3_max_calls = 25
    original_max_calls = settings.agent_max_tool_calls
    settings.agent_max_tool_calls = _bench_sa3_max_calls

    # BENCHMARK-ONLY: capture ERROR-level emits from agent_v2 so synthesis-
    # parse-failure reasons are visible in the scorecard. Prod path still uses
    # the real sb-writer emit_fn.
    captured_events: list[str] = []

    def _capture_emit(_rid: str, _agent: str, level: str, message: str, *_a, **_kw):
        if level in ("ERROR", "WARN"):
            captured_events.append(f"{level}: {message[:220]}")

    try:
        # run_agentic_planner returns tuple[LLMRemediationOutput, VerificationReport] | None
        result = agent_v2.run_agentic_planner(
            issue=issue,
            asset=asset,
            family=family,
            run_id=run_id,
            sb_pub=sb,
            emit_fn=_capture_emit,
        )
        if result is not None:
            plan = result[0] if isinstance(result, tuple) else result
    except Exception as e:  # noqa: BLE001
        error = f"{type(e).__name__}: {str(e)[:300]}"
        failure_mode = "agentic_error"
    finally:
        settings.trace_token_usage = original_trace
        settings.agent_max_tool_calls = original_max_calls
        _model_override[0] = None  # don't leak into the next call

    # If plan is None but no exception, surface the captured ERROR/WARN
    # messages so we can see WHY (budget cap vs synth-parse-fail vs synth-exc).
    if plan is None and not error and captured_events:
        error = " | ".join(captured_events[-3:])  # keep last 3, most relevant
        failure_mode = "returned_none"

    latency_ms = int((time.perf_counter() - started) * 1000)

    # Read budget back from the patched registry
    budget = _BUDGETS_BY_RUN.pop(run_id, None)
    if budget:
        tool_call_count = budget.call_count
        tool_cost_usd_accrued = round(budget.cost_accrued_usd, 4)
        by_tool = dict(budget.by_tool)
        tools_used = ",".join(sorted(by_tool.keys()))
        web_calls = by_tool.get("web_search", 0)
        url_calls = by_tool.get("url_fetch", 0)
        file_calls = by_tool.get("file_fetch", 0)
        budget_remaining = max(0, budget.max_calls - budget.call_count)
    else:
        tool_call_count = 0
        tool_cost_usd_accrued = 0.0
        tools_used = ""
        web_calls = url_calls = file_calls = 0
        budget_remaining = 0

    # Pathway shape (same extras as hybrid SA-3 runner)
    pathways_count = 0
    recommended_steps = 0
    if plan is not None and hasattr(plan, "pathways"):
        pathways_count = len(plan.pathways or [])
        if pathways_count:
            recommended_steps = len(plan.pathways[0].remediation_steps or [])

    return {
        "model": model,
        "scanner": scanner,
        "latency_ms": latency_ms,
        "input_chars": len(str(fixture_input)),
        # No per-call token sum here — agentic path makes many LLM calls, token
        # totals are in the budget. Report tool cost separately as cost_usd.
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "retries": 0,
        "schema_valid": plan is not None,
        "failure_mode": failure_mode,
        "error": error,
        "output": plan.model_dump() if plan and hasattr(plan, "model_dump") else None,
        # Hybrid-SA-3 extras
        "pathways_count": pathways_count,
        "recommended_steps": recommended_steps,
        # Agentic-specific extras
        "tool_call_count": tool_call_count,
        "tools_used": tools_used,
        "web_search_calls": web_calls,
        "url_fetch_calls": url_calls,
        "file_fetch_calls": file_calls,
        "tool_budget_remaining": budget_remaining,
        "tool_cost_usd_accrued": tool_cost_usd_accrued,
    }


# Silence unused-import linter — the tools module is loaded so the patch
# can take effect even if agent_v2 is imported first.
_ = tools
