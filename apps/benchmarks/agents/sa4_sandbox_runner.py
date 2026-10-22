"""SA-4 (fixer) SANDBOX-ORACLE benchmark wrapper — end-to-end.

This dispatches SA-4 against the real env2 EC2 for a given existing
`demo.remediation_packages` row, then reads back the resulting fix_run +
package rows to capture sandbox-truth metrics:

  fix_run_succeeded   — fix_runs.status == 'success'
  rescan_verified     — did a scanner rescan return 0 hits? (strongest signal)
  rolled_back         — SA-4 rolled back from .bak?
  steps_executed      — count of remediation steps that ran
  wall_clock_total_ms — end-to-end dispatch time
  terminal_status     — the full fix_run.status string

MODEL-SWAP LIMITATION
---------------------
SA-4 is a lifecycle with multiple LLM calls (pre-flight rewriter, strategy
reasoning, validation generators) across different code paths. The `model`
argument here is RECORDED on the scorecard row for traceability but does
NOT actually swap the LLM used — the dispatch uses whatever models are
currently configured in prompt_db + hardcoded in preflight.py.

Use this runner for:
  - Baseline capture ("how often does SA-4 succeed today?")
  - Variance measurement (same package × N runs — does outcome drift?)
  - Sandbox-truth validation of fix recipes

NOT yet suitable for cross-model comparison on SA-4 — that needs an
orchestrator refactor to accept model_override and thread it through
all LLM call sites (Phase 2).

Fixture shape:
    {
        "fixture_id": "...",
        "scanner": "...",
        "agent": "sa4_sandbox",
        "input": {
            "package_id": 3399
        }
    }

The package_id must already exist in `demo.remediation_packages` with a
valid recommended_pathway. Create one via the normal demo pipeline (SA-3
run) and pin its ID in your fixture.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from apps.api.app.agents.fixer.orchestrator import run_fixer
from apps.api.app.db import supabase_admin_demo


def run_sa4_sandbox_once(
    *,
    run_id: str,
    model: str,
    raw_finding: dict,  # ignored
    scanner: str,
    fixture_input: dict | None = None,
    **_ignored: Any,
) -> dict[str, Any]:
    """Dispatch SA-4 end-to-end against env2 for the given package_id,
    then read fix_run outcomes.
    """
    if not fixture_input or "package_id" not in fixture_input:
        raise ValueError(
            "SA-4 sandbox fixtures must provide an 'input' block with 'package_id'"
        )
    package_id = int(fixture_input["package_id"])

    sb = supabase_admin_demo()

    # Create a parent agent_runs row so trace FKs can be satisfied even
    # though we're not writing traces in benchmark mode. The row is kept
    # (not deleted) so you can later audit which benchmark triggered
    # which fix_run from the Supabase UI.
    agent_run_resp = (
        sb.table("agent_runs")
        .insert(
            {
                "event_id": f"bench-sa4-sandbox-{uuid.uuid4().hex[:8]}",
                "triggered_by": "benchmark",
                "action": "FULL",
                "targets": {
                    "benchmark": True,
                    "model_tag": model,  # recorded for traceability only
                    "package_id": package_id,
                },
                "status": "running",
            }
        )
        .execute()
    )
    if not agent_run_resp.data:
        raise RuntimeError("Failed to create agent_runs row for benchmark dispatch")
    agent_run_id = agent_run_resp.data[0]["run_id"]

    started = time.perf_counter()
    fix_run_id: int | None = None
    error: str | None = None
    failure_mode: str | None = None

    try:
        fix_run_id = run_fixer(
            package_id,
            agent_run_id=agent_run_id,
            sb=sb,
            emit_fn=lambda *a, **kw: None,  # swallow traces (benchmark mode)
            environment="sandbox",
        )
    except Exception as e:  # noqa: BLE001
        error = f"{type(e).__name__}: {str(e)[:300]}"
        failure_mode = _categorize_failure(e)
    finally:
        sb.table("agent_runs").update({"status": "complete"}).eq(
            "run_id", agent_run_id
        ).execute()

    wall_clock_total_ms = int((time.perf_counter() - started) * 1000)

    # Read back fix_run outcomes. If dispatch crashed before fix_run was
    # created, these come back as defaults — captured as failure_mode.
    fix_run_status: str | None = None
    rescan_verified = False
    rolled_back = False
    steps_executed = 0
    validations_passed = 0
    validations_failed = 0
    terminal_status: str | None = None

    if fix_run_id is not None and fix_run_id > 0:
        try:
            fr_resp = (
                sb.table("fix_runs")
                .select("status, step_results, validation_results, rollback_results")
                .eq("id", fix_run_id)
                .single()
                .execute()
            )
            fr = fr_resp.data or {}
            fix_run_status = fr.get("status")
            terminal_status = fix_run_status
            rolled_back = fix_run_status == "rolled_back"
            step_results = fr.get("step_results") or []
            steps_executed = sum(
                1 for s in step_results if s.get("status") == "success"
            )
            validation_results = fr.get("validation_results") or []
            validations_passed = sum(1 for v in validation_results if v.get("passed"))
            validations_failed = sum(
                1 for v in validation_results if not v.get("passed")
            )
            # rescan_verified = at least one validation flagged is_rescan AND passed
            rescan_verified = any(
                v.get("is_rescan") and v.get("passed") for v in validation_results
            )
        except Exception as e:  # noqa: BLE001
            error = f"fix_run readback failed: {type(e).__name__}: {str(e)[:200]}"

    fix_run_succeeded = fix_run_status == "success"

    return {
        "model": model,
        "scanner": scanner,
        "latency_ms": wall_clock_total_ms,
        "input_chars": 0,  # not meaningful for a lifecycle dispatch
        "prompt_tokens": 0,  # sandbox dispatch spans many LLM calls — not aggregated here
        "completion_tokens": 0,
        "retries": 0,
        "schema_valid": fix_run_succeeded,
        "failure_mode": failure_mode,
        "error": error,
        "output": None,  # too large to serialize per row
        # Sandbox-specific extras
        "fix_run_id": fix_run_id or 0,
        "terminal_status": terminal_status or "no_fix_run",
        "fix_run_succeeded": fix_run_succeeded,
        "rescan_verified": rescan_verified,
        "rolled_back": rolled_back,
        "steps_executed": steps_executed,
        "validations_passed": validations_passed,
        "validations_failed": validations_failed,
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
    if "ssm" in msg or "instance" in msg:
        return "env2_unreachable"
    if "lock" in msg or "concurrent" in msg:
        return "env2_contention"
    return "other"
