"""End-to-end CHAINED pipeline benchmark.

Unlike the per-agent isolated runners (sa1_runner, sa2_runner, …) which
feed each agent a frozen fixture input, this runner chains stages:

    Master → SA-1 → Master → SA-2 → Master → SA-3 → Master → SA-4

Each agent's LIVE output becomes the next agent's input. The only data
pulled from the fixture is the "stable" context that isn't an LLM output
(asset metadata, enrichment numbers, env2 snapshot stub) — that stays
constant across stacks so differences come purely from the models.

Two model stacks compared on the same 27 issues:

    openai:  Master=gpt-4o   SA-1=gpt-4o-mini  SA-2=gpt-4o-mini  SA-3=gpt-4o   SA-4=gpt-4o
    claude:  Master=haiku    SA-1=haiku        SA-2=haiku        SA-3=sonnet   SA-4=sonnet

Output: scorecards/pipeline_<stack>.csv — one row per issue with
total latency, total cost, which stage broke, per-stage breakdown.

Usage:
    cd apps/api
    PYTHONPATH=../.. uv run python -m apps.benchmarks.pipeline_runner --stack openai --limit 3
    PYTHONPATH=../.. uv run python -m apps.benchmarks.pipeline_runner --stack openai
    PYTHONPATH=../.. uv run python -m apps.benchmarks.pipeline_runner --stack claude
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from apps.benchmarks.agents.master_runner import run_master_once
from apps.benchmarks.agents.sa1_runner import run_sa1_once
from apps.benchmarks.agents.sa2_runner import run_sa2_once
from apps.benchmarks.agents.sa3_agentic_runner import run_sa3_agentic_once
from apps.benchmarks.agents.sa4_runner import run_sa4_once
from apps.benchmarks.models import cost_usd
from apps.benchmarks.scorers.sa1_scorer import score_sa1
from apps.benchmarks.scorers.sa2_scorer import score_sa2
from apps.benchmarks.scorers.sa3_scorer import score_sa3


# ─── Optional sandbox dispatch (--sandbox) ─────────────────────────────────
# When enabled, after SA-4 preflight produces a valid rewrite plan, we persist
# the live SA-3 output as a new row in demo.remediation_packages and dispatch
# run_fixer() to execute the plan against env2 via SSM. We then wait for the
# fix_run to reach a terminal state and record truth-grade metrics
# (rescan_verified, rolled_back, steps_executed). This is the gold-standard
# "did the fix actually work" signal.
#
# Imported lazily inside _run_sandbox() so the pipeline still works without
# a Supabase connection or env2 access when --sandbox is NOT set.
def _run_sandbox(
    live_sa3: dict, fixture: dict, run_id: str, sa4_model: str | None = None
) -> dict:
    """Persist SA-3's live output and dispatch run_fixer. Returns sandbox metrics.

    When `sa4_model` is set, we flip the preflight module-level model override
    before run_fixer() so SA-4's internal LLM call uses that model instead of
    the hardcoded gpt-4o. Override is cleared in a finally block regardless
    of outcome. All sandbox columns default to empty/None on any error so a
    sandbox failure never drops the chain's main benchmark row.
    """
    from apps.api.app.agents.fixer import preflight as _preflight
    from apps.api.app.agents.fixer.orchestrator import run_fixer
    from apps.api.app.db import supabase_admin_demo

    sb = supabase_admin_demo()
    sandbox_result: dict = {
        "sandbox_fix_run_id": 0,
        "sandbox_terminal_status": "",
        "sandbox_fix_run_succeeded": False,
        "sandbox_rescan_verified": False,
        "sandbox_rolled_back": False,
        "sandbox_steps_executed": 0,
        "sandbox_validations_passed": 0,
        "sandbox_validations_failed": 0,
        "sandbox_ms": 0,
        "sandbox_error": "",
    }

    # Need an issue_id — pull from the SA-3 fixture metadata.
    issue_id = fixture["sa3"].get("source_issue_id")
    if not issue_id:
        sandbox_result["sandbox_error"] = "no_source_issue_id_in_fixture"
        return sandbox_result

    # Create agent_runs parent row so fix_run FK satisfies.
    try:
        agent_run_resp = (
            sb.table("agent_runs")
            .insert(
                {
                    "event_id": f"bench-pipeline-sandbox-{run_id[:8]}",
                    "triggered_by": "benchmark",
                    "action": "FULL",
                    "targets": {"benchmark": True, "pipeline": True},
                    "status": "running",
                }
            )
            .execute()
        )
        agent_run_id = agent_run_resp.data[0]["run_id"]
    except Exception as e:  # noqa: BLE001
        sandbox_result["sandbox_error"] = (
            f"agent_run_create_failed:{type(e).__name__}:{str(e)[:100]}"
        )
        return sandbox_result

    # Persist SA-3 live output as a new remediation_packages row.
    pathways = live_sa3.get("pathways") or []
    pkg_row = {
        "issue_id": int(issue_id),
        "family": fixture["sa3"]["input"].get("family", "os_vulnerability"),
        "finding": (live_sa3.get("finding") or "")[:1900],
        "root_cause": (live_sa3.get("root_cause") or "")[:1900],
        "impact": (live_sa3.get("impact") or "")[:1900],
        "pathways": pathways,
        "recommended_pathway_index": 0,
        "approval_required": "single_approver",
        "status": "awaiting_approval",
        "agent_run_id": agent_run_id,
    }
    try:
        pkg_resp = sb.table("remediation_packages").insert(pkg_row).execute()
        package_id = pkg_resp.data[0]["id"]
    except Exception as e:  # noqa: BLE001
        sandbox_result["sandbox_error"] = (
            f"package_persist_failed:{type(e).__name__}:{str(e)[:100]}"
        )
        return sandbox_result

    # Dispatch the fixer. If sa4_model is set, flip the preflight override
    # so the Claude pipeline's SA-4 preflight call uses Claude too (not the
    # hardcoded gpt-4o). Reset in finally regardless of outcome.
    started = time.perf_counter()
    _original_override = _preflight._PREFLIGHT_MODEL_OVERRIDE[0]
    try:
        if sa4_model:
            _preflight._PREFLIGHT_MODEL_OVERRIDE[0] = sa4_model
        fix_run_id = run_fixer(
            package_id,
            agent_run_id=agent_run_id,
            sb=sb,
            emit_fn=lambda *a, **kw: None,
            environment="sandbox",
        )
    except Exception as e:  # noqa: BLE001
        sandbox_result["sandbox_error"] = (
            f"fixer_crashed:{type(e).__name__}:{str(e)[:120]}"
        )
        sandbox_result["sandbox_ms"] = int((time.perf_counter() - started) * 1000)
        try:
            sb.table("agent_runs").update({"status": "completed"}).eq(
                "run_id", agent_run_id
            ).execute()
        except Exception:  # noqa: BLE001, S110
            pass  # cleanup is best-effort — never swallow the original fixer error
        return sandbox_result
    finally:
        # Always reset — never leak the override into a subsequent chain.
        _preflight._PREFLIGHT_MODEL_OVERRIDE[0] = _original_override

    sandbox_result["sandbox_ms"] = int((time.perf_counter() - started) * 1000)
    sandbox_result["sandbox_fix_run_id"] = int(fix_run_id or 0)

    # Mark the agent_runs row complete regardless of fix_run outcome.
    try:
        sb.table("agent_runs").update({"status": "completed"}).eq(
            "run_id", agent_run_id
        ).execute()
    except Exception:  # noqa: BLE001, S110
        pass

    # Read back fix_run outcomes.
    if fix_run_id:
        try:
            fr_resp = (
                sb.table("fix_runs")
                .select("status, step_results, validation_results")
                .eq("id", fix_run_id)
                .single()
                .execute()
            )
            fr = fr_resp.data or {}
            status = fr.get("status") or "unknown"
            sandbox_result["sandbox_terminal_status"] = status
            sandbox_result["sandbox_fix_run_succeeded"] = status == "success"
            sandbox_result["sandbox_rolled_back"] = status == "rolled_back"
            steps = fr.get("step_results") or []
            sandbox_result["sandbox_steps_executed"] = sum(
                1 for s in steps if s.get("status") == "success"
            )
            vals = fr.get("validation_results") or []
            sandbox_result["sandbox_validations_passed"] = sum(
                1 for v in vals if v.get("passed")
            )
            sandbox_result["sandbox_validations_failed"] = sum(
                1 for v in vals if not v.get("passed")
            )
            sandbox_result["sandbox_rescan_verified"] = any(
                v.get("is_rescan") and v.get("passed") for v in vals
            )
        except Exception as e:  # noqa: BLE001
            sandbox_result["sandbox_error"] = (
                f"readback_failed:{type(e).__name__}:{str(e)[:100]}"
            )

    return sandbox_result


_BENCH = Path(__file__).parent
_FX_SUCCESS = _BENCH / "fixtures" / "success"
_SCORECARDS = _BENCH / "scorecards"


# Model stacks. Mirror the per-agent choices from the isolated benchmark.
STACKS: dict[str, dict[str, str]] = {
    "openai": {
        "master": "gpt-4o",
        "sa1": "gpt-4o-mini",
        "sa2": "gpt-4o-mini",
        "sa3": "gpt-4o",
        "sa4": "gpt-4o",
    },
    "claude": {
        "master": "claude-haiku-4-5",
        "sa1": "claude-haiku-4-5",
        "sa2": "claude-haiku-4-5",
        "sa3": "claude-sonnet-4-6",
        "sa4": "claude-sonnet-4-6",
    },
    # Google retired every version-pinned Gemini name in Oct 2026. Only
    # -latest aliases are live. SA-1 gets the cheapest (lite); SA-3/SA-4
    # need pro for the agentic + nested-schema workload (free-tier quota
    # on pro is tight — enable billing on the Google project before full
    # 9-chain runs).
    "gemini": {
        # Flash (non-lite) tier has NO pinned name live on this project;
        # must use the -latest alias here.
        "master": "gemini-flash-latest",
        "sa2": "gemini-flash-latest",
        # Flash-Lite + Pro both have specific-pinned names live on this
        # project — use them so results are reproducible even if Google
        # updates the -latest aliases later.
        "sa1": "gemini-3.1-flash-lite",  # PINNED (stable)
        "sa3": "gemini-3.1-pro-preview",  # PINNED (preview)
        "sa4": "gemini-3.1-pro-preview",  # PINNED (preview)
    },
}


def _load_issue_fixtures(limit: int | None) -> list[dict]:
    """Load all 4 agent fixtures per issue, matched by slug.

    Returns list of {slug, sa1, sa2, sa3, sa4} dicts. Skips issues missing
    any of the 4 agent fixture files.
    """
    sa1_dir = _FX_SUCCESS / "sa1"
    if not sa1_dir.exists():
        print(f"✗ Missing {sa1_dir} — run pick_success_fixtures.py first")
        return []

    issues: list[dict] = []
    for sa1_path in sorted(sa1_dir.glob("*.json")):
        slug = sa1_path.stem
        sa2_path = _FX_SUCCESS / "sa2" / f"{slug}-sa2.json"
        sa3_path = _FX_SUCCESS / "sa3" / f"{slug}-sa3.json"
        sa4_path = _FX_SUCCESS / "sa4" / f"{slug}-sa4.json"
        if not (sa2_path.exists() and sa3_path.exists() and sa4_path.exists()):
            continue
        issues.append(
            {
                "slug": slug,
                "sa1": json.loads(sa1_path.read_text()),
                "sa2": json.loads(sa2_path.read_text()),
                "sa3": json.loads(sa3_path.read_text()),
                "sa4": json.loads(sa4_path.read_text()),
            }
        )
    if limit:
        issues = issues[:limit]
    return issues


def _master_trigger(stage: str, slug: str, prev_output: dict | None) -> dict:
    """Build a Master trigger input for a given stage in the chain."""
    return {
        "trigger": {
            "event_id": f"BENCH-{slug[:16]}-{stage}",
            "action": "FULL",
            "persona": "admin",
            "targets": {"scanners": [slug.split("-")[0]]},
            "next_stage": stage,
            "prev_output_summary": _summary(prev_output),
        },
        "available_tools": ["sub-agent-1", "sub-agent-2", "sub-agent-3", "sub-agent-4"],
    }


def _summary(output: dict | None) -> str:
    """Compact summary of a previous stage's output for Master context."""
    if not output:
        return "none"
    keys = list(output.keys())[:5]
    return f"keys={keys}"


def _overlay_sa2_input(sa2_fixture: dict, live_sa1_output: dict) -> dict:
    """Build SA-2 input from fixture metadata + LIVE SA-1 output."""
    fixture_input = sa2_fixture.get("input", {})
    live_issue = {
        "severity": live_sa1_output.get("severity"),
        "cve_id": live_sa1_output.get("cve_id"),
        "source_vuln_id": live_sa1_output.get("source_vuln_id"),
        "title": live_sa1_output.get("title"),
        "description": live_sa1_output.get("description"),
        "asset_identity": live_sa1_output.get("asset_identity") or {},
        "package": live_sa1_output.get("package"),
    }
    # Keep the frozen enrichment/asset/scoring — those aren't LLM outputs.
    return {
        "issue": live_issue,
        "enrichment": fixture_input.get("enrichment", {}),
        "scoring": fixture_input.get("scoring", {}),
    }


def _overlay_sa3_input(sa3_fixture: dict, live_sa1_output: dict) -> dict:
    """Build SA-3 input from fixture metadata + LIVE normalized issue."""
    fixture_input = sa3_fixture.get("input", {})
    live_issue = {
        "id": fixture_input.get("issue", {}).get("id"),  # synthetic id for logging
        "source": fixture_input.get("issue", {}).get("source"),
        "severity": live_sa1_output.get("severity"),
        "cve_id": live_sa1_output.get("cve_id"),
        "source_vuln_id": live_sa1_output.get("source_vuln_id"),
        "title": live_sa1_output.get("title"),
        "description": live_sa1_output.get("description"),
        "package": live_sa1_output.get("package"),
        "asset_identity": live_sa1_output.get("asset_identity") or {},
    }
    return {
        "issue": live_issue,
        "asset": fixture_input.get("asset", {}),
        "family": fixture_input.get("family", "os_vulnerability"),
    }


def _overlay_sa4_input(
    sa4_fixture: dict, live_sa3_output: dict, live_sa1_output: dict
) -> dict:
    """Build SA-4 input from LIVE SA-3 remediation package + LIVE SA-1 issue."""
    pathways = live_sa3_output.get("pathways") or []
    pathway = pathways[0] if pathways else {"remediation_steps": []}
    return {
        "pathway": {"remediation_steps": pathway.get("remediation_steps") or []},
        "snapshot_text": sa4_fixture.get("input", {}).get("snapshot_text", ""),
        "issue": {
            "id": sa4_fixture.get("input", {}).get("issue", {}).get("id"),
            "source_vuln_id": live_sa1_output.get("source_vuln_id"),
            "title": live_sa1_output.get("title"),
            "severity": live_sa1_output.get("severity"),
            "asset_identity": live_sa1_output.get("asset_identity") or {},
        },
    }


def _stage_cost(result: dict, model: str) -> float:
    return cost_usd(
        model, result.get("prompt_tokens", 0), result.get("completion_tokens", 0)
    )


def run_pipeline_once(
    issue: dict, stack: dict[str, str], *, sandbox: bool = False
) -> dict:
    """Run one chained pipeline for one issue + one stack. Returns row dict.

    When sandbox=True, after SA-4 preflight succeeds we also persist the SA-3
    live output as a demo.remediation_packages row and dispatch run_fixer()
    against env2, recording truth-grade metrics.
    """
    slug = issue["slug"]
    row: dict = {
        "slug": slug,
        "stack_master": stack["master"],
        "stack_sa1": stack["sa1"],
        "stack_sa2": stack["sa2"],
        "stack_sa3": stack["sa3"],
        "stack_sa4": stack["sa4"],
        "broken_at": "",
        "final_output_valid": False,
    }
    stages_cost = 0.0
    stages_latency = 0

    def _record(stage: str, result: dict, model: str) -> bool:
        """Record stage metrics into the row. Returns False if stage failed."""
        nonlocal stages_cost, stages_latency
        cost = _stage_cost(result, model)
        chars = result.get("input_chars", 0) or 0
        cost_per_1k = round((cost / chars * 1000), 6) if chars else 0.0
        row[f"{stage}_ms"] = result.get("latency_ms", 0)
        row[f"{stage}_cost"] = round(cost, 6)
        row[f"{stage}_cost_per_1k_chars"] = cost_per_1k
        row[f"{stage}_input_chars"] = chars
        row[f"{stage}_prompt_tokens"] = result.get("prompt_tokens", 0)
        row[f"{stage}_completion_tokens"] = result.get("completion_tokens", 0)
        row[f"{stage}_ok"] = result.get("schema_valid", False)
        row[f"{stage}_failure_mode"] = result.get("failure_mode") or ""
        row[f"{stage}_error"] = (result.get("error") or "")[:200]
        stages_cost += cost
        stages_latency += result.get("latency_ms", 0)
        return bool(result.get("schema_valid"))

    def _score(stage: str, scorer_fn, fixture_id: str, output: dict | None) -> None:
        """Run the per-agent LLM-judge rubric scorer against the live output.

        Writes efficacy_score + fields_passed/failed + hallucinated + reason
        into the row under keys like sa1_efficacy_score, sa2_efficacy_score, ...
        Judge call cost is NOT added to total_cost (that measures the stack
        under test, not our evaluator).
        """
        try:
            s = scorer_fn(fixture_id, output)
        except Exception as e:  # noqa: BLE001
            s = {
                "efficacy_score": None,
                "fields_passed": "",
                "fields_failed": "",
                "hallucinated": None,
                "efficacy_reason": f"scorer_crashed:{type(e).__name__}",
            }
        row[f"{stage}_efficacy_score"] = s.get("efficacy_score")
        row[f"{stage}_fields_passed"] = s.get("fields_passed", "")
        row[f"{stage}_fields_failed"] = s.get("fields_failed", "")
        row[f"{stage}_hallucinated"] = s.get("hallucinated")
        row[f"{stage}_efficacy_reason"] = (s.get("efficacy_reason") or "")[:200]

    # ─── Master → decides SA-1 ─────────────────────────────────────────
    rid = str(uuid.uuid4())
    master1 = run_master_once(
        run_id=rid,
        model=stack["master"],
        raw_finding={},
        scanner="pipeline",
        fixture_input=_master_trigger("sa1", slug, None),
    )
    if not _record("master1", master1, stack["master"]):
        row["broken_at"] = "master1"
        row["total_ms"] = stages_latency
        row["total_cost"] = round(stages_cost, 6)
        return row

    # ─── SA-1 ──────────────────────────────────────────────────────────
    rid = str(uuid.uuid4())
    sa1_result = run_sa1_once(
        run_id=rid,
        model=stack["sa1"],
        raw_finding=issue["sa1"].get("raw", {}),
        scanner=issue["sa1"].get("scanner", "unknown"),
    )
    if not _record("sa1", sa1_result, stack["sa1"]):
        row["broken_at"] = "sa1"
        row["total_ms"] = stages_latency
        row["total_cost"] = round(stages_cost, 6)
        return row
    live_sa1 = sa1_result.get("output") or {}
    _score("sa1", score_sa1, slug, live_sa1)

    # ─── Master → decides SA-2 ─────────────────────────────────────────
    rid = str(uuid.uuid4())
    master2 = run_master_once(
        run_id=rid,
        model=stack["master"],
        raw_finding={},
        scanner="pipeline",
        fixture_input=_master_trigger("sa2", slug, live_sa1),
    )
    if not _record("master2", master2, stack["master"]):
        row["broken_at"] = "master2"
        row["total_ms"] = stages_latency
        row["total_cost"] = round(stages_cost, 6)
        return row

    # ─── SA-2 ──────────────────────────────────────────────────────────
    rid = str(uuid.uuid4())
    sa2_result = run_sa2_once(
        run_id=rid,
        model=stack["sa2"],
        raw_finding={},
        scanner=issue["sa2"].get("scanner", "unknown"),
        fixture_input=_overlay_sa2_input(issue["sa2"], live_sa1),
    )
    if not _record("sa2", sa2_result, stack["sa2"]):
        row["broken_at"] = "sa2"
        row["total_ms"] = stages_latency
        row["total_cost"] = round(stages_cost, 6)
        return row
    _score("sa2", score_sa2, f"{slug}-sa2", sa2_result.get("output"))

    # ─── Master → decides SA-3 ─────────────────────────────────────────
    rid = str(uuid.uuid4())
    master3 = run_master_once(
        run_id=rid,
        model=stack["master"],
        raw_finding={},
        scanner="pipeline",
        fixture_input=_master_trigger("sa3", slug, sa2_result.get("output")),
    )
    if not _record("master3", master3, stack["master"]):
        row["broken_at"] = "master3"
        row["total_ms"] = stages_latency
        row["total_cost"] = round(stages_cost, 6)
        return row

    # ─── SA-3 agentic (the expensive one) ──────────────────────────────
    rid = str(uuid.uuid4())
    sa3_result = run_sa3_agentic_once(
        run_id=rid,
        model=stack["sa3"],
        raw_finding={},
        scanner=issue["sa3"].get("scanner", "unknown"),
        fixture_input=_overlay_sa3_input(issue["sa3"], live_sa1),
    )
    # SA-3 reports tool cost separately — add it to the chain total.
    sa3_tool_cost = float(sa3_result.get("tool_cost_usd_accrued") or 0.0)
    row["sa3_tool_cost"] = round(sa3_tool_cost, 6)
    row["sa3_tool_calls"] = sa3_result.get("tool_call_count", 0)
    stages_cost += sa3_tool_cost
    if not _record("sa3", sa3_result, stack["sa3"]):
        row["broken_at"] = "sa3"
        row["total_ms"] = stages_latency
        row["total_cost"] = round(stages_cost, 6)
        return row
    live_sa3 = sa3_result.get("output") or {}
    _score("sa3", score_sa3, f"{slug}-sa3", live_sa3)

    # ─── Master → decides SA-4 ─────────────────────────────────────────
    rid = str(uuid.uuid4())
    master4 = run_master_once(
        run_id=rid,
        model=stack["master"],
        raw_finding={},
        scanner="pipeline",
        fixture_input=_master_trigger("sa4", slug, live_sa3),
    )
    if not _record("master4", master4, stack["master"]):
        row["broken_at"] = "master4"
        row["total_ms"] = stages_latency
        row["total_cost"] = round(stages_cost, 6)
        return row

    # ─── SA-4 preflight ────────────────────────────────────────────────
    rid = str(uuid.uuid4())
    sa4_result = run_sa4_once(
        run_id=rid,
        model=stack["sa4"],
        raw_finding={},
        scanner=issue["sa4"].get("scanner", "unknown"),
        fixture_input=_overlay_sa4_input(issue["sa4"], live_sa3, live_sa1),
    )
    if not _record("sa4", sa4_result, stack["sa4"]):
        row["broken_at"] = "sa4"
        row["total_ms"] = stages_latency
        row["total_cost"] = round(stages_cost, 6)
        return row

    # ─── Optional sandbox dispatch — truth-grade "did the fix work?" ──────
    # Only runs when --sandbox is set. Takes +5-15 min per chain, mutates
    # env2 state. Columns default to blank so chains without sandbox still
    # fit the same CSV schema (writer uses extrasaction="ignore").
    if sandbox:
        sandbox_run_id = str(uuid.uuid4())
        # Pass the stack's SA-4 model so Claude pipelines run SA-4 preflight
        # on Claude too, not the hardcoded production gpt-4o default.
        sandbox_metrics = _run_sandbox(
            live_sa3, issue, sandbox_run_id, sa4_model=stack.get("sa4")
        )
        row.update(sandbox_metrics)

    row["final_output_valid"] = True
    row["total_ms"] = stages_latency
    row["total_cost"] = round(stages_cost, 6)
    return row


def _stage_cols(stage: str, *, with_efficacy: bool) -> list[str]:
    """Standard per-stage column names. Keep ordering stable for CSV."""
    base = [
        f"{stage}_ms",
        f"{stage}_input_chars",
        f"{stage}_prompt_tokens",
        f"{stage}_completion_tokens",
        f"{stage}_cost",
        f"{stage}_cost_per_1k_chars",
        f"{stage}_ok",
        f"{stage}_failure_mode",
        f"{stage}_error",
    ]
    if with_efficacy:
        base += [
            f"{stage}_efficacy_score",
            f"{stage}_fields_passed",
            f"{stage}_fields_failed",
            f"{stage}_hallucinated",
            f"{stage}_efficacy_reason",
        ]
    return base


_SANDBOX_COLS = [
    "sandbox_fix_run_id",
    "sandbox_terminal_status",
    "sandbox_fix_run_succeeded",
    "sandbox_rescan_verified",
    "sandbox_rolled_back",
    "sandbox_steps_executed",
    "sandbox_validations_passed",
    "sandbox_validations_failed",
    "sandbox_ms",
    "sandbox_error",
]

_CSV_COLUMNS = (
    [
        "run_timestamp",
        "slug",
        "stack_master",
        "stack_sa1",
        "stack_sa2",
        "stack_sa3",
        "stack_sa4",
        "final_output_valid",
        "broken_at",
        "total_ms",
        "total_cost",
    ]
    + _stage_cols("master1", with_efficacy=False)
    + _stage_cols("sa1", with_efficacy=True)
    + _stage_cols("master2", with_efficacy=False)
    + _stage_cols("sa2", with_efficacy=True)
    + _stage_cols("master3", with_efficacy=False)
    + _stage_cols("sa3", with_efficacy=True)
    + ["sa3_tool_cost", "sa3_tool_calls"]
    + _stage_cols("master4", with_efficacy=False)
    + _stage_cols("sa4", with_efficacy=False)
    + _SANDBOX_COLS
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="End-to-end chained pipeline benchmark"
    )
    parser.add_argument("--stack", required=True, choices=sorted(STACKS.keys()))
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Only run first N issues (for smoke tests)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Chain each issue N times for consistency measurement (default 1)",
    )
    parser.add_argument(
        "--skip-done",
        action="store_true",
        help="Skip (slug, run_n) pairs already marked final_output_valid=True in the CSV",
    )
    parser.add_argument(
        "--one-per-scanner",
        action="store_true",
        help="Pick 1 issue per scanner (9 total, instead of 27). Fast triage pass.",
    )
    parser.add_argument(
        "--per-scanner",
        type=int,
        default=None,
        help="Pick first N issues per scanner (e.g. --per-scanner 2 → 18 issues total).",
    )
    parser.add_argument(
        "--sa3-model",
        default=None,
        help="Override just SA-3's model (e.g. claude-opus-4-7 or claude-haiku-4-5). "
        "Other agents keep their stack defaults. Useful for isolated SA-3 model trials.",
    )
    parser.add_argument(
        "--scanner",
        default=None,
        help="Only run issues from this scanner (e.g. 'checkov-ec2'). "
        "Combine with --limit for targeted trials.",
    )
    parser.add_argument(
        "--sandbox",
        action="store_true",
        help="After SA-4 preflight succeeds, dispatch run_fixer() to env2 via SSM "
        "and wait for the fix_run to complete. Adds sandbox_* columns (fix_run_id, "
        "terminal_status, rescan_verified, rolled_back, steps_executed, validations_*). "
        "Each chain takes +5-15 min. Mutates real env2 state.",
    )
    parser.add_argument(
        "--per-scanner-until-success",
        action="store_true",
        help="For each scanner, keep trying issues until ONE succeeds end-to-end "
        "(final_output_valid=True). Writes the winning (scanner, slug) pairs to "
        "scorecards/winning_issues_<stack>.json so a follow-up OpenAI run can target "
        "the exact same set for apples-to-apples comparison.",
    )
    parser.add_argument(
        "--issue-slugs",
        default=None,
        help="Comma-separated list of exact issue slugs to run (e.g. for replaying "
        "a 'winning' set captured earlier). Combines with --sandbox + --stack to "
        "mirror a previous run on a different stack.",
    )
    args = parser.parse_args(argv)

    # Build stack config, with optional SA-3 model override for isolated trials.
    stack = dict(STACKS[args.stack])
    if args.sa3_model:
        stack["sa3"] = args.sa3_model
        print(f"▶ --sa3-model: overriding SA-3 model → {args.sa3_model}")

    # Defer --limit until AFTER --scanner / --one-per-scanner filters so limit
    # trims the filtered set (not the raw alphabetical set). E.g.
    # "--scanner semgrep-ec2 --limit 1" picks the first semgrep issue, not
    # the first alphabetical issue (which is checkov).
    needs_deferred_limit = args.one_per_scanner or args.scanner
    load_limit = None if needs_deferred_limit else args.limit
    issues = _load_issue_fixtures(limit=load_limit)
    if not issues:
        print("✗ No issues loaded. Did you run pick_success_fixtures.py?")
        return 1

    # Filter to one scanner only if requested.
    if args.scanner:
        before = len(issues)
        issues = [i for i in issues if i["sa1"].get("scanner") == args.scanner]
        print(f"▶ --scanner={args.scanner}: filtered {before} → {len(issues)} issues")
        if not issues:
            print(f"✗ No issues match scanner={args.scanner}")
            return 1
        # Apply --limit now if --one-per-scanner isn't set (which has its own
        # limit application later).
        if args.limit and not args.one_per_scanner:
            issues = issues[: args.limit]
            print(
                f"▶ --limit={args.limit} applied to scanner subset → {len(issues)} issues"
            )

    # Filter to a specific list of slugs (e.g. a "winning" set captured earlier).
    if args.issue_slugs:
        wanted = {s.strip() for s in args.issue_slugs.split(",") if s.strip()}
        before = len(issues)
        issues = [i for i in issues if i["slug"] in wanted]
        print(
            f"▶ --issue-slugs: filtered {before} → {len(issues)} issues (requested {len(wanted)})"
        )
        if len(issues) < len(wanted):
            missing = wanted - {i["slug"] for i in issues}
            print(f"  ⚠ Missing: {sorted(missing)}")

    # Pick first N issues per scanner (e.g. --per-scanner 2 → first 2 of each).
    # Deterministic: alphabetical order within each scanner, so re-runs across
    # providers hit the SAME issue set.
    if args.per_scanner:
        by_scanner_map: dict[str, list[dict]] = {}
        for issue in issues:
            scanner = issue["sa1"].get("scanner", "unknown")
            by_scanner_map.setdefault(scanner, []).append(issue)
        filtered_n: list[dict] = []
        for scanner in sorted(by_scanner_map.keys()):
            filtered_n.extend(by_scanner_map[scanner][: args.per_scanner])
        issues = filtered_n
        print(
            f"▶ --per-scanner={args.per_scanner}: {len(issues)} issues ({args.per_scanner} per scanner)"
        )

    # Filter to 1 issue per scanner for a fast triage pass.
    # Scanner is the slug prefix up to the first digit-containing segment —
    # e.g. "checkov-ec2-ckv-aws-288-23895" → scanner "checkov-ec2".
    if args.one_per_scanner:
        seen: set[str] = set()
        filtered: list[dict] = []
        for issue in issues:
            scanner = (
                issue["sa1"].get("scanner")
                or issue["slug"].split("-ckv-")[0].split("-cve-")[0].split("-opt.")[0]
            )
            if scanner not in seen:
                seen.add(scanner)
                filtered.append(issue)
        issues = filtered
        print(f"▶ --one-per-scanner: filtered to {len(issues)} issues (1 per scanner)")

        # Now apply --limit to the deduplicated per-scanner picks.
        if args.limit:
            issues = issues[: args.limit]
            print(
                f"▶ --limit={args.limit} applied to per-scanner picks → {len(issues)} issues"
            )

    _SCORECARDS.mkdir(parents=True, exist_ok=True)
    out_path = _SCORECARDS / f"pipeline_{args.stack}.csv"
    file_existed = out_path.exists()

    # ─── Load already-complete (slug, run_n) pairs if --skip-done ─────────
    already_done: set[tuple[str, int]] = set()
    if args.skip_done and out_path.exists():
        try:
            with out_path.open() as f:
                for r in csv.DictReader(f):
                    if r.get("final_output_valid") == "True":
                        try:
                            already_done.add((r["slug"], int(r.get("run_n") or 1)))
                        except (ValueError, KeyError):
                            pass
            print(
                f"▶ --skip-done: found {len(already_done)} already-complete (slug, run) pairs"
            )
        except Exception as e:  # noqa: BLE001
            print(f"⚠ --skip-done: could not read existing CSV ({e}); running all")

    total_chains = len(issues) * args.runs
    chains_to_run = total_chains - len(already_done)
    print(
        f"▶ Pipeline benchmark — stack={args.stack}, {len(issues)} issue(s) × {args.runs} run(s) = {total_chains} total ({chains_to_run} to run)"
    )
    print(f"  Models: {stack}")
    print(f"  Scorecard: {out_path}")
    print()

    totals_cost = 0.0
    full_success = 0
    broke_counts: dict[str, int] = {}
    columns = _CSV_COLUMNS + ["run_n"] if "run_n" not in _CSV_COLUMNS else _CSV_COLUMNS

    # ─── Build the schedule ───────────────────────────────────────────
    # When --per-scanner-until-success is set, we iterate per-scanner and
    # move on as soon as one issue succeeds (across any run). Otherwise
    # we run every (issue, run_n) pair in order.
    winning_slugs: dict[str, str] = {}  # scanner → winning slug
    winners_path = _SCORECARDS / f"winning_issues_{args.stack}.json"

    def _write_row(writer, f, row, run_n):
        row["run_timestamp"] = datetime.now(UTC).isoformat()
        row["run_n"] = run_n
        writer.writerow(row)
        f.flush()

    def _print_outcome(wall_s, cost, row):
        if row.get("final_output_valid"):
            if args.sandbox:
                rescan = (
                    "✓ RESCAN VERIFIED"
                    if row.get("sandbox_rescan_verified")
                    else f"✗ sandbox: {row.get('sandbox_terminal_status') or 'no_result'}"
                )
                sb_err = row.get("sandbox_error", "")
                sb_tail = f"  [{sb_err}]" if sb_err else ""
                print(
                    f"      ✓ full chain  — {wall_s:.1f}s  ${cost:.4f}  {rescan}{sb_tail}"
                )
            else:
                print(f"      ✓ full chain  — {wall_s:.1f}s  ${cost:.4f}")
        else:
            broken_at = row.get("broken_at", "?")
            err = row.get(f"{broken_at}_error", "")[:120]
            print(
                f"      ✗ broke at {broken_at}  — {wall_s:.1f}s  ${cost:.4f}  err={err}"
            )

    with out_path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        if not file_existed:
            writer.writeheader()

        if args.per_scanner_until_success:
            # Group issues by scanner, iterate until one succeeds per scanner.
            # Load ALL issues (not just the one-per-scanner picks) so we have
            # alternates to try when the first candidate fails at SA-3.
            all_issues = _load_issue_fixtures(limit=None)
            by_scanner: dict[str, list[dict]] = {}
            for i in all_issues:
                by_scanner.setdefault(i["sa1"].get("scanner", "unknown"), []).append(i)
            scanners_to_run = sorted(by_scanner.keys())
            if args.scanner:
                scanners_to_run = [s for s in scanners_to_run if s == args.scanner]
            if args.limit:
                scanners_to_run = scanners_to_run[: args.limit]
            print(
                f"\n▶ Per-scanner-until-success mode: {len(scanners_to_run)} scanners\n"
            )

            for scanner in scanners_to_run:
                candidates = by_scanner[scanner]
                print(f"━━━ Scanner: {scanner} ({len(candidates)} candidates) ━━━")
                succeeded = False
                for cand in candidates:
                    sandbox_tag = " +sandbox" if args.sandbox else ""
                    print(f"  → trying {cand['slug']}{sandbox_tag}")
                    started = time.perf_counter()
                    row = run_pipeline_once(cand, stack, sandbox=args.sandbox)
                    _write_row(writer, f, row, 1)
                    wall_s = time.perf_counter() - started
                    cost = float(row.get("total_cost", 0.0))
                    totals_cost += cost
                    _print_outcome(wall_s, cost, row)
                    if row.get("final_output_valid"):
                        full_success += 1
                        winning_slugs[scanner] = cand["slug"]
                        # Write winners file after each success for crash safety.
                        winners_path.write_text(json.dumps(winning_slugs, indent=2))
                        succeeded = True
                        break
                    broke_counts[row.get("broken_at", "?")] = (
                        broke_counts.get(row.get("broken_at", "?"), 0) + 1
                    )
                if not succeeded:
                    print(f"  ✗ No candidate succeeded for scanner={scanner}")
                print()
        else:
            # Standard per-issue loop with --runs N
            chain_i = 0
            for issue in issues:
                for run_n in range(1, args.runs + 1):
                    chain_i += 1
                    if (issue["slug"], run_n) in already_done:
                        print(
                            f"  [{chain_i}/{total_chains}] {issue['slug']} (run {run_n}/{args.runs})  ⏭  already done, skipping"
                        )
                        continue
                    sandbox_tag = " +sandbox" if args.sandbox else ""
                    print(
                        f"  [{chain_i}/{total_chains}] {issue['slug']} (run {run_n}/{args.runs}){sandbox_tag}"
                    )
                    started = time.perf_counter()
                    row = run_pipeline_once(issue, stack, sandbox=args.sandbox)
                    _write_row(writer, f, row, run_n)
                    wall_s = time.perf_counter() - started
                    cost = float(row.get("total_cost", 0.0))
                    totals_cost += cost
                    _print_outcome(wall_s, cost, row)
                    if row.get("final_output_valid"):
                        full_success += 1
                    else:
                        broken_at = row.get("broken_at", "?")
                        broke_counts[broken_at] = broke_counts.get(broken_at, 0) + 1

    print()
    print(
        f"▶ Done. {full_success} full-chain successes. Total cost: ${totals_cost:.4f}"
    )
    if broke_counts:
        print(
            "  Broke at:",
            ", ".join(f"{k}={v}" for k, v in sorted(broke_counts.items())),
        )
    print(f"  Scorecard: {out_path}")
    if args.per_scanner_until_success and winning_slugs:
        print()
        print(f"▶ Winning issues per scanner ({len(winning_slugs)}):")
        for s, slug in sorted(winning_slugs.items()):
            print(f"    [{s}] {slug}")
        print(f"  Saved to: {winners_path}")
        print()
        print("  To replay this same set on another stack:")
        slugs_csv = ",".join(sorted(winning_slugs.values()))
        print(
            f'  PYTHONPATH=../.. uv run python -m apps.benchmarks.pipeline_runner --stack <other> --issue-slugs "{slugs_csv}" --runs 1 --sandbox'
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
