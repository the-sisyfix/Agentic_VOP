"""Benchmark harness CLI entry point.

Usage:
    python -m apps.benchmarks.runner --agent sa1 --model gpt-4o-mini
    python -m apps.benchmarks.runner --agent sa1 --model claude-haiku-4-5 --runs 3

Loads pinned fixtures from fixtures/raw/, invokes the chosen agent with the
chosen model, writes one CSV row per (fixture × run) to scorecards/.

Day-1 scope: SA-1 only, Tier 1 metrics only (latency, cost, schema valid,
failure mode). Tier 3 quality scoring is added later when ground truth
labeling exists.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from apps.benchmarks.agents.master_runner import run_master_once
from apps.benchmarks.agents.sa1_runner import run_sa1_once
from apps.benchmarks.agents.sa2_runner import run_sa2_once
from apps.benchmarks.agents.sa3_agentic_runner import run_sa3_agentic_once
from apps.benchmarks.agents.sa4_runner import run_sa4_once
from apps.benchmarks.agents.sa4_sandbox_runner import run_sa4_sandbox_once
from apps.benchmarks.models import BY_NAME, cost_usd
from apps.benchmarks.scorers.master_scorer import score_master
from apps.benchmarks.scorers.sa1_scorer import score_sa1
from apps.benchmarks.scorers.sa2_scorer import score_sa2
from apps.benchmarks.scorers.sa3_scorer import score_sa3
from apps.benchmarks.scorers.sa4_scorer import score_sa4


_BENCHMARK_ROOT = Path(__file__).parent
_FIXTURES_DIR = _BENCHMARK_ROOT / "fixtures" / "raw"
_SCORECARDS_DIR = _BENCHMARK_ROOT / "scorecards"


_AGENT_RUNNERS = {
    "sa1": run_sa1_once,
    "sa2": run_sa2_once,
    "sa3": run_sa3_agentic_once,  # agentic tool-calling loop (Nikhil's spec)
    "sa4": run_sa4_once,
    "sa4_sandbox": run_sa4_sandbox_once,  # end-to-end oracle, slower
    "master": run_master_once,
}

# Agent-specific extra columns appended to the scorecard CSV when present
# in the result dict. The common Tier-1 columns are in _CSV_COLUMNS below;
# these are the per-agent extras.
_EXTRA_COLUMNS_BY_AGENT = {
    "sa3": [
        "pathways_count",
        "recommended_steps",
        "tool_call_count",
        "tools_used",
        "web_search_calls",
        "url_fetch_calls",
        "file_fetch_calls",
        "tool_budget_remaining",
        "tool_cost_usd_accrued",
    ],
    "sa4": ["rewrites_total", "rewrites_high_conf"],
    "sa4_sandbox": [
        "fix_run_id",
        "terminal_status",
        "fix_run_succeeded",
        "rescan_verified",
        "rolled_back",
        "steps_executed",
        "validations_passed",
        "validations_failed",
    ],
}


def _load_fixtures(
    agent: str, scanner_filter: str | None = None, fixtures_dir: Path | None = None
) -> list[dict]:
    """Load fixtures from a directory matching the given agent.

    `fixtures_dir` defaults to _FIXTURES_DIR (the mixed random pool). The
    success-only pool lives at fixtures/success/{sa1,sa2,sa3,sa4}/ — pass
    that path to benchmark against known-good fixtures only.
    """
    base = fixtures_dir or _FIXTURES_DIR
    if not base.exists():
        return []
    # If base has per-agent subdirs (sa1/, sa2/, ...), only scan the one
    # matching our agent. Otherwise scan the whole flat dir.
    agent_subdir = base / agent
    search_root = agent_subdir if agent_subdir.exists() else base
    fixtures: list[dict] = []
    for path in sorted(search_root.rglob("*.json")):
        with path.open() as f:
            data = json.load(f)
        declared = data.get("agent")
        inferred = None if "input" in data else "sa1" if "raw" in data else None
        matched_agent = declared or inferred
        if matched_agent != agent:
            continue
        if scanner_filter and data.get("scanner") != scanner_filter:
            continue
        fixtures.append(data)
    return fixtures


def _scorecard_path(agent: str, model: str) -> Path:
    """One CSV per (agent, model) combo in scorecards/."""
    _SCORECARDS_DIR.mkdir(parents=True, exist_ok=True)
    safe_model = model.replace("/", "_").replace(":", "_")
    return _SCORECARDS_DIR / f"{agent}_{safe_model}.csv"


_CSV_COLUMNS = [
    "run_timestamp",
    "fixture_id",
    "scanner",
    "model",
    "run_n",
    # Performance
    "latency_ms",
    # Cost — both ways per Nikhil's requirement
    "input_chars",
    "prompt_tokens",
    "completion_tokens",
    "cost_usd",
    "cost_per_1000_input_chars",  # char-normalized — fair across providers
    # Efficacy (filled by scorer when ground truth exists)
    "schema_valid",
    "efficacy_score",
    "fields_passed",
    "fields_failed",
    "hallucinated",
    "efficacy_reason",
    # Failure breakdown
    "retries",
    "failure_mode",
    "error",
]


# Agent → scorer function. One scorer per agent.
_SCORER_BY_AGENT = {
    "sa1": score_sa1,  # exact-match vs auto-labeled ground truth
    "sa2": score_sa2,  # LLM-judge rubric (grounding, actionability, hallucination)
    "sa3": score_sa3,  # LLM-judge rubric (concrete commands, rescan, safety, addresses)
    "sa4": score_sa4,  # adversarial safety (destructive-command catch rate)
    "master": score_master,  # LLM-judge (pipeline coverage, order, summary match)
}


def _append_row(path: Path, row: dict, agent: str) -> None:
    file_exists = path.exists()
    columns = _CSV_COLUMNS + _EXTRA_COLUMNS_BY_AGENT.get(agent, [])
    with path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LLM benchmark harness")
    parser.add_argument("--agent", required=True, choices=sorted(_AGENT_RUNNERS.keys()))
    parser.add_argument("--model", required=True, help="Model name (e.g. gpt-4o-mini)")
    parser.add_argument(
        "--runs", type=int, default=1, help="Repeat each fixture N times"
    )
    parser.add_argument(
        "--scanner", default=None, help="Only run fixtures for this scanner"
    )
    parser.add_argument(
        "--fixtures-dir",
        default=None,
        help="Fixtures directory (default: fixtures/raw/). "
        "Use fixtures/success/ for success-only pool.",
    )
    parser.add_argument(
        "--scorecard-suffix",
        default="",
        help="Append to scorecard filename, e.g. '_success' → sa1_gpt-4o-mini_success.csv",
    )
    args = parser.parse_args(argv)

    if args.model not in BY_NAME:
        print(f"⚠ Model '{args.model}' not in registry — cost will be 0.0 in scorecard")

    fx_dir = Path(args.fixtures_dir).resolve() if args.fixtures_dir else None
    fixtures = _load_fixtures(
        agent=args.agent, scanner_filter=args.scanner, fixtures_dir=fx_dir
    )
    if not fixtures:
        print(
            f"✗ No fixtures found for agent={args.agent} in {fx_dir or _FIXTURES_DIR}"
        )
        return 1

    runner_fn = _AGENT_RUNNERS[args.agent]
    safe_model = args.model.replace("/", "_").replace(":", "_")
    out_path = _SCORECARDS_DIR / f"{args.agent}_{safe_model}{args.scorecard_suffix}.csv"
    _SCORECARDS_DIR.mkdir(parents=True, exist_ok=True)
    print(
        f"▶ Running {args.agent} × {args.model} on {len(fixtures)} fixture(s), {args.runs} run(s) each"
    )
    print(f"  Scorecard: {out_path}")

    total_calls = 0
    successes = 0
    for fixture in fixtures:
        for run_n in range(1, args.runs + 1):
            # Use a real UUID — the _TokenUsageCallback tries to insert it as
            # a trace row and errors (cosmetically) if it isn't a valid UUID.
            run_id = str(uuid.uuid4())
            # SA-1 fixtures carry `raw`; SA-2 carry `input`. Both are passed
            # through — unused ones are ignored by the runner wrapper.
            result = runner_fn(
                run_id=run_id,
                model=args.model,
                raw_finding=fixture.get("raw", {}),
                scanner=fixture["scanner"],
                **({"fixture_input": fixture["input"]} if "input" in fixture else {}),
            )
            # Real cost from accumulated token counts (populated by the
            # callback inside get_chat_llm).
            raw_cost = cost_usd(
                args.model,
                result.get("prompt_tokens", 0),
                result.get("completion_tokens", 0),
            )
            chars = result.get("input_chars", 0)
            cost_per_1k_chars = round((raw_cost / chars * 1000), 6) if chars else 0.0

            # Score the output if a scorer is wired for this agent.
            scorer = _SCORER_BY_AGENT.get(args.agent)
            if scorer:
                score_row = scorer(fixture["fixture_id"], result.get("output"))
            else:
                score_row = {
                    "efficacy_score": None,
                    "fields_passed": "",
                    "fields_failed": "",
                    "hallucinated": None,
                    "efficacy_reason": "no_scorer_wired",
                }

            row = {
                **result,
                **score_row,
                "run_timestamp": datetime.now(UTC).isoformat(),
                "fixture_id": fixture["fixture_id"],
                "run_n": run_n,
                "cost_usd": round(raw_cost, 6),
                "cost_per_1000_input_chars": cost_per_1k_chars,
            }
            _append_row(out_path, row, args.agent)
            total_calls += 1
            if result["schema_valid"]:
                successes += 1
            status = (
                "✓" if result["schema_valid"] else f"✗ {result.get('failure_mode')}"
            )
            print(
                f"  [{run_n}/{args.runs}] fixture {fixture['fixture_id']} ({fixture['scanner']}): {status} — {result['latency_ms']}ms"
            )

    print(
        f"\n▶ Done: {successes}/{total_calls} calls succeeded. Scorecard appended → {out_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
