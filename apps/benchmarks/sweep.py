"""Baseline sweep — run every agent against every applicable fixture, N
runs each, with a chosen model. Writes scorecard CSVs + runs the rollup.

This is the "establish the OpenAI baseline" command. Repeat with different
--model values when Anthropic / Gemini keys arrive to produce cross-provider
comparison tables.

Usage:
    cd apps/api
    # Full OpenAI baseline sweep (uses the default models.py tier assignment):
    PYTHONPATH=../.. uv run python -m apps.benchmarks.sweep

    # Specific model override (same model for every agent — comparison runs):
    PYTHONPATH=../.. uv run python -m apps.benchmarks.sweep --model claude-haiku-4-5 --agents sa1,sa2

    # Narrow to a few agents:
    PYTHONPATH=../.. uv run python -m apps.benchmarks.sweep --agents sa1,sa4
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).parent.parent.parent

# Default model per agent for the OpenAI baseline sweep. Edit here or pass
# --model to override uniformly.
_DEFAULT_MODELS = {
    "sa1": "gpt-4o-mini",
    "sa2": "gpt-4o-mini",
    "sa3": "gpt-4o",  # agentic tool-calling loop
    "sa4": "gpt-4o",
    "master": "gpt-4o",
}


def _run(cmd: list[str]) -> int:
    print(f"\n$ {' '.join(cmd)}")
    return subprocess.call(cmd, cwd=_REPO_ROOT / "apps" / "api")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Full OpenAI baseline sweep")
    parser.add_argument(
        "--agents",
        default=",".join(_DEFAULT_MODELS.keys()),
        help=f"Which agents to run (default: {','.join(_DEFAULT_MODELS.keys())})",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override the model used for every agent (default: per-agent default from models.py)",
    )
    parser.add_argument("--runs", type=int, default=1)
    args = parser.parse_args(argv)

    agents = [a.strip() for a in args.agents.split(",") if a.strip()]
    print(f"▶ Baseline sweep: agents={agents}, runs={args.runs}")

    exit_codes: list[int] = []
    for agent in agents:
        model = args.model or _DEFAULT_MODELS.get(agent) or "gpt-4o-mini"
        rc = _run(
            [
                "uv",
                "run",
                "python",
                "-m",
                "apps.benchmarks.runner",
                "--agent",
                agent,
                "--model",
                model,
                "--runs",
                str(args.runs),
            ]
        )
        exit_codes.append(rc)

    # Always run rollup at the end so you get the summary table.
    print("\n═══ ROLLUP ═══")
    _run(["uv", "run", "python", "-m", "apps.benchmarks.rollup"])

    print(
        f"\n▶ Sweep done. agent exit codes: "
        f"{dict(zip(agents, exit_codes, strict=False))}"
    )
    return 0 if all(c == 0 for c in exit_codes) else 1


if __name__ == "__main__":
    sys.exit(main())
