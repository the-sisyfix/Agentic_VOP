"""Compare pipeline scorecards across providers.

Reads one `pipeline_*_per_scanner_N.csv` per provider and emits the six-section
Nikhil-style comparison table (Efficacy, Performance, Cost, Normalized Cost,
SA-3 Tool Use, Tokens).

Default behavior: auto-pick the newest `pipeline_openai|gemini|claude*.csv`
from `apps/benchmarks/scorecards/`. Override with --openai/--gemini/--claude.

Usage:
    cd apps/benchmarks && PYTHONPATH=../.. uv run python -m apps.benchmarks.compare_pipeline

    # Pin to specific files:
    PYTHONPATH=../.. uv run python -m apps.benchmarks.compare_pipeline \\
        --openai scorecards/pipeline_openai_per_scanner_3.csv \\
        --gemini scorecards/pipeline_gemini_per_scanner_3.csv \\
        --claude scorecards/pipeline_claude_per_scanner_3.csv \\
        --out scorecards/COMPARISON.md
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from statistics import mean

_SCORECARDS = Path(__file__).parent / "scorecards"
AGENTS = ["master1", "sa1", "master2", "sa2", "master3", "sa3", "master4", "sa4"]


def _fnum(x: str, d: float = 0.0) -> float:
    try:
        return float(x)
    except (ValueError, TypeError):
        return d


def _newest(pattern: str) -> Path | None:
    """Return the most recently modified file matching the glob, or None."""
    matches = sorted(
        _SCORECARDS.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True
    )
    return matches[0] if matches else None


def _load(path: Path) -> dict:
    """Read a pipeline scorecard CSV and compute all aggregates."""
    with path.open() as f:
        rows = list(csv.DictReader(f))
    n = len(rows)
    if n == 0:
        return {"n": 0}

    chain_ok = sum(1 for r in rows if r["final_output_valid"] == "True")
    rescan = sum(1 for r in rows if r["sandbox_rescan_verified"] == "True")
    rolled = sum(1 for r in rows if r["sandbox_rolled_back"] == "True")
    sand_fail = sum(1 for r in rows if r["sandbox_terminal_status"] == "failed")
    tot_cost = sum(_fnum(r["total_cost"]) for r in rows)
    tot_ms = sum(
        _fnum(r["total_ms"]) for r in rows if r["final_output_valid"] == "True"
    )

    agent_ms: dict[str, list[float]] = {a: [] for a in AGENTS}
    agent_cost: dict[str, list[float]] = {a: [] for a in AGENTS}
    agent_chars: dict[str, list[float]] = {a: [] for a in AGENTS}
    agent_pt: dict[str, list[float]] = {a: [] for a in AGENTS}
    agent_ct: dict[str, list[float]] = {a: [] for a in AGENTS}
    for r in rows:
        for a in AGENTS:
            if r.get(f"{a}_ok") == "True":
                agent_ms[a].append(_fnum(r.get(f"{a}_ms", "")))
                agent_cost[a].append(_fnum(r.get(f"{a}_cost", "")))
                agent_chars[a].append(_fnum(r.get(f"{a}_input_chars", "")))
                agent_pt[a].append(_fnum(r.get(f"{a}_prompt_tokens", "")))
                agent_ct[a].append(_fnum(r.get(f"{a}_completion_tokens", "")))

    sa3_calls = [
        _fnum(r.get("sa3_tool_calls", "")) for r in rows if r.get("sa3_tool_calls")
    ]
    sa3_tool_cost = [
        _fnum(r.get("sa3_tool_cost", "")) for r in rows if r.get("sa3_tool_cost")
    ]

    return {
        "n": n,
        "chain": chain_ok,
        "rescan": rescan,
        "rolled": rolled,
        "sand_fail": sand_fail,
        "tot_cost": tot_cost,
        "tot_ms": tot_ms,
        "mean_cost": tot_cost / max(chain_ok, 1),
        "mean_latency_s": tot_ms / max(chain_ok, 1) / 1000,
        "agent_ms": agent_ms,
        "agent_cost": agent_cost,
        "agent_chars": agent_chars,
        "agent_pt": agent_pt,
        "agent_ct": agent_ct,
        "sa3_tc_mean": mean(sa3_calls) if sa3_calls else 0.0,
        "sa3_tool_cost_sum": sum(sa3_tool_cost),
    }


def _emit_markdown(stacks: dict[str, dict], out: list[str]) -> None:
    """Append the six-section markdown comparison to `out` (list of lines)."""
    names = list(stacks.keys())
    header = "| Metric | " + " | ".join(names) + " |"
    sep = "|---" * (len(names) + 1) + "|"
    n_values = {s: stacks[s]["n"] for s in names}
    n_sample = max(n_values.values()) if n_values else 0

    out.append(f"# 3-way comparison — {n_sample} fixtures per provider\n")
    out.append(f"Sample sizes: {', '.join(f'{s}={n_values[s]}' for s in names)}\n")

    # 1. Efficacy
    out.append("\n## 1. EFFICACY\n")
    out.append(header)
    out.append(sep)
    for label, k in [
        ("Pipeline chain success", "chain"),
        ("Sandbox RESCAN VERIFIED", "rescan"),
        ("Sandbox rolled_back", "rolled"),
        ("Sandbox failed", "sand_fail"),
    ]:
        cells = []
        for s in names:
            v = stacks[s][k]
            tot = stacks[s]["n"]
            cells.append(f"{v}/{tot} ({100 * v / max(tot, 1):.0f}%)")
        out.append(f"| {label} | " + " | ".join(cells) + " |")

    # 2. Performance
    out.append("\n## 2. PERFORMANCE — mean seconds per agent (successful chains)\n")
    out.append("| Agent | " + " | ".join(names) + " |")
    out.append(sep)
    for a in AGENTS:
        cells = []
        for s in names:
            ms = stacks[s]["agent_ms"][a]
            cells.append(f"{mean(ms) / 1000:.1f}" if ms else "—")
        out.append(f"| {a} | " + " | ".join(cells) + " |")
    cells = [f"**{stacks[s]['mean_latency_s']:.1f}**" for s in names]
    out.append("| **TOTAL mean per chain** | " + " | ".join(cells) + " |")

    # 3. Cost
    out.append(f"\n## 3. COST — raw $ (sum across {n_sample} fixtures)\n")
    out.append("| Agent | " + " | ".join(names) + " |")
    out.append(sep)
    for a in AGENTS:
        cells = []
        for s in names:
            c = stacks[s]["agent_cost"][a]
            cells.append(f"${sum(c):.4f}" if c else "—")
        out.append(f"| {a} | " + " | ".join(cells) + " |")
    cells = [f"${stacks[s]['sa3_tool_cost_sum']:.4f}" for s in names]
    out.append("| sa3_tool_cost (Tavily) | " + " | ".join(cells) + " |")
    cells = [f"**${stacks[s]['tot_cost']:.4f}**" for s in names]
    out.append("| **TOTAL $** | " + " | ".join(cells) + " |")
    cells = [f"**${stacks[s]['mean_cost']:.4f}**" for s in names]
    out.append("| **Mean $ / chain** | " + " | ".join(cells) + " |")

    # 4. Normalized cost
    out.append("\n## 4. COST per 1k input chars (normalized)\n")
    out.append("| Agent | " + " | ".join(names) + " |")
    out.append(sep)
    for a in AGENTS:
        cells = []
        for s in names:
            chars = stacks[s]["agent_chars"][a]
            cost = stacks[s]["agent_cost"][a]
            if chars and sum(chars) > 0:
                cells.append(f"${(sum(cost) / sum(chars)) * 1000:.5f}")
            else:
                cells.append("—")
        out.append(f"| {a} | " + " | ".join(cells) + " |")

    # 5. SA-3 tool use
    out.append("\n## 5. AGENT-SPECIFIC: SA-3 Tool Use\n")
    out.append("| Metric | " + " | ".join(names) + " |")
    out.append(sep)
    cells = [f"{stacks[s]['sa3_tc_mean']:.1f}" for s in names]
    out.append("| Mean SA-3 tool calls / run | " + " | ".join(cells) + " |")

    # 6. Tokens
    out.append(
        f"\n## 6. TOKEN TOTALS ({n_sample} fixtures, prompt / completion in k)\n"
    )
    out.append("| Agent | " + " | ".join(names) + " |")
    out.append(sep)
    for a in AGENTS:
        cells = []
        for s in names:
            p = stacks[s]["agent_pt"][a]
            c = stacks[s]["agent_ct"][a]
            if p:
                cells.append(f"{int(sum(p) / 1000)}k / {int(sum(c) / 1000)}k")
            else:
                cells.append("—")
        out.append(f"| {a} | " + " | ".join(cells) + " |")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--openai",
        type=Path,
        help="OpenAI scorecard path (default: newest pipeline_openai*.csv)",
    )
    p.add_argument(
        "--gemini",
        type=Path,
        help="Gemini scorecard path (default: newest pipeline_gemini*.csv)",
    )
    p.add_argument(
        "--claude",
        type=Path,
        help="Claude scorecard path (default: newest pipeline_claude*.csv)",
    )
    p.add_argument("--out", type=Path, help="Also write markdown to this path")
    args = p.parse_args()

    picks = {
        "OpenAI": args.openai
        or _newest("pipeline_openai*per_scanner*.csv")
        or _newest("pipeline_openai*.csv"),
        "Gemini": args.gemini
        or _newest("pipeline_gemini*per_scanner*.csv")
        or _newest("pipeline_gemini*.csv"),
        "Claude": args.claude
        or _newest("pipeline_claude*per_scanner*.csv")
        or _newest("pipeline_claude*.csv"),
    }

    missing = [k for k, v in picks.items() if v is None or not Path(v).exists()]
    if missing:
        print(f"ERROR: no scorecard found for: {', '.join(missing)}", file=sys.stderr)
        print(f"Searched in: {_SCORECARDS}", file=sys.stderr)
        return 1

    print("Using scorecards:")
    for name, path in picks.items():
        print(f"  {name}: {path.name}")
    print()

    stacks = {name: _load(Path(path)) for name, path in picks.items()}

    lines: list[str] = []
    _emit_markdown(stacks, lines)
    text = "\n".join(lines) + "\n"
    print(text)

    if args.out:
        args.out.write_text(text)
        print(f"\nWrote markdown to: {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
