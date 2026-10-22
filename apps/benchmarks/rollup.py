"""Rollup script — aggregate scorecard CSVs into per-(agent, model) summaries.

Reads every CSV under scorecards/ and emits one summary row per (agent, model)
with p50/p95 latency, mean cost, mean char-normalized cost, success rate,
mean efficacy, failure-mode counts. Prints a table to stdout and writes
`scorecards/_summary.csv` for spreadsheet comparison.

Usage:
    PYTHONPATH=../.. uv run python -m apps.benchmarks.rollup
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path
from statistics import mean


_SCORECARDS_DIR = Path(__file__).parent / "scorecards"


def _percentile(values: list[float], pct: float) -> float:
    """Simple percentile (no numpy)."""
    if not values:
        return 0.0
    s = sorted(values)
    k = int(round((len(s) - 1) * pct))
    return s[k]


def _summarize_file(path: Path) -> dict | None:
    """Read one scorecard CSV, return a summary dict (or None if empty)."""
    with path.open() as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return None

    latencies = [float(r["latency_ms"]) for r in rows if r.get("latency_ms")]
    costs = [float(r["cost_usd"]) for r in rows if r.get("cost_usd")]
    cost_per_1k_chars = [
        float(r["cost_per_1000_input_chars"])
        for r in rows
        if r.get("cost_per_1000_input_chars")
    ]
    efficacy = [
        float(r["efficacy_score"])
        for r in rows
        if r.get("efficacy_score") not in (None, "", "None")
    ]
    schema_ok = sum(1 for r in rows if str(r.get("schema_valid")).lower() == "true")

    failure_counts: dict[str, int] = defaultdict(int)
    for r in rows:
        fm = r.get("failure_mode") or ""
        if fm:
            failure_counts[fm] += 1

    total_wall_time_s = sum(latencies) / 1000.0
    throughput_per_min = (
        (len(rows) / total_wall_time_s * 60) if total_wall_time_s else 0.0
    )

    return {
        "agent": rows[0]["agent"]
        if rows[0].get("agent")
        else path.stem.split("_", 1)[0],
        "model": rows[0]["model"],
        "scorecard": path.name,
        "n_runs": len(rows),
        "success_rate": round(schema_ok / len(rows), 3),
        "latency_p50_ms": int(_percentile(latencies, 0.50)),
        "latency_p95_ms": int(_percentile(latencies, 0.95)),
        "latency_mean_ms": int(mean(latencies)) if latencies else 0,
        "throughput_per_min_serial": round(throughput_per_min, 2),
        "mean_cost_usd": round(mean(costs), 6) if costs else 0.0,
        "mean_cost_per_1k_chars": round(mean(cost_per_1k_chars), 6)
        if cost_per_1k_chars
        else 0.0,
        "mean_efficacy_score": round(mean(efficacy), 3) if efficacy else None,
        "failure_modes": ";".join(
            f"{k}={v}" for k, v in sorted(failure_counts.items())
        ),
    }


def main() -> int:
    if not _SCORECARDS_DIR.exists():
        print("No scorecards/ directory yet. Run the harness first.")
        return 1

    summaries: list[dict] = []
    for csv_path in sorted(_SCORECARDS_DIR.glob("*.csv")):
        if csv_path.stem.startswith("_"):
            continue  # skip the summary CSV itself
        s = _summarize_file(csv_path)
        if s:
            summaries.append(s)

    if not summaries:
        print("No scorecard CSVs found under scorecards/.")
        return 1

    # Print table
    print("\n═══ BENCHMARK SUMMARY ═══\n")
    for s in summaries:
        print(
            f"  {s['agent']:<12} {s['model']:<22} runs={s['n_runs']:>3}  "
            f"success={s['success_rate']:.0%}  "
            f"p50={s['latency_p50_ms']}ms  p95={s['latency_p95_ms']}ms  "
            f"${s['mean_cost_usd']:.5f}/call  "
            f"${s['mean_cost_per_1k_chars']:.6f}/1k-chars  "
            f"efficacy={s['mean_efficacy_score']}"
        )
    print()

    # Write summary CSV
    out_path = _SCORECARDS_DIR / "_summary.csv"
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(summaries[0].keys()))
        writer.writeheader()
        for s in summaries:
            writer.writerow(s)
    print(f"▶ Summary written → {out_path}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
