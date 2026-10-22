"""Pick success-only fixtures for the benchmark.

Queries demo.fix_runs where status='success', traces back through
remediation_packages → issues → raw_findings, and pins N diverse ones
per scanner.

For each picked finding, writes 4 fixtures + 1 ground truth file:
  fixtures/success/sa1/{slug}.json       — raw finding (SA-1 input)
  fixtures/success/sa2/{slug}.json       — normalized issue + enrichment (SA-2 input)
  fixtures/success/sa3/{slug}.json       — enriched issue + asset + family (SA-3 input)
  fixtures/success/sa4/{slug}.json       — pathway + snapshot + issue (SA-4 input)
  ground_truth/sa1_success/{slug}.json   — SA-1 expected output (auto-derived from raw)

Picks the FIRST N candidates per scanner, deduplicated by check_id / CVE
(so you get variety, not 3 copies of CVE-2022-0778).

Usage:
    cd apps/api
    PYTHONPATH=../.. uv run python -m apps.benchmarks.pick_success_fixtures
    PYTHONPATH=../.. uv run python -m apps.benchmarks.pick_success_fixtures --per-scanner 5
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from apps.api.app.db import supabase_admin, supabase_admin_demo
from apps.benchmarks.auto_label_sa1 import _extract_expected as _sa1_expected
from apps.benchmarks.derive_fixtures import _derive_sa2, _derive_sa3, _derive_sa4
from apps.benchmarks.pick_fixtures import _slug_for_fixture, _unique_key


_BENCH = Path(__file__).parent
_FX_DIR = _BENCH / "fixtures" / "success"
_GT_DIR = _BENCH / "ground_truth" / "sa1_success"


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(payload, f, indent=2, default=str)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pin success-only fixtures from demo DB"
    )
    parser.add_argument("--per-scanner", type=int, default=3)
    args = parser.parse_args(argv)

    sb_d = supabase_admin_demo()
    sb_p = supabase_admin()

    # 1. All success fix_runs
    frs = (
        sb_d.table("fix_runs")
        .select("id, package_id")
        .eq("status", "success")
        .limit(1000)
        .execute()
        .data
        or []
    )
    pkg_ids = list({fr["package_id"] for fr in frs if fr.get("package_id")})
    if not pkg_ids:
        print("No success fix_runs found in demo schema. Trigger a UI run first.")
        return 1

    # 2. Chain back: packages → issues → raws
    pkgs_by_id: dict[int, dict] = {}
    for chunk_start in range(0, len(pkg_ids), 50):
        chunk = pkg_ids[chunk_start : chunk_start + 50]
        rows = (
            sb_d.table("remediation_packages")
            .select("*")
            .in_("id", chunk)
            .execute()
            .data
            or []
        )
        for p in rows:
            pkgs_by_id[int(p["id"])] = p

    issue_ids = list({p["issue_id"] for p in pkgs_by_id.values() if p.get("issue_id")})
    issues_by_id: dict[int, dict] = {}
    for chunk_start in range(0, len(issue_ids), 50):
        chunk = issue_ids[chunk_start : chunk_start + 50]
        rows = sb_d.table("issues").select("*").in_("id", chunk).execute().data or []
        for i in rows:
            issues_by_id[int(i["id"])] = i

    raw_ids = list(
        {i["raw_finding_id"] for i in issues_by_id.values() if i.get("raw_finding_id")}
    )
    raws_by_id: dict[int, dict] = {}
    for chunk_start in range(0, len(raw_ids), 50):
        chunk = raw_ids[chunk_start : chunk_start + 50]
        rows = (
            sb_p.table("raw_findings").select("*").in_("id", chunk).execute().data or []
        )
        for r in rows:
            raws_by_id[int(r["id"])] = r

    # 3. Group by scanner, dedupe by check_id/CVE, pick N per scanner
    by_scanner: dict[str, list[tuple[dict, dict, dict]]] = {}  # (issue, raw, package)
    seen_keys_per_scanner: dict[str, set] = {}
    # Prefer the package with the most recent (highest id) fix_run per (scanner, key)
    for pkg_id in sorted(pkgs_by_id.keys(), reverse=True):  # newest-first
        pkg = pkgs_by_id[pkg_id]
        issue = issues_by_id.get(int(pkg["issue_id"]))
        if not issue or not issue.get("raw_finding_id"):
            continue
        raw = raws_by_id.get(int(issue["raw_finding_id"]))
        if not raw:
            continue
        scanner = issue.get("source") or "unknown"
        key = _unique_key(raw.get("raw") or {}, int(raw["id"]))
        seen = seen_keys_per_scanner.setdefault(scanner, set())
        if key in seen:
            continue
        seen.add(key)
        by_scanner.setdefault(scanner, []).append((issue, raw, pkg))

    # 4. Pick N per scanner and write all 4 fixture forms + ground truth
    total = 0
    for scanner, bucket in sorted(by_scanner.items()):
        picked = bucket[: args.per_scanner]
        print(
            f"\n━━━ {scanner} ━━━ ({len(bucket)} unique success candidates, pinning {len(picked)})"
        )
        for issue, raw, pkg in picked:
            slug = _slug_for_fixture(scanner, int(raw["id"]), raw.get("raw") or {})
            sa1 = {
                "fixture_id": slug,
                "scanner": scanner,
                "agent": "sa1",
                "source_raw_finding_id": int(raw["id"]),
                "notes": "Success-chain pinned by pick_success_fixtures.py",
                "raw": raw.get("raw") or {},
            }
            _write(_FX_DIR / "sa1" / f"{slug}.json", sa1)
            _write(
                _GT_DIR / f"{slug}.json",
                {
                    "fixture_id": slug,
                    "notes": "Auto-derived from raw payload.",
                    "expected": _sa1_expected(scanner, raw.get("raw") or {}),
                },
            )
            sa2 = _derive_sa2({"fixture_id": slug, "scanner": scanner}, issue)
            sa2["fixture_id"] = f"{slug}-sa2"
            _write(_FX_DIR / "sa2" / f"{slug}-sa2.json", sa2)
            sa3 = _derive_sa3({"fixture_id": slug, "scanner": scanner}, issue, {})
            sa3["fixture_id"] = f"{slug}-sa3"
            _write(_FX_DIR / "sa3" / f"{slug}-sa3.json", sa3)
            sa4 = _derive_sa4({"fixture_id": slug, "scanner": scanner}, issue, pkg)
            sa4["fixture_id"] = f"{slug}-sa4"
            _write(_FX_DIR / "sa4" / f"{slug}-sa4.json", sa4)
            print(f"  ✓ {slug}")
            total += 1

    print(
        f"\n▶ Done. {total} success-chain fixtures pinned (4 agent forms + SA-1 ground truth each)"
    )
    print(f"  Fixtures:    {_FX_DIR}")
    print(f"  Ground truth:{_GT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
