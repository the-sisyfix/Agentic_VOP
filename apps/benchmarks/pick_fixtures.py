"""Interactive fixture-picker — pulls real -ec2 raw_findings from
Supabase and lets you pin 3 per scanner (adjustable to 5 later).

Usage:
    cd apps/api
    PYTHONPATH=../.. uv run python -m apps.benchmarks.pick_fixtures
    PYTHONPATH=../.. uv run python -m apps.benchmarks.pick_fixtures --per-scanner 5
    PYTHONPATH=../.. uv run python -m apps.benchmarks.pick_fixtures --scanners trivy-image-ec2,checkov-ec2

For each scanner it shows up to 15 candidate findings with their id, check_id
/ CVE, and short title. You pick N indices. The script writes each picked
finding as a SA-1 fixture under fixtures/raw/.

Day-1 scope: picks SA-1 fixtures only (raw_findings). SA-2/SA-3/SA-4 fixtures
are a separate step — they need the normalized/enriched/planned forms of
the SAME findings and can be derived by running the production pipeline on
the pinned raws, then snapshotting the intermediate rows.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from apps.api.app.db import supabase_admin


_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "raw"


# -ec2 scanner sources we want coverage of. Trimmed version of the full
# scanner catalogue — add/remove as the product grows.
_DEFAULT_SCANNERS = [
    "trivy-image-ec2",
    "checkov-ec2",
    "trivy-fs-ec2",
    "trivy-os-ec2",
    "trivy-image-python-ec2",
    "trivy-image-java-ec2",
    "semgrep-ec2",
    "serverless-ec2",
]


def _label_for_raw(raw: dict) -> str:
    """Pull a human-readable one-liner from the raw payload — tries common
    fields across scanner shapes including nested Vulnerability dicts."""
    if not isinstance(raw, dict):
        return "(unparseable raw)"
    vuln = (
        raw.get("Vulnerability") if isinstance(raw.get("Vulnerability"), dict) else {}
    )
    # CVE-shaped — root OR nested Vulnerability dict (snake_case + CamelCase)
    cve = (
        raw.get("vuln_id")
        or raw.get("VulnerabilityID")
        or raw.get("cve_id")
        or raw.get("vulnerability_id")
        or vuln.get("VulnerabilityID")
        or vuln.get("cve_id")
    )
    pkg = (
        raw.get("pkg_name")
        or raw.get("PkgName")
        or raw.get("package_name")
        or vuln.get("PkgName")
    )
    title = raw.get("Title") or raw.get("title") or vuln.get("Title")
    # Checkov / semgrep-shaped
    check = raw.get("check_id") or raw.get("rule_id") or raw.get("CheckID")
    resource = raw.get("resource") or raw.get("file_path")
    severity = (
        raw.get("Severity")
        or raw.get("severity")
        or raw.get("level")
        or vuln.get("Severity")
    )

    bits: list[str] = []
    if cve:
        bits.append(str(cve))
    if check:
        bits.append(str(check))
    if pkg:
        bits.append(f"pkg={pkg}")
    if resource:
        bits.append(f"on={str(resource)[:40]}")
    if severity:
        bits.append(f"[{severity}]")
    label = " · ".join(bits) or (
        str(title)[:60] if title else "(no identifiable fields)"
    )
    return label[:100]


def _slug_for_fixture(scanner: str, finding_id: int, raw: dict) -> str:
    """Short slug for the fixture filename."""
    cve = (
        raw.get("vuln_id")
        or raw.get("VulnerabilityID")
        or raw.get("cve_id")
        or raw.get("check_id")
        or raw.get("rule_id")
        or ""
    )
    cve_slug = str(cve).lower().replace("_", "-").replace("/", "-")[:30] or "finding"
    return f"{scanner}-{cve_slug}-{finding_id}"


def _unique_key(raw: dict, finding_id: int) -> str:
    """Return a dedupe key for a finding — the check_id / CVE / rule_id.

    Two findings with the same key are treated as "the same variation"
    for coverage purposes. Falls back to the raw id (always unique) when
    no identifying field is found — so unparseable rows aren't collapsed.
    """
    if not isinstance(raw, dict):
        return f"id:{finding_id}"
    vuln = (
        raw.get("Vulnerability") if isinstance(raw.get("Vulnerability"), dict) else {}
    )
    key = (
        raw.get("vuln_id")
        or raw.get("VulnerabilityID")
        or raw.get("cve_id")
        or raw.get("vulnerability_id")
        or vuln.get("VulnerabilityID")
        or raw.get("check_id")
        or raw.get("CheckID")
        or raw.get("rule_id")
        or raw.get("Title")
        or raw.get("title")
        or vuln.get("Title")
    )
    return str(key)[:80] if key else f"id:{finding_id}"


def _list_candidates(
    sb, scanner: str, limit: int = 15, dedupe: bool = True
) -> list[dict]:
    """Grab recent raw_findings for this scanner.

    When `dedupe=True`, returns at most ONE candidate per unique
    check_id/CVE — so showing 15 candidates == 15 different variations
    (not 15 copies of the same CVE). Scanning fetches more rows upstream
    (4× limit) so the deduped slice is still `limit` long.
    """
    fetch_cap = limit * 4 if dedupe else limit
    try:
        resp = (
            sb.table("raw_findings")
            .select("id, source, raw, fetched_at")
            .eq("source", scanner)
            .order("fetched_at", desc=True)
            .limit(fetch_cap)
            .execute()
        )
        rows = resp.data or []
    except Exception as e:  # noqa: BLE001
        print(f"  ✗ failed to query {scanner}: {type(e).__name__}: {str(e)[:120]}")
        return []

    if not dedupe:
        return rows[:limit]

    seen: dict[str, dict] = {}
    duplicate_counts: dict[str, int] = {}
    for row in rows:
        key = _unique_key(row.get("raw") or {}, int(row["id"]))
        duplicate_counts[key] = duplicate_counts.get(key, 0) + 1
        if key not in seen:
            seen[key] = row
        if len(seen) >= limit:
            # Keep counting duplicates for the ones already picked
            continue
    # Stash the duplicate count on each row so the label shows "×N similar"
    for key, row in seen.items():
        row["_dupe_count"] = duplicate_counts[key]
    return list(seen.values())


def _pick_from_candidates(candidates: list[dict], per_scanner: int) -> list[dict]:
    """Interactive loop — prompt user to pick N by index."""
    if not candidates:
        print("  (no findings found for this scanner — skipping)")
        return []
    print(f"\n  Candidates ({len(candidates)} unique variations):")
    for i, row in enumerate(candidates):
        label = _label_for_raw(row.get("raw") or {})
        dupes = row.get("_dupe_count", 1)
        suffix = f"  (×{dupes} similar)" if dupes > 1 else ""
        print(f"    [{i:>2}]  id={row['id']}  {label}{suffix}")

    while True:
        raw_input_str = input(
            f"  Pick {per_scanner} indices (comma-separated), or 'skip', or 'all': "
        ).strip()
        if raw_input_str.lower() == "skip":
            return []
        if raw_input_str.lower() == "all":
            return candidates[:per_scanner]
        try:
            indices = [int(x.strip()) for x in raw_input_str.split(",") if x.strip()]
        except ValueError:
            print("  ✗ invalid input — comma-separated integers please")
            continue
        if not all(0 <= i < len(candidates) for i in indices):
            print(f"  ✗ indices must be in [0, {len(candidates) - 1}]")
            continue
        if len(indices) == 0:
            print("  ✗ pick at least one")
            continue
        return [candidates[i] for i in indices]


def _write_fixture(scanner: str, row: dict) -> Path:
    """Write one picked finding as a SA-1 fixture JSON."""
    _FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    raw = row.get("raw") or {}
    fixture_id = _slug_for_fixture(scanner, int(row["id"]), raw)
    path = _FIXTURES_DIR / f"{fixture_id}.json"
    payload = {
        "fixture_id": fixture_id,
        "scanner": scanner,
        "source_raw_finding_id": int(row["id"]),
        "pinned_at": row.get("fetched_at"),
        "notes": "Pinned by pick_fixtures.py — do not edit raw by hand.",
        "raw": raw,
    }
    with path.open("w") as f:
        json.dump(payload, f, indent=2, default=str)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pin real -ec2 findings as SA-1 fixtures"
    )
    parser.add_argument(
        "--per-scanner",
        type=int,
        default=3,
        help="How many findings to pin per scanner (default 3; bump to 5 if coverage feels thin)",
    )
    parser.add_argument(
        "--scanners",
        default=",".join(_DEFAULT_SCANNERS),
        help=f"Comma-separated scanner sources (default: {','.join(_DEFAULT_SCANNERS)})",
    )
    parser.add_argument(
        "--candidates",
        type=int,
        default=15,
        help="How many unique variations to show per scanner (default 15)",
    )
    parser.add_argument(
        "--no-dedupe",
        action="store_true",
        help="Show raw findings including duplicates (default: dedupe by check_id/CVE)",
    )
    args = parser.parse_args(argv)

    scanners = [s.strip() for s in args.scanners.split(",") if s.strip()]
    sb = supabase_admin()
    print(
        f"▶ Fixture-picker: pinning {args.per_scanner} per scanner across {len(scanners)} scanner(s)"
    )
    print(f"  Writing to: {_FIXTURES_DIR}")

    total_pinned = 0
    for scanner in scanners:
        print(f"\n━━━ {scanner} ━━━")
        candidates = _list_candidates(
            sb, scanner, limit=args.candidates, dedupe=not args.no_dedupe
        )
        if not candidates:
            continue
        picked = _pick_from_candidates(candidates, args.per_scanner)
        for row in picked:
            path = _write_fixture(scanner, row)
            print(f"  ✓ wrote {path.name}")
            total_pinned += 1

    print(f"\n▶ Done. {total_pinned} fixture(s) pinned under {_FIXTURES_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
