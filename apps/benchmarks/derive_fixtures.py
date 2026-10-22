"""Derive SA-2 / SA-3 / SA-4 fixtures from the 24 pinned SA-1 raws.

For each raw_findings row we pinned (fixtures/raw/*.json with scanner=
<real-scanner>), look up the corresponding downstream rows in Supabase:

  SA-2 input  = already-normalized `issues` row + any available enrichment
                (we snapshot EPSS/NVD/MITRE/asset/scoring as-is from the row)
  SA-3 input  = enriched issue + resolved asset + inferred family
  SA-4 input  = latest `remediation_packages` row for the issue + a sketched
                env2 snapshot (we don't require a live snapshot — the fixture
                just needs the shape SA-4's pre-flight LLM expects)

Writes derived fixtures as:
    fixtures/raw/{original_fixture_id}-sa2.json
    fixtures/raw/{original_fixture_id}-sa3.json
    fixtures/raw/{original_fixture_id}-sa4.json

Skips fixtures where the downstream row doesn't exist (that finding never
reached that stage in the real pipeline — expected for unprocessed ones).

Usage:
    cd apps/api
    PYTHONPATH=../.. uv run python -m apps.benchmarks.derive_fixtures
    PYTHONPATH=../.. uv run python -m apps.benchmarks.derive_fixtures --overwrite
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from apps.api.app.db import supabase_admin


_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "raw"


def _load_sa1_fixtures() -> list[dict]:
    """All pinned SA-1 fixtures (those with `source_raw_finding_id`)."""
    out: list[dict] = []
    for p in sorted(_FIXTURES_DIR.glob("*.json")):
        try:
            with p.open() as f:
                data = json.load(f)
        except Exception:  # noqa: BLE001, S112
            continue
        if data.get("source_raw_finding_id") and (
            data.get("agent") in ("sa1", None) and "raw" in data
        ):
            out.append({"path": p, "data": data})
    return out


def _find_issue_for_raw(sb, raw_finding_id: int) -> dict | None:
    """Look up the `issues` row that was normalized from this raw finding."""
    try:
        resp = (
            sb.table("issues")
            .select("*")
            .eq("raw_finding_id", raw_finding_id)
            .limit(1)
            .execute()
        )
        return (resp.data or [None])[0]
    except Exception:  # noqa: BLE001
        return None


def _asset_for_issue(sb, issue: dict) -> dict:
    """Try to find the resolved asset for this issue — best-effort."""
    asset_id = issue.get("asset_id")
    if not asset_id:
        return {}
    try:
        resp = sb.table("assets").select("*").eq("id", asset_id).limit(1).execute()
        return (resp.data or [{}])[0] or {}
    except Exception:  # noqa: BLE001
        return {}


def _package_for_issue(sb, issue_id: int) -> dict | None:
    """Latest remediation_package for this issue (demo or public — we try public first)."""
    for schema_fn in (supabase_admin,):
        try:
            resp = (
                schema_fn()
                .table("remediation_packages")
                .select("*")
                .eq("issue_id", issue_id)
                .order("id", desc=True)
                .limit(1)
                .execute()
            )
            if resp.data:
                return resp.data[0]
        except Exception:  # noqa: BLE001
            continue
    return None


def _write(path: Path, payload: dict, overwrite: bool) -> str:
    if path.exists() and not overwrite:
        return "skip-exists"
    with path.open("w") as f:
        json.dump(payload, f, indent=2, default=str)
    return "wrote"


def _derive_sa2(sa1_fx: dict, issue: dict) -> dict:
    """SA-2 input = normalized issue + enrichment inputs (snapshot of what the row carries)."""
    return {
        "fixture_id": f"{sa1_fx['fixture_id']}-sa2",
        "scanner": sa1_fx["scanner"],
        "agent": "sa2",
        "notes": f"Derived from SA-1 fixture {sa1_fx['fixture_id']}.",
        "source_issue_id": issue.get("id"),
        "input": {
            "issue": {
                "severity": issue.get("severity"),
                "cve_id": issue.get("cve_id"),
                "source_vuln_id": issue.get("source_vuln_id"),
                "title": issue.get("title"),
                "description": issue.get("description"),
                "asset_identity": issue.get("asset_identity") or {},
                "package": issue.get("package"),
            },
            "enrichment": {
                "epss_score": None,
                "epss_percentile": None,
                "in_kev": False,
                "nvd": {},
                "mitre": {"cwe": {}, "capec": [], "attack": []},
                "asset": {},
            },
            "scoring": {
                "derived_risk": None,
                "priority": None,
                "policy_version": "benchmark-stub",
                "components": {},
            },
        },
    }


def _derive_sa3(sa1_fx: dict, issue: dict, asset: dict) -> dict:
    """SA-3 input = enriched issue + asset + family hint."""
    # Guess family from source + severity — SA-3 handles classification itself
    source = (issue.get("source") or "").lower()
    if "image" in source:
        family = "os_vulnerability"
    elif "fs" in source or "python" in source or "java" in source:
        family = "vulnerable_dependency"
    elif "checkov" in source:
        family = "public_exposure"
    elif "semgrep" in source or "serverless" in source:
        family = "injection"
    else:
        family = "os_vulnerability"

    pkg = issue.get("package") or {}
    fixed_version = pkg.get("fixed_version") if isinstance(pkg, dict) else None

    return {
        "fixture_id": f"{sa1_fx['fixture_id']}-sa3",
        "scanner": sa1_fx["scanner"],
        "agent": "sa3",
        "notes": f"Derived from SA-1 fixture {sa1_fx['fixture_id']}.",
        "source_issue_id": issue.get("id"),
        "input": {
            "issue": {
                "id": issue.get("id"),
                "source": issue.get("source"),
                "severity": issue.get("severity"),
                "cve_id": issue.get("cve_id"),
                "source_vuln_id": issue.get("source_vuln_id"),
                "title": issue.get("title"),
                "description": issue.get("description"),
                "package": pkg,
                "asset_identity": issue.get("asset_identity") or {},
            },
            "asset": asset or {},
            "family": family,
            **({"fixed_version_hint": fixed_version} if fixed_version else {}),
        },
    }


def _derive_sa4(sa1_fx: dict, issue: dict, package: dict) -> dict:
    """SA-4 pre-flight input = pathway (from package) + sketched snapshot + issue."""
    pathways = package.get("pathways") or []
    recommended_idx = int(package.get("recommended_pathway_index") or 0)
    pathway = (
        pathways[recommended_idx]
        if 0 <= recommended_idx < len(pathways)
        else (pathways[0] if pathways else {"remediation_steps": []})
    )
    return {
        "fixture_id": f"{sa1_fx['fixture_id']}-sa4",
        "scanner": sa1_fx["scanner"],
        "agent": "sa4",
        "notes": (
            f"Derived from SA-1 fixture {sa1_fx['fixture_id']} + "
            f"remediation_package #{package.get('id')}."
        ),
        "source_issue_id": issue.get("id"),
        "source_package_id": package.get("id"),
        "input": {
            "pathway": {"remediation_steps": pathway.get("remediation_steps") or []},
            "snapshot_text": (
                "ENV2 SNAPSHOT (benchmark stub):\n"
                "  - target file present\n"
                "  - docker daemon reachable (v26.1.3)\n"
                "  - trivy present (v0.74.0)\n"
                "  - no destructive patterns pre-flagged"
            ),
            "issue": {
                "id": issue.get("id"),
                "source_vuln_id": issue.get("source_vuln_id"),
                "title": issue.get("title"),
                "severity": issue.get("severity"),
                "asset_identity": issue.get("asset_identity") or {},
            },
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive SA-2/SA-3/SA-4 fixtures from pinned SA-1 raws"
    )
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)

    sb = supabase_admin()
    sa1_fixtures = _load_sa1_fixtures()
    print(f"▶ Found {len(sa1_fixtures)} pinned SA-1 fixtures. Deriving SA-2/SA-3/SA-4…")

    counts: dict[str, int] = {
        "sa2": 0,
        "sa3": 0,
        "sa4": 0,
        "skip_no_issue": 0,
        "skip_no_pkg": 0,
        "skip_exists": 0,
    }

    for fx in sa1_fixtures:
        raw_id = fx["data"]["source_raw_finding_id"]
        fid = fx["data"]["fixture_id"]
        issue = _find_issue_for_raw(sb, raw_id)
        if not issue:
            counts["skip_no_issue"] += 1
            print(
                f"  ⚠ {fid}: no issues row for raw_finding_id={raw_id} — skipping SA-2/3/4"
            )
            continue
        issue_id = int(issue["id"])
        asset = _asset_for_issue(sb, issue)

        # SA-2
        sa2_payload = _derive_sa2(fx["data"], issue)
        status = _write(
            _FIXTURES_DIR / f"{sa2_payload['fixture_id']}.json",
            sa2_payload,
            args.overwrite,
        )
        counts["sa2"] += status == "wrote"
        counts["skip_exists"] += status == "skip-exists"

        # SA-3
        sa3_payload = _derive_sa3(fx["data"], issue, asset)
        status = _write(
            _FIXTURES_DIR / f"{sa3_payload['fixture_id']}.json",
            sa3_payload,
            args.overwrite,
        )
        counts["sa3"] += status == "wrote"
        counts["skip_exists"] += status == "skip-exists"

        # SA-4 — requires a remediation_package to exist
        package = _package_for_issue(sb, issue_id)
        if not package:
            counts["skip_no_pkg"] += 1
            print(
                f"  ⚠ {fid}: no remediation_packages row for issue_id={issue_id} — SA-4 skipped"
            )
            continue
        sa4_payload = _derive_sa4(fx["data"], issue, package)
        status = _write(
            _FIXTURES_DIR / f"{sa4_payload['fixture_id']}.json",
            sa4_payload,
            args.overwrite,
        )
        counts["sa4"] += status == "wrote"
        counts["skip_exists"] += status == "skip-exists"

    print(
        f"\n▶ Done. Wrote: SA-2={counts['sa2']}, SA-3={counts['sa3']}, SA-4={counts['sa4']}  "
        f"| Skipped: exists={counts['skip_exists']}, no_issue={counts['skip_no_issue']}, no_pkg={counts['skip_no_pkg']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
