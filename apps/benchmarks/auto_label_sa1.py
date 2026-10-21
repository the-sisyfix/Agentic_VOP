"""Auto-generate SA-1 ground-truth labels from pinned raw fixtures.

For each file in `fixtures/raw/` that targets SA-1, read the raw finding
and emit the expected normalized fields as `ground_truth/sa1/{fixture_id}.json`.

Because SA-1 is "take the scanner's own fields and canonicalize them,"
the expected output is deterministically derivable from the raw — no
human judgment needed per fixture. If a scanner changes shape later,
re-run this script.

Skips any fixtures that already have a ground-truth file (so hand-tuned
labels aren't overwritten).

Usage:
    PYTHONPATH=../.. uv run python -m apps.benchmarks.auto_label_sa1
    PYTHONPATH=../.. uv run python -m apps.benchmarks.auto_label_sa1 --overwrite
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "raw"
_GT_DIR = Path(__file__).parent / "ground_truth" / "sa1"

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "unknown": "info",
    "info": "info",
    "informational": "info",
    "error": "high",
    "warning": "medium",
    "note": "low",
}


def _extract_expected(scanner: str, raw: dict) -> dict:
    """Derive expected normalized fields from a raw finding payload."""
    expected: dict = {"source": scanner}

    # ─ CVE / check_id / rule_id ──────────────────────────────────────
    cve = (
        raw.get("vuln_id")
        or raw.get("VulnerabilityID")
        or raw.get("cve_id")
        or raw.get("vulnerability_id")
    )
    check_id = raw.get("check_id") or raw.get("CheckID") or raw.get("rule_id")

    if cve:
        expected["source_vuln_id"] = cve
        if str(cve).upper().startswith("CVE-"):
            expected["cve_id"] = cve
    elif check_id:
        expected["source_vuln_id"] = check_id

    # ─ CWE ───────────────────────────────────────────────────────────
    cwes = raw.get("CweIDs") or raw.get("cwe_ids") or raw.get("cwe")
    if cwes:
        if isinstance(cwes, list) and cwes:
            expected["cwe_id"] = cwes[0]
        elif isinstance(cwes, str):
            expected["cwe_id"] = cwes

    # ─ Severity ──────────────────────────────────────────────────────
    sev = raw.get("Severity") or raw.get("severity") or raw.get("level")
    if sev:
        expected["severity"] = _SEVERITY_MAP.get(str(sev).lower(), str(sev).lower())

    # ─ CVSS ──────────────────────────────────────────────────────────
    cvss = raw.get("CVSS") or raw.get("cvss") or {}
    if isinstance(cvss, dict):
        nvd = cvss.get("nvd") or cvss.get("NVD") or {}
        if isinstance(nvd, dict):
            v3_score = nvd.get("V3Score") or nvd.get("v3_score")
            v3_vec = nvd.get("V3Vector") or nvd.get("v3_vector")
            if v3_score:
                expected["cvss_score"] = float(v3_score)
            if v3_vec:
                expected["cvss_vector"] = v3_vec
                if "3.1" in v3_vec:
                    expected["cvss_version"] = "3.1"
                elif "3.0" in v3_vec:
                    expected["cvss_version"] = "3.0"
    # trivy flat form
    if "cvss_score" not in expected and raw.get("cvss_score") is not None:
        try:
            expected["cvss_score"] = float(raw["cvss_score"])
        except (TypeError, ValueError):
            pass

    # ─ Title ─────────────────────────────────────────────────────────
    title = raw.get("Title") or raw.get("title") or raw.get("message")
    if title:
        # Use substring match on a distinctive word — avoids exact-string
        # brittleness while still catching gross semantic drift.
        words = [w for w in str(title).split() if len(w) > 4 and w.isalpha()]
        if words:
            expected["title_contains"] = words[0].lower()
        expected["description_present"] = True
    else:
        expected["description_present"] = True

    # ─ Package (trivy / snyk shape) ──────────────────────────────────
    pkg_name = raw.get("pkg_name") or raw.get("PkgName") or raw.get("package_name")
    inst_ver = (
        raw.get("installed_version")
        or raw.get("InstalledVersion")
        or raw.get("package_version")
    )
    fix_ver = raw.get("fixed_version") or raw.get("FixedVersion")
    if pkg_name:
        pkg_block: dict = {"name": pkg_name}
        if inst_ver:
            pkg_block["installed_version"] = inst_ver
        if fix_ver:
            pkg_block["fixed_version"] = fix_ver
        expected["package"] = pkg_block

    return expected


def _label_one(fixture_path: Path, *, overwrite: bool) -> str:
    """Return a short status string: 'wrote' / 'skipped' / 'skipped-other-agent' / 'error'."""
    try:
        with fixture_path.open() as f:
            fixture = json.load(f)
    except Exception as e:  # noqa: BLE001
        return f"error ({type(e).__name__}: {str(e)[:80]})"

    # Only auto-label SA-1 fixtures. SA-2/SA-3/SA-4 need different ground truths.
    declared = fixture.get("agent")
    is_sa1 = (declared == "sa1") or ("raw" in fixture and declared is None)
    if not is_sa1:
        return "skipped-other-agent"

    fixture_id = fixture.get("fixture_id")
    scanner = fixture.get("scanner") or "unknown"
    raw = fixture.get("raw") or {}
    if not fixture_id or not raw:
        return "error (missing fixture_id or raw)"

    out_path = _GT_DIR / f"{fixture_id}.json"
    if out_path.exists() and not overwrite:
        return "skipped-exists"

    expected = _extract_expected(scanner, raw)
    _GT_DIR.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        json.dump(
            {
                "fixture_id": fixture_id,
                "notes": "Auto-generated by auto_label_sa1.py from raw payload. "
                "Hand-edit if the mapping is wrong.",
                "expected": expected,
            },
            f,
            indent=2,
        )
    return "wrote"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Auto-generate SA-1 ground truth from raw fixtures"
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing ground_truth files (default: skip them)",
    )
    args = parser.parse_args(argv)

    if not _FIXTURES_DIR.exists():
        print(f"✗ No fixtures dir at {_FIXTURES_DIR}")
        return 1

    counts = {"wrote": 0, "skipped-exists": 0, "skipped-other-agent": 0, "error": 0}
    for path in sorted(_FIXTURES_DIR.glob("*.json")):
        status = _label_one(path, overwrite=args.overwrite)
        if status == "wrote":
            counts["wrote"] += 1
            print(f"  ✓ {path.name}")
        elif status == "skipped-exists":
            counts["skipped-exists"] += 1
        elif status == "skipped-other-agent":
            counts["skipped-other-agent"] += 1
        else:
            counts["error"] += 1
            print(f"  ✗ {path.name}: {status}")

    print(
        f"\n▶ Done: wrote={counts['wrote']}, "
        f"skipped-exists={counts['skipped-exists']}, "
        f"skipped-other-agent={counts['skipped-other-agent']}, "
        f"errors={counts['error']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
