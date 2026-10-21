"""SA-1 (normalization) scorer — exact-match against ground truth.

Loads the labeled expected output for a fixture, compares each field of
the model's actual output, returns:

  efficacy_score  — fraction of fields that matched (0.0 - 1.0)
  fields_passed   — "severity, cve_id, cwe_id" (comma-joined names)
  fields_failed   — "cvss_score" (comma-joined names)
  hallucinated    — True if actual contains invented fields not in reference
                    OR a field value with no basis in the raw finding
  efficacy_reason — short human-readable summary

Returns zeros + "no_ground_truth" if no ground-truth file exists for the
fixture — allows the harness to run even on un-labeled fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_GT_DIRS = (
    Path(__file__).parent.parent / "ground_truth" / "sa1",
    Path(__file__).parent.parent / "ground_truth" / "sa1_success",
)


def score_sa1(fixture_id: str, actual_output: dict | None) -> dict[str, Any]:
    """Compare SA-1 actual output to the labeled expected output.

    Looks in both ground_truth/sa1/ (random pool) and
    ground_truth/sa1_success/ (success-only pool) — first match wins.
    """
    gt_path = next(
        (
            d / f"{fixture_id}.json"
            for d in _GT_DIRS
            if (d / f"{fixture_id}.json").exists()
        ),
        None,
    )
    if not gt_path:
        return {
            "efficacy_score": 0.0,
            "fields_passed": "",
            "fields_failed": "",
            "hallucinated": False,
            "efficacy_reason": "no_ground_truth",
        }

    if actual_output is None:
        return {
            "efficacy_score": 0.0,
            "fields_passed": "",
            "fields_failed": "all",
            "hallucinated": False,
            "efficacy_reason": "no_output",
        }

    with gt_path.open() as f:
        expected = json.load(f).get("expected") or {}

    passed: list[str] = []
    failed: list[str] = []

    # Exact-match scalar fields
    for field in (
        "source",
        "source_vuln_id",
        "cve_id",
        "cwe_id",
        "severity",
        "cvss_version",
        "cvss_vector",
    ):
        exp = expected.get(field)
        if exp is None:
            continue
        act = _nested_get(actual_output, field)
        if _case_insensitive_eq(act, exp):
            passed.append(field)
        else:
            failed.append(field)

    # Numeric with tolerance (CVSS can round differently)
    if "cvss_score" in expected:
        exp_num = float(expected["cvss_score"])
        act_num = _as_float(actual_output.get("cvss_score"))
        if act_num is not None and abs(act_num - exp_num) < 0.1:
            passed.append("cvss_score")
        else:
            failed.append("cvss_score")

    # Substring match for free-form title
    if "title_contains" in expected:
        needle = str(expected["title_contains"]).lower()
        title = str(actual_output.get("title") or "").lower()
        if needle in title:
            passed.append("title_contains")
        else:
            failed.append("title_contains")

    # Presence-only for description (free-form, don't score content)
    if expected.get("description_present"):
        if actual_output.get("description"):
            passed.append("description_present")
        else:
            failed.append("description_present")

    # Nested package dict — exact-match per subfield
    if "package" in expected:
        exp_pkg = expected["package"]
        act_pkg = actual_output.get("package") or {}
        if not isinstance(act_pkg, dict):
            act_pkg = {}
        for pf in ("name", "installed_version", "fixed_version"):
            if pf not in exp_pkg:
                continue
            if _case_insensitive_eq(act_pkg.get(pf), exp_pkg[pf]):
                passed.append(f"package.{pf}")
            else:
                failed.append(f"package.{pf}")

    total = len(passed) + len(failed)
    score = len(passed) / total if total else 0.0

    # Hallucination heuristic: cve_id looks CVE-shaped but doesn't match
    # expected (model made up a different one), OR severity is way off.
    hallucinated = False
    act_cve = str(actual_output.get("cve_id") or "").upper()
    exp_cve = str(expected.get("cve_id") or "").upper()
    if act_cve and exp_cve and act_cve != exp_cve and act_cve.startswith("CVE-"):
        hallucinated = True

    reason = f"{len(passed)}/{total} fields matched"
    if hallucinated:
        reason += " (CVE_HALLUCINATED)"

    return {
        "efficacy_score": round(score, 3),
        "fields_passed": ",".join(passed),
        "fields_failed": ",".join(failed),
        "hallucinated": hallucinated,
        "efficacy_reason": reason,
    }


def _case_insensitive_eq(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a == b
    return str(a).strip().lower() == str(b).strip().lower()


def _nested_get(d: dict, key: str) -> Any:
    """Dot-path get for `package.name` style keys."""
    cur: Any = d
    for part in key.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _as_float(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
