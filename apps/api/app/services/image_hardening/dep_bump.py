"""Deterministic dependency-version bumping (pip / requirements.txt).

Reads the FIX straight from trivy's lang-pkgs findings (each carries the exact
`FixedVersion`) and pins the vulnerable package to that version in
requirements.txt. No guessing, no "latest", no LLM — fully deterministic, which
is required by the "no margin for error" bar.

Scope (this increment): pip only. npm / gomod / gobinary etc. are reported as
residual (out of scope here; added in later increments). Transitive packages
(not present in requirements.txt) are also residual — pinning a package the
manifest doesn't declare risks breaking the resolver, so we report rather than
guess.

The core (`compute_pip_bumps`, `apply_pip_bumps`) are PURE functions — no I/O —
so they are fully unit-testable without a build box.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# trivy lang-pkg "Type" values that are pip. (Trivy uses "pip" for
# requirements.txt / installed Python packages.)
_PIP_TYPES = {"pip", "python-pkg"}

# A requirements line: optional leading pkg name, then a specifier. We only need
# to identify the package token at the start of a non-comment, non-blank line.
_REQ_LINE_RE = re.compile(
    r"""^\s*
        (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)   # package name
        \s*(?P<rest>.*)$                         # the rest (specifier/extras/markers)
    """,
    re.VERBOSE,
)


def normalize_pkg(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of -_. collapse to a single '-'.
    So 'Flask', 'flask', 'foo_bar', 'foo.bar' compare equal to their canonical."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


@dataclass
class PipBumpPlan:
    """What we will / won't change, computed deterministically from findings."""

    # normalized_pkg -> fixed_version to pin
    to_pin: dict[str, str] = field(default_factory=dict)
    # findings we could not pin, with a reason (residual — reported honestly)
    residual: list[dict] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.to_pin)


def _highest_version(a: str, b: str) -> str:
    """Return the higher of two version strings using a tuple comparison on
    numeric components. Falls back to string compare for non-numeric parts.
    Deterministic and dependency-free (no packaging lib needed for the MVP)."""

    def parts(v: str):
        out = []
        for seg in re.split(r"[.\-+]", v):
            out.append((0, int(seg)) if seg.isdigit() else (1, seg))
        return out

    return a if parts(a) >= parts(b) else b


def compute_pip_bumps(trivy_report_json: str, requirements_text: str) -> PipBumpPlan:
    """Deterministically decide which pip packages to pin to which fixed version.

    - Only pip-type lang-pkg findings with a FixedVersion are considered.
    - A finding is pinned only if its package is DECLARED in requirements.txt
      (direct dependency). Packages not present → residual (likely transitive).
    - Non-pip lang findings → residual (out of scope this increment).
    - Multiple findings for one package → pin to the highest FixedVersion.
    """
    plan = PipBumpPlan()
    try:
        data = json.loads(trivy_report_json)
    except (ValueError, TypeError):
        return plan

    declared = _declared_pip_packages(requirements_text)  # normalized -> original token

    for result in data.get("Results") or []:
        rtype = (result.get("Type") or "").strip().lower()
        rclass = (result.get("Class") or "").strip()
        if rclass != "lang-pkgs":
            continue
        for v in result.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "").upper()
            if sev not in ("CRITICAL", "HIGH"):
                continue
            pkg = v.get("PkgName") or ""
            fixed = v.get("FixedVersion") or ""
            vuln_id = v.get("VulnerabilityID") or ""
            if not pkg:
                continue
            if rtype not in _PIP_TYPES:
                plan.residual.append(
                    {
                        "pkg": pkg,
                        "vuln": vuln_id,
                        "reason": f"non-pip ecosystem ({rtype or 'unknown'})",
                    }
                )
                continue
            if not fixed:
                plan.residual.append(
                    {"pkg": pkg, "vuln": vuln_id, "reason": "no fixed version available"}
                )
                continue
            # trivy FixedVersion can be a comma list (e.g. "1.2, 2.0"); take the
            # first (lowest fixed) — the minimal version that resolves it.
            fixed_one = fixed.split(",")[0].strip()
            norm = normalize_pkg(pkg)
            if norm not in declared:
                plan.residual.append(
                    {
                        "pkg": pkg,
                        "vuln": vuln_id,
                        "reason": "not declared in requirements.txt (transitive)",
                    }
                )
                continue
            # Multiple findings for same pkg → keep the highest fixed version.
            if norm in plan.to_pin:
                plan.to_pin[norm] = _highest_version(plan.to_pin[norm], fixed_one)
            else:
                plan.to_pin[norm] = fixed_one
    return plan


def _declared_pip_packages(requirements_text: str) -> dict[str, str]:
    """Map normalized package name -> original name token, for lines that
    declare a package. Skips comments, blanks, and non-package directives
    (-r, -e, --hash, URLs)."""
    declared: dict[str, str] = {}
    for raw in requirements_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "://" in line:  # URL / VCS requirement — leave as-is
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            name = m.group("name")
            declared[normalize_pkg(name)] = name
    return declared


def apply_pip_bumps(requirements_text: str, plan: PipBumpPlan) -> str:
    """Rewrite requirements.txt pinning each planned package to ==fixed_version.

    Preserves comments, blanks, ordering, and untouched lines. Rewrites only the
    lines whose package is in plan.to_pin. Deterministic + idempotent.
    """
    if not plan.has_changes:
        return requirements_text

    out_lines: list[str] = []
    for raw in requirements_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-") or "://" in line:
            out_lines.append(raw)
            continue
        m = _REQ_LINE_RE.match(line)
        if not m:
            out_lines.append(raw)
            continue
        norm = normalize_pkg(m.group("name"))
        if norm in plan.to_pin:
            # Pin to the exact fixed version. Keep the original name token's
            # casing/spelling for readability.
            out_lines.append(f"{m.group('name')}=={plan.to_pin[norm]}")
        else:
            out_lines.append(raw)
    # Preserve trailing newline convention.
    text = "\n".join(out_lines)
    if requirements_text.endswith("\n") and not text.endswith("\n"):
        text += "\n"
    return text
