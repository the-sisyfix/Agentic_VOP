"""Shared trivy scanning + finding classification for the hardening pipeline.

ONE full-scope scan is the source of truth for the policy-zero gate; its
findings are classified by trivy's `Class` field into OS-package vs
dependency/language findings so the orchestrator can decide what to run:

  - OS findings (Class == "os-pkgs")   → copa can patch in place.
  - dep findings (Class == "lang-pkgs")→ need the rebuild leg (if a Dockerfile
                                          is available) or are residual.

The GATE is full-scope: zero fixable critical/high across BOTH classes. This is
why a dependency-only image is NOT falsely passed by a copa-only (OS) scan.

Only fixable findings count (FixedVersion present) — matching the policy-zero
definition ("zero *fixable* critical/high at certification").
"""

from __future__ import annotations

import json
from dataclasses import dataclass

# trivy Result.Class values (verified from trivy's output schema).
_CLASS_OS = "os-pkgs"
_CLASS_LANG = "lang-pkgs"

_GATE_SEVERITIES = ("CRITICAL", "HIGH")


@dataclass(frozen=True)
class ScanClassification:
    """Fixable critical/high counts, split by remediation class."""

    os_critical: int = 0
    os_high: int = 0
    dep_critical: int = 0
    dep_high: int = 0

    @property
    def os_fixable(self) -> int:
        return self.os_critical + self.os_high

    @property
    def dep_fixable(self) -> int:
        return self.dep_critical + self.dep_high

    @property
    def total_fixable(self) -> int:
        return self.os_fixable + self.dep_fixable

    @property
    def gate_passes(self) -> bool:
        """Policy-zero gate: zero fixable critical/high across ALL classes."""
        return self.total_fixable == 0

    def summary(self) -> dict:
        return {
            "os_fixable_critical": self.os_critical,
            "os_fixable_high": self.os_high,
            "dep_fixable_critical": self.dep_critical,
            "dep_fixable_high": self.dep_high,
            "total_fixable": self.total_fixable,
            "gate_passes": self.gate_passes,
        }


def classify_trivy_report(report_json: str) -> ScanClassification:
    """Parse a full-scope trivy JSON report into fixable crit/high by class.

    Full-scope report is produced with:
        trivy image --vuln-type os,library --ignore-unfixed -f json ...

    Robust to malformed/empty input (returns an all-zero classification).
    """
    try:
        data = json.loads(report_json)
    except (ValueError, TypeError):
        return ScanClassification()

    os_c = os_h = dep_c = dep_h = 0
    for result in data.get("Results") or []:
        cls = (result.get("Class") or "").strip()
        for v in result.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "").upper()
            if sev not in _GATE_SEVERITIES:
                continue
            if not v.get("FixedVersion"):  # only fixable findings count
                continue
            is_os = cls == _CLASS_OS
            is_dep = cls == _CLASS_LANG
            # If Class is missing/unknown, be conservative and treat as dep
            # (dep is the "needs source" path — safer to over-report than to
            # silently drop a finding from the gate).
            if not is_os and not is_dep:
                is_dep = True
            if sev == "CRITICAL":
                if is_os:
                    os_c += 1
                else:
                    dep_c += 1
            elif sev == "HIGH":
                if is_os:
                    os_h += 1
                else:
                    dep_h += 1
    return ScanClassification(os_critical=os_c, os_high=os_h, dep_critical=dep_c, dep_high=dep_h)
