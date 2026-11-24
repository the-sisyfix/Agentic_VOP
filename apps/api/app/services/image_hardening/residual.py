"""Residual report + OpenVEX generation for the hardening pipeline.

After copa patches everything FIXABLE (policy-zero gate = zero fixable
critical/high), an image typically still carries UNFIXABLE CVEs — findings with
no available upstream fix (Debian `will_not_fix` / `fix_deferred` / `affected`
with no fixed version). These are the "honest residual": real, present, but not
remediable by anyone today. They are exactly why a client's ECR/Inspector
console still shows CVEs on a correctly-hardened image.

This module turns the box-extracted residual findings (deduplicated by CVE id,
all severities) into two client-facing artifacts:

  1. Itemized residual REPORT  — human/machine readable JSON: per-CVE id,
     severity, trivy status, affected packages, installed version, title, plus
     a severity histogram. This reconciles with the client's scanner view.

  2. OpenVEX document          — a standards-based VEX asserting the product's
     status for each residual CVE. For unfixable residual the status is
     "affected" (the vuln is present and we cannot remediate it) with an
     action statement pointing at the vendor status. OpenVEX is the lightweight,
     widely-adopted VEX format (https://github.com/openvex/spec).

Both are generated from the SAME final full-scope trivy report we already
produce — no extra scan. Residual is REPORTED, not gating: the run remains a
success (policy-zero is about fixable findings).
"""

from __future__ import annotations

from datetime import UTC, datetime

# OpenVEX constants (spec: https://github.com/openvex/spec).
_OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
_VEX_STATUS_AFFECTED = "affected"

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def build_residual_report(
    *,
    findings: list[dict],
    image_ref: str,
    image_digest: str,
    artifact_name: str = "",
) -> dict:
    """Build the itemized residual report from box-extracted residual findings.

    `findings` is the list from scanning.parse_box_residual — each item:
    {id, severity, status, pkgs, installed, title}, already deduped by CVE id.

    The report is honest-by-construction: it lists every unfixable finding, with
    the trivy Status so the reader can see WHY it is residual (will_not_fix /
    fix_deferred / affected-no-fix). Counts are grouped by severity.
    """
    normalized: list[dict] = []
    for f in findings:
        sev = str(f.get("severity") or "UNKNOWN").upper()
        if sev not in _SEVERITY_ORDER:
            sev = "UNKNOWN"
        normalized.append(
            {
                "id": f.get("id") or "",
                "severity": sev,
                "status": f.get("status") or "",
                "packages": sorted(f.get("pkgs") or []),
                "installed_version": f.get("installed") or "",
                "title": f.get("title") or "",
            }
        )
    # Stable ordering: by severity rank, then CVE id.
    normalized.sort(key=lambda x: (_SEVERITY_ORDER.index(x["severity"]), x["id"]))

    by_sev: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in normalized:
        by_sev[f["severity"]] += 1

    return {
        "schema": "sisyfix.image-hardening.residual/v1",
        "generated_at": _utcnow_iso(),
        "image_ref": image_ref,
        "image_digest": image_digest,
        "artifact_name": artifact_name,
        "definition": (
            "Residual = CVEs with NO available fix at hardening time (unfixable). "
            "All fixable CRITICAL/HIGH were patched (policy-zero gate). These "
            "remain because upstream has no fix (e.g. Debian will_not_fix / "
            "fix_deferred) — not remediable by patching today."
        ),
        "counts": {
            "total": len(normalized),
            "critical": by_sev["CRITICAL"],
            "high": by_sev["HIGH"],
            "medium": by_sev["MEDIUM"],
            "low": by_sev["LOW"],
            "unknown": by_sev["UNKNOWN"],
        },
        "findings": normalized,
    }


def build_openvex(
    *,
    findings: list[dict],
    image_ref: str,
    image_digest: str,
    author: str = "Sisyfix Image Hardening",
) -> dict:
    """Build an OpenVEX document for the residual (unfixable) CVEs.

    Each residual CVE becomes a VEX statement with status "affected" (the vuln
    is present in the product and we could not remediate it), plus an
    action_statement that records the upstream vendor status so a consumer's
    tooling understands it is unfixable rather than ignored.

    Product is identified by the published image DIGEST (immutable), as a
    container-image purl-style identifier. MVP scope: faithful to the OpenVEX
    shape (@context/@id/author/timestamp/statements with vulnerability +
    products + status); justification enrichment can follow later.
    """
    now = _utcnow_iso()
    product_id = f"pkg:oci/{_oci_name(image_ref)}@{image_digest}" if image_digest else image_ref
    statements: list[dict] = []
    for f in findings:
        vid = f.get("id") or ""
        if not vid:
            continue
        vendor_status = f.get("status") or "no-fix-available"
        statements.append(
            {
                "vulnerability": {"name": vid},
                "products": [{"@id": product_id}],
                "status": _VEX_STATUS_AFFECTED,
                "action_statement": (
                    f"No upstream fix available at hardening time "
                    f"(vendor status: {vendor_status}). All fixable findings were "
                    f"patched; this CVE cannot be remediated by patching today."
                ),
                "action_statement_timestamp": now,
            }
        )
    return {
        "@context": _OPENVEX_CONTEXT,
        "@id": f"https://sisyfix/vex/{image_digest or 'unknown'}",
        "author": author,
        "timestamp": now,
        "version": 1,
        "statements": statements,
    }


def residual_summary_for_scan(report: dict) -> dict:
    """Small dict (counts) to merge into hardening_runs.scan_summary.

    Keeps the API/run-record aware that residual exists and how much, without
    embedding the full list (that lives in S3). Keys are prefixed `residual_`.
    """
    c = report.get("counts") or {}
    return {
        "residual_total": c.get("total", 0),
        "residual_critical": c.get("critical", 0),
        "residual_high": c.get("high", 0),
        "residual_medium": c.get("medium", 0),
        "residual_low": c.get("low", 0),
    }


def _oci_name(image_ref: str) -> str:
    """Best-effort OCI name (repo without tag/digest) for the VEX product id."""
    ref = image_ref.strip()
    at = ref.find("@")
    if at != -1:
        ref = ref[:at]
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    if colon > slash:
        ref = ref[:colon]
    return ref or image_ref
