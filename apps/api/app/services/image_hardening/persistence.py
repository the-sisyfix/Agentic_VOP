"""Image Hardening persistence — reads/writes the `hardening_runs` table only.

Deliberately standalone: no access to issues / remediation_packages / fix_runs.
Mirrors the fixer's persistence.py style (create / set_status / finalize /
any_concurrent_run) so the code reads familiarly, but it is a separate module
operating on a separate table.
"""

from __future__ import annotations

from typing import Any

from .models import HardeningOutcome, utcnow

# The table name is the same in both public.* and demo.* schemas; the schema is
# selected by WHICH supabase client the caller passes (supabase_admin vs
# supabase_admin_demo), identical to how the fixer's persistence works.
_TABLE = "hardening_runs"


# =============================================================================
# CREATE
# =============================================================================
def create_hardening_run(
    sb: Any,
    *,
    source_image_ref: str,
    target_registry: str,
    published_tag: str,
    build_instance_id: str,
    auto_sign: bool,
    timeout_seconds: int,
) -> int:
    """Insert a hardening_runs row in status='pending'. Return the new id."""
    row = {
        "source_image_ref": source_image_ref,
        "target_registry": target_registry,
        "published_tag": published_tag,
        "status": "pending",
        "auto_sign": auto_sign,
        "build_instance_id": build_instance_id,
        "started_at": utcnow().isoformat(),
        "timeout_seconds": timeout_seconds,
    }
    resp = sb.table(_TABLE).insert(row).execute()
    rows = resp.data or []
    if not rows:
        raise RuntimeError("INSERT into hardening_runs returned no row")
    return int(rows[0]["id"])


# =============================================================================
# UPDATE — status transitions
# =============================================================================
def set_status(
    sb: Any,
    hardening_run_id: int,
    status: str,
    *,
    error_message: str | None = None,
) -> None:
    """Transition a hardening_run to a new status. Status values must match the
    CHECK constraint in migration 0044."""
    patch: dict[str, Any] = {"status": status, "updated_at": utcnow().isoformat()}
    if error_message is not None:
        patch["error_message"] = error_message[:2000]
    sb.table(_TABLE).update(patch).eq("id", hardening_run_id).execute()


def set_published(
    sb: Any,
    hardening_run_id: int,
    *,
    published_digest: str,
    published_tag: str,
) -> None:
    """Record the published digest/tag once the image is pushed. The digest is
    the exact artifact the signing workflow will sign."""
    sb.table(_TABLE).update(
        {
            "published_digest": published_digest,
            "published_tag": published_tag,
            "updated_at": utcnow().isoformat(),
        }
    ).eq("id", hardening_run_id).execute()


def set_sbom_key(sb: Any, hardening_run_id: int, sbom_s3_key: str) -> None:
    """Record the S3 key where the SBOM was uploaded."""
    sb.table(_TABLE).update(
        {"sbom_s3_key": sbom_s3_key, "updated_at": utcnow().isoformat()}
    ).eq("id", hardening_run_id).execute()


def set_sign_dispatched(sb: Any, hardening_run_id: int, dispatched: bool) -> None:
    """Record whether the signing workflow was auto-dispatched."""
    sb.table(_TABLE).update(
        {"sign_dispatched": dispatched, "updated_at": utcnow().isoformat()}
    ).eq("id", hardening_run_id).execute()


# =============================================================================
# UPDATE — write the whole outcome at end-of-run
# =============================================================================
def finalize_hardening_run(
    sb: Any,
    hardening_run_id: int,
    outcome: HardeningOutcome,
    *,
    started_at,
) -> None:
    """Write the final row shape when the run ends (success/failed/rolled_back)."""
    finished_at = utcnow()
    duration_s = int((finished_at - started_at).total_seconds())

    patch: dict[str, Any] = {
        "status": outcome.status,
        "step_results": [r.model_dump(mode="json") for r in outcome.step_results],
        "validation_results": [r.model_dump(mode="json") for r in outcome.validation_results],
        "rollback_results": [r.model_dump(mode="json") for r in outcome.rollback_results],
        "rollback_triggered": len(outcome.rollback_results) > 0,
        "scan_summary": outcome.scan_summary or {},
        "sign_dispatched": outcome.sign_dispatched,
        "finished_at": finished_at.isoformat(),
        "duration_seconds": duration_s,
        "updated_at": finished_at.isoformat(),
    }
    if outcome.published_digest:
        patch["published_digest"] = outcome.published_digest
    if outcome.published_tag:
        patch["published_tag"] = outcome.published_tag
    if outcome.sbom_s3_key:
        patch["sbom_s3_key"] = outcome.sbom_s3_key
    if outcome.backup_reference:
        patch["backup_reference"] = outcome.backup_reference
    if outcome.error_message:
        patch["error_message"] = outcome.error_message[:2000]

    sb.table(_TABLE).update(patch).eq("id", hardening_run_id).execute()


# =============================================================================
# READ
# =============================================================================
def get_hardening_run(sb: Any, hardening_run_id: int) -> dict | None:
    """Fetch a hardening_runs row by id (for the API + UI)."""
    resp = sb.table(_TABLE).select("*").eq("id", hardening_run_id).limit(1).execute()
    rows = resp.data or []
    return rows[0] if rows else None


def any_concurrent_run_on_instance(sb: Any, build_instance_id: str) -> dict | None:
    """Return an in-flight hardening_run on the SAME build instance, or None.

    Concurrency is scoped to the build EC2 (isolation guarantee #5): this only
    looks at hardening_runs, and only those targeting the same instance. It is
    completely independent of the fixer's env2 lock — a hardening run never
    blocks, and is never blocked by, a vulnerability-fix run.
    """
    resp = (
        sb.table(_TABLE)
        .select("id, status, build_instance_id, started_at")
        .eq("build_instance_id", build_instance_id)
        .in_("status", ("pending", "preflight", "building", "scanning", "publishing", "signing"))
        .order("id", desc=False)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    return rows[0] if rows else None
