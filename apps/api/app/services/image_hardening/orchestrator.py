"""Image Hardening orchestrator — the entry point.

Standalone: does NOT call run_fixer, does NOT touch issues/packages/fix_runs.
Owns its own run record (hardening_runs), its own concurrency lane (scoped to
the build instance), and its own non-agent identity.

Flow:
  resolve build instance (ephemeral seam) → concurrency check → create run row
  → pre_flight → backup → execute → validate (scan gate) → finalize
  → best-effort auto-sign dispatch (if enabled).

Concurrency is scoped to the build EC2 only — a hardening run never blocks, and
is never blocked by, a vulnerability-fix run (isolation guarantee #5).
"""

from __future__ import annotations

import logging
from typing import Any

from app.config import settings

from .config import HardeningConfig, load_hardening_config, resolve_build_instance
from .models import HardenContext, HardeningOutcome, utcnow
from .persistence import (
    any_concurrent_run_on_instance,
    create_hardening_run,
    finalize_hardening_run,
    set_published,
    set_sbom_key,
    set_sign_dispatched,
    set_status,
)
from .signing import dispatch_signing_workflow
from .strategy import ImageHardenStrategy

log = logging.getLogger("image_hardening")


def _log_emitter(
    run_id: str, agent: str, event_type: str, message: str, payload: Any = None
) -> None:
    """No-op-to-DB emitter: logs only, does NOT write agent_trace_events.

    Per the MVP decision, hardening does not emit trace events — the
    hardening_runs row carries the story. We log for operator visibility.
    """
    log.info("[%s][%s] %s", agent, event_type, message)


def create_run_record(
    *,
    source_image_ref: str,
    target_registry: str,
    published_tag: str,
    auto_sign: bool,
    sb: Any,
    config: HardeningConfig | None = None,
) -> int:
    """Create the hardening_runs row synchronously and return its id.

    Split out from run_hardening so the API endpoint can create the row (and
    return a real id to the caller) BEFORE dispatching the long-running
    pipeline as a background task. Also performs the setup checks (build
    instance resolvable + no concurrent run) so the caller gets a clean error
    synchronously instead of only in a background log.
    """
    cfg = config or load_hardening_config()
    cfg = _with_defaults(cfg, target_registry)

    instance_id = resolve_build_instance(cfg)

    other = any_concurrent_run_on_instance(sb, instance_id)
    if other is not None:
        raise RuntimeError(
            f"Build instance {instance_id} is busy with hardening_run "
            f"#{other['id']} (status={other.get('status')}). Try again shortly."
        )

    return create_hardening_run(
        sb,
        source_image_ref=source_image_ref,
        target_registry=target_registry,
        published_tag=published_tag,
        build_instance_id=instance_id,
        auto_sign=auto_sign,
        timeout_seconds=cfg.run_timeout_s,
    )


def run_hardening(
    *,
    run_id: int,
    source_image_ref: str,
    target_registry: str,
    published_tag: str,
    auto_sign: bool,
    sb: Any,
    config: HardeningConfig | None = None,
) -> int:
    """Run the pipeline for an ALREADY-CREATED hardening_runs row.

    Args:
        run_id:           the hardening_runs row id (from create_run_record)
        source_image_ref: image to harden (informational for the MVP sample)
        target_registry:  ECR repo URL (push target, no tag)
        published_tag:    tag to publish under (e.g. v0.1.0)
        auto_sign:        if True, dispatch the signing workflow after publish
        sb:               supabase client (public or demo — selects the schema)
        config:           optional HardeningConfig; loaded from settings if None

    Pipeline failures are captured in the hardening_runs row, not raised.
    """
    cfg = config or load_hardening_config()
    cfg = _with_defaults(cfg, target_registry)
    instance_id = resolve_build_instance(cfg)
    log.info(
        "hardening_run #%s started (source=%s target=%s:%s auto_sign=%s)",
        run_id,
        source_image_ref,
        target_registry,
        published_tag,
        auto_sign,
    )

    ctx = HardenContext(
        hardening_run_id=run_id,
        source_image_ref=source_image_ref,
        target_registry=target_registry,
        published_tag=published_tag,
        build_instance_id=instance_id,
        aws_region=cfg.aws_region,
        sbom_bucket=cfg.sbom_bucket or None,
        auto_sign=auto_sign,
    )
    strategy = ImageHardenStrategy(config=cfg, emit_fn=_log_emitter)
    started_at = utcnow()

    outcome = _run_lifecycle(sb, run_id, strategy, ctx, started_at=started_at)

    # 4. Best-effort auto-sign AFTER a successful publish.
    if auto_sign and outcome.status == "success" and ctx.published_digest:
        dispatched, msg = dispatch_signing_workflow(
            cfg,
            github_pat=getattr(settings, "github_pat", ""),
            image_digest=ctx.published_digest,
            image_tag=published_tag,
            sbom_bucket=ctx.sbom_bucket or cfg.sbom_bucket,
        )
        outcome.sign_dispatched = dispatched
        try:
            set_sign_dispatched(sb, run_id, dispatched)
        except Exception:  # noqa: BLE001, S110
            pass
        log.info("hardening_run #%s auto-sign: dispatched=%s (%s)", run_id, dispatched, msg)

    finalize_hardening_run(sb, run_id, outcome, started_at=started_at)
    log.info("hardening_run #%s finished: status=%s", run_id, outcome.status)
    return run_id


def _run_lifecycle(
    sb: Any,
    run_id: int,
    strategy: ImageHardenStrategy,
    ctx: HardenContext,
    *,
    started_at,
) -> HardeningOutcome:
    """Run the 5 phases, mapping results into a HardeningOutcome. Any unhandled
    exception is captured as a failed outcome so the run always finalizes."""
    try:
        # Pre-flight
        set_status(sb, run_id, "preflight")
        pf = strategy.pre_flight_check(ctx)
        if not pf.ready:
            return HardeningOutcome(
                status="failed", error_message=pf.blocking_reason or "pre-flight failed"
            )

        # Backup
        backup = strategy.backup(ctx)
        ctx.backup_reference = backup.backup_reference

        # Execute (build → push → SBOM)
        set_status(sb, run_id, "building")
        steps = strategy.execute(ctx)
        if any(s.status == "failed" for s in steps):
            rollback = strategy.rollback(ctx)
            return HardeningOutcome(
                status="rolled_back" if rollback else "failed",
                step_results=steps,
                rollback_results=rollback,
                backup_reference=ctx.backup_reference,
                error_message="a build/publish step failed",
            )

        # Record publish + SBOM key as we learn them
        if ctx.published_digest:
            try:
                set_published(
                    sb,
                    run_id,
                    published_digest=ctx.published_digest,
                    published_tag=ctx.published_tag,
                )
            except Exception:  # noqa: BLE001, S110
                pass

        # Validate (scan gate)
        set_status(sb, run_id, "scanning")
        validations = strategy.validate(ctx)
        gate_failed = any((not v.passed) for v in validations)

        sbom_key = f"sboms/{ctx.published_digest}.spdx.json" if ctx.published_digest else None
        if sbom_key:
            try:
                set_sbom_key(sb, run_id, sbom_key)
            except Exception:  # noqa: BLE001, S110
                pass

        if gate_failed:
            rollback = strategy.rollback(ctx)
            return HardeningOutcome(
                status="rolled_back" if rollback else "failed",
                step_results=steps,
                validation_results=validations,
                rollback_results=rollback,
                published_digest=ctx.published_digest,
                published_tag=ctx.published_tag,
                sbom_s3_key=sbom_key,
                scan_summary={"gate": "failed"},
                backup_reference=ctx.backup_reference,
                error_message="scan gate failed (CRITICAL/HIGH findings)",
            )

        # Success
        return HardeningOutcome(
            status="success",
            step_results=steps,
            validation_results=validations,
            published_digest=ctx.published_digest,
            published_tag=ctx.published_tag,
            sbom_s3_key=sbom_key,
            scan_summary={"gate": "passed"},
            backup_reference=ctx.backup_reference,
        )
    except Exception as e:  # noqa: BLE001
        log.exception("hardening_run #%s crashed", run_id)
        return HardeningOutcome(
            status="failed",
            error_message=f"orchestrator crashed: {type(e).__name__}: {str(e)[:400]}",
        )


def _with_defaults(cfg: HardeningConfig, target_registry: str) -> HardeningConfig:
    """Fill ecr_repository_url from the trigger's target_registry when config
    didn't carry it (the trigger is the source of truth for the push target)."""
    if not cfg.ecr_repository_url and target_registry:
        from dataclasses import replace  # noqa: PLC0415

        return replace(cfg, ecr_repository_url=target_registry)
    return cfg
