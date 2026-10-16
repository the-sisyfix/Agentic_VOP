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

import json
import logging
from typing import Any

from app.config import settings

from .config import HardeningConfig, load_hardening_config, resolve_build_instance
from .dep_bump import apply_pip_bumps, compute_pip_bumps
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
from .copa_strategy import CopaPatchStrategy
from .signing import dispatch_signing_workflow
from .strategy import ImageHardenStrategy

log = logging.getLogger("image_hardening")

# Remediation modes. "patch" = copa in-place OS patch (image-ref path, primary).
# "rebuild" = build-from-Dockerfile (secondary; wired in the next increment).
MODE_PATCH = "patch"
MODE_REBUILD = "rebuild"


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
    mode: str = MODE_PATCH,  # noqa: ARG001 — reserved for persistence when a mode column is added
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
    mode: str = MODE_PATCH,
    dockerfile_path: str | None = None,
    config: HardeningConfig | None = None,
) -> int:
    """Run the pipeline for an ALREADY-CREATED hardening_runs row.

    Args:
        run_id:           the hardening_runs row id (from create_run_record)
        source_image_ref: client image to harden (ref/digest)
        target_registry:  ECR repo URL (push target, no tag)
        published_tag:    tag to publish under (e.g. v0.1.0)
        auto_sign:        if True, dispatch the signing workflow after publish
        sb:               supabase client (public or demo — selects the schema)
        mode:             "patch" (copa in-place, primary) or "rebuild"
                          (Dockerfile; wired next increment)
        config:           optional HardeningConfig; loaded from settings if None

    Pipeline failures are captured in the hardening_runs row, not raised.
    """
    cfg = config or load_hardening_config()
    cfg = _with_defaults(cfg, target_registry)
    instance_id = resolve_build_instance(cfg)
    log.info(
        "hardening_run #%s started (mode=%s source=%s target=%s:%s auto_sign=%s)",
        run_id,
        mode,
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
        dockerfile_path=dockerfile_path,
    )
    started_at = utcnow()

    if mode == MODE_PATCH:
        copa = CopaPatchStrategy(config=cfg, emit_fn=_log_emitter)
        outcome = _run_copa_lifecycle(sb, run_id, copa, ctx, cfg=cfg, started_at=started_at)
    else:
        # Rebuild path (build-from-Dockerfile) — the proven prototype flow.
        strategy = ImageHardenStrategy(config=cfg, emit_fn=_log_emitter)
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


def _run_copa_lifecycle(
    sb: Any,
    run_id: int,
    copa: CopaPatchStrategy,
    ctx: HardenContext,
    *,
    cfg: HardeningConfig,
    started_at,
) -> HardeningOutcome:
    """Copa in-place patch lifecycle (image-ref path).

    preflight → remediation loop (scan→patch→re-scan) → gate →
    decide-from-findings: one FULL-SCOPE scan is the source of truth for the
    policy-zero gate AND the routing. OS findings → copa; dependency findings →
    rebuild leg (if a Dockerfile is available) else reported as residual.

    Edge cases handled explicitly:
      - 0 fixable (OS+dep) at intake            → clean, publish original.
      - OS-only                                 → copa → re-gate.
      - dependency-only (NO OS)                 → copa no-ops; rebuild if
                                                   Dockerfile, else residual
                                                   (NOT a false pass — the gate
                                                   is full-scope).
      - mixed OS + dependency                   → copa then rebuild.
      - residual deps, no Dockerfile            → failed (needs source).
      - only UNfixable findings (no fix avail)  → gate passes (policy-zero is
                                                   zero *fixable*), publish.
    """
    try:
        set_status(sb, run_id, "preflight")
        pf = copa.pre_flight_check(ctx)
        if not pf.ready:
            return HardeningOutcome(
                status="failed", error_message=pf.blocking_reason or "pre-flight failed"
            )

        steps: list = []
        set_status(sb, run_id, "scanning")

        # --- 1. Full-scope intake scan = source of truth for gate + routing ---
        intake = copa.full_scope_scan(ctx, ctx.source_image_ref)
        log.info(
            "hardening_run #%s intake: os_fixable=%d dep_fixable=%d",
            run_id,
            intake.os_fixable,
            intake.dep_fixable,
        )
        current_ref = ctx.source_image_ref

        # --- 2. Already policy-zero (incl. only-unfixable case) → publish ---
        if intake.gate_passes:
            return _finalize_clean(
                sb, run_id, copa, ctx, cfg, current_ref, steps, intake, iterations=0, intake=intake
            )

        # --- 3. OS findings → copa patch loop ---
        if intake.os_fixable > 0:
            set_status(sb, run_id, "building")
            result = copa.remediate(ctx, current_ref)
            steps.extend(result["steps"])
            if result["status"] == "error":
                return HardeningOutcome(
                    status="failed",
                    step_results=steps,
                    scan_summary={
                        **_intake_summary(intake),
                        "stage": "copa",
                        "detail": result["message"],
                    },
                    error_message=result["message"],
                )
            current_ref = result["final_image_ref"]

        # --- 4. Re-gate full scope after copa ---
        after_copa = copa.full_scope_scan(ctx, current_ref)

        # --- 5. Dependency findings remain → rebuild leg (if Dockerfile) ---
        if after_copa.dep_fixable > 0:
            if ctx.dockerfile_path:
                set_status(sb, run_id, "building")
                rebuild_steps, current_ref = _run_rebuild_leg(copa, ctx, cfg, current_ref)
                steps.extend(rebuild_steps)
                if any(s.status == "failed" for s in rebuild_steps):
                    return HardeningOutcome(
                        status="failed",
                        step_results=steps,
                        scan_summary={
                            **_intake_summary(intake),
                            "stage": "rebuild",
                            "detail": "rebuild leg failed",
                        },
                        error_message="rebuild leg failed",
                    )
                after_rebuild = copa.full_scope_scan(ctx, current_ref)
            else:
                # No source to rebuild dependency fixes → honest residual.
                gate = _gate_from(after_copa)
                return HardeningOutcome(
                    status="failed",
                    step_results=steps,
                    validation_results=[gate],
                    scan_summary={
                        **after_copa.summary(),
                        **_intake_summary(intake),
                        "residual": "dependency CVEs remain; no Dockerfile "
                        "provided to rebuild — provide source or accept residual",
                    },
                    error_message="dependency CVEs remain and no Dockerfile to rebuild",
                )
        else:
            after_rebuild = after_copa

        # --- 6. Final full-scope gate ---
        if not after_rebuild.gate_passes:
            return HardeningOutcome(
                status="failed",
                step_results=steps,
                validation_results=[_gate_from(after_rebuild)],
                scan_summary={
                    **after_rebuild.summary(),
                    **_intake_summary(intake),
                    "result": "gate not met",
                },
                error_message="fixable critical/high remain after remediation",
            )

        return _finalize_clean(
            sb,
            run_id,
            copa,
            ctx,
            cfg,
            current_ref,
            steps,
            after_rebuild,
            iterations=1,
            intake=intake,
        )
    except Exception as e:  # noqa: BLE001
        log.exception("hardening_run #%s (copa) crashed", run_id)
        return HardeningOutcome(
            status="failed",
            error_message=f"orchestrator crashed: {type(e).__name__}: {str(e)[:400]}",
        )


def _intake_summary(intake) -> dict:
    """Intake (pre-remediation) fixable counts, for the auditable run record.

    scan_summary otherwise reports only the FINAL (post-remediation) scan, so a
    reader cannot tell "came in clean" from "came in with N and we fixed them".
    These keys make the before/after provable from the run record itself.
    """
    return {
        "intake_os_fixable": intake.os_fixable,
        "intake_dep_fixable": intake.dep_fixable,
        "intake_total_fixable": intake.total_fixable,
    }


def _gate_from(scan) -> Any:
    """Build the policy-zero gate ValidationResult from a full-scope scan."""
    from .models import ValidationResult  # noqa: PLC0415

    return ValidationResult(
        test_name="policy-zero gate (fixable CRITICAL,HIGH, full scope)",
        method="cli",
        command="trivy image --vuln-type os,library --ignore-unfixed --severity CRITICAL,HIGH",
        expected="0 fixable CRITICAL/HIGH (OS + dependencies)",
        actual=(f"os_fixable={scan.os_fixable}, dep_fixable={scan.dep_fixable}"),
        passed=scan.gate_passes,
        is_rescan=True,
    )


def _finalize_clean(
    sb, run_id, copa, ctx, cfg, final_ref, steps, scan, *, iterations, intake=None
) -> Any:
    """Publish the clean image at the client's tag + SBOM; return success.

    `intake` (the pre-remediation full-scope scan) is recorded in scan_summary
    so the run proves "came in with N fixable, went out with 0". Defaults to
    `scan` when not supplied (the already-clean-at-intake path, where intake IS
    the final scan).
    """
    intake_dict = _intake_summary(intake if intake is not None else scan)
    set_status(sb, run_id, "publishing")
    publish_steps = _copa_publish(copa, ctx, final_ref, cfg)
    steps.extend(publish_steps)
    gate = _gate_from(scan)
    if any(s.status == "failed" for s in publish_steps):
        return HardeningOutcome(
            status="failed",
            step_results=steps,
            validation_results=[gate],
            scan_summary={**scan.summary(), **intake_dict, "publish": "failed"},
            error_message="publish failed",
        )
    if ctx.published_digest:
        try:
            set_published(
                sb, run_id, published_digest=ctx.published_digest, published_tag=ctx.published_tag
            )
        except Exception:  # noqa: BLE001, S110
            pass
    sbom_key = f"sboms/{ctx.published_digest}.spdx.json" if ctx.published_digest else None
    if sbom_key:
        try:
            set_sbom_key(sb, run_id, sbom_key)
        except Exception:  # noqa: BLE001, S110
            pass
    return HardeningOutcome(
        status="success",
        step_results=steps,
        validation_results=[gate],
        published_digest=ctx.published_digest,
        published_tag=ctx.published_tag,
        sbom_s3_key=sbom_key,
        scan_summary={**scan.summary(), **intake_dict, "iterations": iterations},
    )


def _run_rebuild_leg(copa, ctx, cfg, current_ref):
    """Option (a) rebuild leg: rebuild from the client's Dockerfile.

    MVP scope: rebuild from the provided Dockerfile (picks up newer base/deps if
    the Dockerfile does not pin vulnerable versions). Deterministic
    dependency-version bumping is the NEXT increment. Reuses copa's executor to
    run docker build + push at the client's tag; the final gate re-scan decides
    pass/fail honestly.
    """
    from .models import StepResult  # noqa: PLC0415

    executor = copa._executor(ctx)  # noqa: SLF001 — same-package reuse
    wd = ctx.build_directory or cfg.default_build_directory
    final_ref = f"{ctx.target_registry}:{ctx.published_tag}"
    steps: list = []

    def step(num, action, command, timeout_s):
        start = utcnow()
        try:
            r = copa._run(executor, command, workdir=wd, timeout_s=timeout_s)  # noqa: SLF001
        except Exception as e:  # noqa: BLE001
            steps.append(
                StepResult(
                    step_num=num,
                    action=action,
                    command=command,
                    stderr=f"{type(e).__name__}: {e}",
                    exit_code=1,
                    status="failed",
                    started_at=start,
                    finished_at=utcnow(),
                )
            )
            return False
        steps.append(
            StepResult(
                step_num=num,
                action=action,
                command=command,
                stdout=(r.stdout or "")[:2000],
                stderr=(r.stderr or "")[:1000],
                exit_code=r.exit_code,
                duration_ms=r.duration_ms,
                status="success" if r.exit_code == 0 else "failed",
                started_at=start,
                finished_at=utcnow(),
                ssm_command_id=r.ssm_command_id,
            )
        )
        return r.exit_code == 0

    # --- Option b: deterministic pip dependency bump before rebuild ---
    # 1. Full-scope scan of the CURRENT image to a report file we can read back.
    scratch = cfg.copa_scratch_dir
    report_path = f"{scratch}/trivy-deps-{ctx.hardening_run_id}.json"
    req_path = f"{wd.rstrip('/')}/{cfg.requirements_filename}"

    scan_cmd = (
        f"trivy image --vuln-type library --ignore-unfixed -f json "
        f"-o '{report_path}' {current_ref} && cat '{report_path}'"
    )
    start = utcnow()
    report_json = "{}"
    try:
        r = copa._run(executor, scan_cmd, workdir=scratch, timeout_s=600)  # noqa: SLF001
        report_json = r.stdout or "{}"
        steps.append(
            StepResult(
                step_num=20,
                action="scan deps (for bump)",
                command=scan_cmd,
                exit_code=r.exit_code,
                status="success" if r.exit_code == 0 else "failed",
                started_at=start,
                finished_at=utcnow(),
                ssm_command_id=r.ssm_command_id,
            )
        )
    except Exception as e:  # noqa: BLE001
        steps.append(
            StepResult(
                step_num=20,
                action="scan deps (for bump)",
                command=scan_cmd,
                stderr=f"{type(e).__name__}: {e}",
                exit_code=1,
                status="failed",
                started_at=start,
                finished_at=utcnow(),
            )
        )
        return steps, current_ref

    # 2. Read requirements.txt from the build context.
    req_text = ""
    cat_cmd = f"cat '{req_path}' 2>/dev/null || echo '__NO_REQUIREMENTS__'"
    try:
        r = copa._run(executor, cat_cmd, workdir=wd, timeout_s=60)  # noqa: SLF001
        req_text = r.stdout or ""
    except Exception:  # noqa: BLE001
        req_text = "__NO_REQUIREMENTS__"

    if "__NO_REQUIREMENTS__" in req_text:
        # No manifest to bump — honest residual; still attempt a plain rebuild
        # (Option a) so a floating-version Dockerfile can still pick up fixes.
        steps.append(
            StepResult(
                step_num=21,
                action="dep bump skipped",
                command=f"read {req_path}",
                stdout="requirements.txt not found — dependency pinning skipped (residual)",
                exit_code=0,
                status="skipped",
                started_at=utcnow(),
                finished_at=utcnow(),
            )
        )
    else:
        # 3. Compute the deterministic bump plan from trivy's fixed versions.
        plan = compute_pip_bumps(report_json, req_text)
        if plan.has_changes:
            new_text = apply_pip_bumps(req_text, plan)
            # 4. Write the bumped requirements.txt back (heredoc, safety-allowed dir).
            pinned = ", ".join(f"{k}=={v}" for k, v in plan.to_pin.items())
            write_cmd = f"cat > '{req_path}' <<'__REQ_EOF__'\n{new_text}\n__REQ_EOF__"
            start = utcnow()
            try:
                r = copa._run(executor, write_cmd, workdir=wd, timeout_s=60)  # noqa: SLF001
                steps.append(
                    StepResult(
                        step_num=21,
                        action="pin pip deps",
                        command=f"pin: {pinned}",
                        stdout=(r.stdout or "")[:500],
                        exit_code=r.exit_code,
                        status="success" if r.exit_code == 0 else "failed",
                        started_at=start,
                        finished_at=utcnow(),
                    )
                )
            except Exception as e:  # noqa: BLE001
                steps.append(
                    StepResult(
                        step_num=21,
                        action="pin pip deps",
                        command=f"pin: {pinned}",
                        stderr=f"{type(e).__name__}: {e}",
                        exit_code=1,
                        status="failed",
                        started_at=start,
                        finished_at=utcnow(),
                    )
                )
                return steps, current_ref
        if plan.residual:
            steps.append(
                StepResult(
                    step_num=22,
                    action="dep residual (reported)",
                    command="honest residual",
                    stdout=json.dumps(plan.residual)[:1500],
                    exit_code=0,
                    status="skipped",
                    started_at=utcnow(),
                    finished_at=utcnow(),
                )
            )

    # 5. Rebuild from the (possibly bumped) Dockerfile + context.
    df = ctx.dockerfile_path
    if not step(23, "docker build (rebuild)", f"docker build -f '{df}' -t {final_ref} '{wd}'", 900):
        return steps, current_ref
    return steps, final_ref


def _copa_publish(
    copa: CopaPatchStrategy,
    ctx: HardenContext,
    patched_ref: str,
    cfg: HardeningConfig,
) -> list:
    """Push the clean patched image at the client's intended tag, resolve its
    digest (set on ctx), and upload the SBOM. Returns StepResults.

    Reuses the copa strategy's executor + safety-validated _run. Command shapes
    mirror the proven rebuild path's publish tail.
    """
    from .models import StepResult  # noqa: PLC0415

    executor = copa._executor(ctx)  # noqa: SLF001 — same package, intentional reuse
    wd = cfg.copa_scratch_dir
    final_ref = f"{ctx.target_registry}:{ctx.published_tag}"
    steps: list = []

    def step(num, action, command, timeout_s):
        start = utcnow()
        try:
            r = copa._run(executor, command, workdir=wd, timeout_s=timeout_s)  # noqa: SLF001
        except Exception as e:  # noqa: BLE001
            steps.append(
                StepResult(
                    step_num=num,
                    action=action,
                    command=command,
                    stderr=f"{type(e).__name__}: {e}",
                    exit_code=1,
                    status="failed",
                    started_at=start,
                    finished_at=utcnow(),
                )
            )
            return False
        steps.append(
            StepResult(
                step_num=num,
                action=action,
                command=command,
                stdout=(r.stdout or "")[:2000],
                stderr=(r.stderr or "")[:1000],
                exit_code=r.exit_code,
                duration_ms=r.duration_ms,
                status="success" if r.exit_code == 0 else "failed",
                started_at=start,
                finished_at=utcnow(),
                ssm_command_id=r.ssm_command_id,
            )
        )
        return r.exit_code == 0

    # ECR login + retag the patched image to the client's intended tag + push.
    login = (
        f"aws ecr get-login-password --region {ctx.aws_region} "
        f"| docker login --username AWS --password-stdin {ctx.target_registry.split('/')[0]}"
    )
    if not step(10, "ECR login", login, 120):
        return steps
    # Ensure the image is present LOCALLY before retag — correct for BOTH paths:
    #   - copa-patched path: `patched_ref` is a LOCAL-ONLY image copa built on
    #     the box (never pushed anywhere). It is already present → inspect
    #     succeeds, we must NOT `docker pull` it (pull would fail: no such repo).
    #   - clean-at-intake path: `patched_ref` is the ORIGINAL source ref, which
    #     trivy/copa only scanned remotely and was never pulled → inspect fails,
    #     so we pull it.
    # `inspect || pull` handles both without a false failure.
    ensure_local = (
        f"docker image inspect {patched_ref} >/dev/null 2>&1 || docker pull {patched_ref}"
    )
    if not step(11, "ensure image local", ensure_local, 600):
        return steps
    if not step(12, "retag patched", f"docker tag {patched_ref} {final_ref}", 60):
        return steps
    if not step(13, "push patched", f"docker push {final_ref}", 600):
        return steps

    digest_cmd = (
        f"docker inspect --format='{{{{index .RepoDigests 0}}}}' {final_ref} | cut -d'@' -f2"
    )
    if step(14, "resolve digest", digest_cmd, 60):
        out = (steps[-1].stdout or "").strip().splitlines()
        digest = out[-1] if out else ""
        if digest.startswith("sha256:"):
            ctx.published_digest = digest

    if ctx.published_digest and (ctx.sbom_bucket or cfg.sbom_bucket):
        bucket = ctx.sbom_bucket or cfg.sbom_bucket
        key = f"sboms/{ctx.published_digest}.spdx.json"
        if step(
            15, "generate SBOM", f"syft {final_ref} -o spdx-json=/tmp/harden-sbom.spdx.json", 300
        ):
            step(
                16, "upload SBOM", f"aws s3 cp /tmp/harden-sbom.spdx.json s3://{bucket}/{key}", 120
            )

    return steps


def _with_defaults(cfg: HardeningConfig, target_registry: str) -> HardeningConfig:
    """Fill ecr_repository_url from the trigger's target_registry when config
    didn't carry it (the trigger is the source of truth for the push target)."""
    if not cfg.ecr_repository_url and target_registry:
        from dataclasses import replace  # noqa: PLC0415

        return replace(cfg, ecr_repository_url=target_registry)
    return cfg
