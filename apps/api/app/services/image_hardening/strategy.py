"""ImageHardenStrategy — the deterministic hardening pipeline, 5 phases.

Reuses the fixer engine as a library:
  - BaseFixStrategy contract shape (pre_flight → backup → execute → validate →
    rollback), though this strategy is driven by the hardening orchestrator, not
    run_fixer.
  - RemoteExecutor (SSM) to run commands on the build EC2.
  - validate_command (safety) before every dispatch.
  - The result models (StepResult, ValidationResult, ...).

INSTANCE-AGNOSTIC (ephemeral-ready): the strategy never resolves the build box.
It uses ctx.build_instance_id, which the orchestrator injects. Swapping to an
ephemeral-box-per-build model later requires NO change here.

The commands are DETERMINISTIC (authored here), not LLM-generated — a key
difference from the vulnerability fixer.
"""

from __future__ import annotations

from app.agents.fixer.config import FixerConfig
from app.agents.fixer.safety import validate_command
from app.agents.fixer.tools.remote_exec import (
    CommandTimeoutError,
    RemoteExecError,
    RemoteExecutor,
)

from .config import HardeningConfig
from .models import (
    BackupResult,
    HardenContext,
    PreFlightResult,
    RollbackResult,
    StepResult,
    ValidationResult,
    utcnow,
)

# Trace identity — NOT "sub-agent-4". Isolation guarantee #6.
_TRACE_AGENT = "image-hardening"


class ImageHardenStrategy:
    """Hardening pipeline for a container base image.

    Phases mirror BaseFixStrategy. The orchestrator calls them in order and
    maps results into a HardeningOutcome + persists to hardening_runs.
    """

    name = "Image Hardening"
    strategy_key = "image_harden"

    def __init__(self, *, config: HardeningConfig, emit_fn) -> None:
        self.config = config
        self.emit_fn = emit_fn
        # RemoteExecutor expects a FixerConfig for its timeout knobs. We reuse
        # it purely for those knobs — this does NOT route through the fixer.
        self._exec_config = FixerConfig(run_timeout_s=config.run_timeout_s)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _emit(self, ctx: HardenContext, event_type: str, message: str) -> None:
        try:
            self.emit_fn(str(ctx.hardening_run_id), _TRACE_AGENT, event_type, message)
        except Exception:  # noqa: BLE001, S110
            pass

    def _executor(self, ctx: HardenContext) -> RemoteExecutor:
        return RemoteExecutor(
            ctx.build_instance_id,
            region=ctx.aws_region,
            config=self._exec_config,
            emit_fn=self.emit_fn,
            run_id=str(ctx.hardening_run_id),
        )

    def _run(self, executor: RemoteExecutor, command: str, *, workdir: str, timeout_s: int):
        """Safety-validate then dispatch one command. Returns the CommandResult
        or raises. Every command passes validate_command first (reused safety)."""
        verdict = validate_command(command, working_directory=workdir)
        if not verdict.allowed:
            raise RemoteExecError(f"safety blocked: {verdict.reason}")
        return executor.run_command(command, working_directory=workdir, timeout_s=timeout_s)

    def _build_dir(self, ctx: HardenContext) -> str:
        return ctx.build_directory or self.config.default_build_directory

    def _dockerfile(self, ctx: HardenContext) -> str:
        return ctx.dockerfile_path or self.config.default_dockerfile_path

    def _image_ref(self, ctx: HardenContext) -> str:
        """Full ECR ref with tag: <registry>:<tag>."""
        return f"{ctx.target_registry}:{ctx.published_tag}"

    # ==================================================================
    # Phase 1 — pre-flight
    # ==================================================================
    def pre_flight_check(self, ctx: HardenContext) -> PreFlightResult:
        executor = self._executor(ctx)

        if not executor.is_reachable():
            return PreFlightResult(
                ready=False,
                blocking_reason=f"SSM agent on {ctx.build_instance_id} is not Online.",
            )
        self._emit(ctx, "MESSAGE", "✓ Pre-flight: build box reachable via SSM")

        wd = self._build_dir(ctx)
        # Verify docker, trivy, syft, cosign are present + Dockerfile exists.
        probes = [
            ("docker", "docker version --format '{{.Server.Version}}'"),
            ("trivy", "trivy --version 2>&1 | head -1"),
            ("syft", "syft version 2>&1 | head -1"),
        ]
        for tool, cmd in probes:
            try:
                r = self._run(executor, cmd, workdir=wd, timeout_s=60)
            except (RemoteExecError, CommandTimeoutError) as e:
                return PreFlightResult(
                    ready=False,
                    blocking_reason=f"{tool} probe failed: {type(e).__name__}: {e}",
                )
            if r.exit_code != 0:
                return PreFlightResult(
                    ready=False,
                    blocking_reason=f"{tool} not usable on build box (exit={r.exit_code})",
                )
        self._emit(ctx, "MESSAGE", "✓ Pre-flight: docker + trivy + syft present")

        df = self._dockerfile(ctx)
        try:
            r = self._run(
                executor, f"test -f '{df}' && echo YES || echo NO", workdir=wd, timeout_s=30
            )
        except (RemoteExecError, CommandTimeoutError) as e:
            return PreFlightResult(ready=False, blocking_reason=f"Dockerfile probe crashed: {e}")
        if "YES" not in (r.stdout or ""):
            return PreFlightResult(ready=False, blocking_reason=f"Dockerfile not found at {df}")
        self._emit(ctx, "MESSAGE", f"✓ Pre-flight: Dockerfile present at {df}")

        return PreFlightResult(ready=True)

    # ==================================================================
    # Phase 2 — backup
    # ==================================================================
    def backup(self, ctx: HardenContext) -> BackupResult:
        """Record the digest currently behind the target tag (if any), so
        rollback can re-point the tag. Non-fatal if the tag doesn't exist yet
        (first publish)."""
        executor = self._executor(ctx)
        image_ref = self._image_ref(ctx)
        wd = self._build_dir(ctx)

        prior_digest = ""
        probe = (
            f"docker manifest inspect {image_ref} "
            f"--verbose 2>/dev/null | grep -m1 '\"digest\"' || echo NONE"
        )
        try:
            r = self._run(executor, probe, workdir=wd, timeout_s=60)
            out = (r.stdout or "").strip()
            if out and "NONE" not in out:
                prior_digest = out
        except (RemoteExecError, CommandTimeoutError):
            # Non-fatal — first publish or registry probe hiccup.
            prior_digest = ""

        ref = f"tag:{image_ref}|prior:{prior_digest}" if prior_digest else "(no prior tag)"
        self._emit(ctx, "MESSAGE", f"💾 Backup: recorded prior state for {image_ref}")
        return BackupResult(
            backup_reference=ref,
            # "none" when there's no prior tag to roll back to (first publish);
            # otherwise the semantics are a tag re-point (closest enum: state_snapshot).
            backup_type="state_snapshot" if prior_digest else "none",
            original_path=image_ref,
            created_at=utcnow(),
        )

    # ==================================================================
    # Phase 3 — execute (build → push → SBOM → upload)
    # ==================================================================
    def execute(self, ctx: HardenContext) -> list[StepResult]:
        executor = self._executor(ctx)
        wd = self._build_dir(ctx)
        image_ref = self._image_ref(ctx)
        results: list[StepResult] = []

        def step(num: int, action: str, command: str, timeout_s: int) -> bool:
            started = utcnow()
            try:
                r = self._run(executor, command, workdir=wd, timeout_s=timeout_s)
            except (RemoteExecError, CommandTimeoutError) as e:
                results.append(
                    StepResult(
                        step_num=num,
                        action=action,
                        command=command,
                        stderr=f"{type(e).__name__}: {e}",
                        exit_code=1,
                        status="failed",
                        started_at=started,
                        finished_at=utcnow(),
                    )
                )
                return False
            results.append(
                StepResult(
                    step_num=num,
                    action=action,
                    command=command,
                    stdout=(r.stdout or "")[:4000],
                    stderr=(r.stderr or "")[:2000],
                    exit_code=r.exit_code,
                    duration_ms=r.duration_ms,
                    status="success" if r.exit_code == 0 else "failed",
                    started_at=started,
                    finished_at=utcnow(),
                    ssm_command_id=r.ssm_command_id,
                )
            )
            return r.exit_code == 0

        # 1. ECR login
        login = (
            f"aws ecr get-login-password --region {ctx.aws_region} "
            f"| docker login --username AWS --password-stdin "
            f"{ctx.target_registry.split('/')[0]}"
        )
        if not step(1, "ECR login", login, 120):
            return results

        # 2. docker build (hardened image)
        if not step(2, "docker build", f"docker build -t {image_ref} '{wd}'", 900):
            return results

        # 3. docker push
        if not step(3, "docker push", f"docker push {image_ref}", 600):
            return results

        # 4. resolve the pushed digest (needed for SBOM key + signing)
        digest_cmd = (
            f"docker inspect --format='{{{{index .RepoDigests 0}}}}' {image_ref} | cut -d'@' -f2"
        )
        if step(4, "resolve digest", digest_cmd, 60):
            digest = (
                (results[-1].stdout or "").strip().splitlines()[-1] if results[-1].stdout else ""
            )
            if digest.startswith("sha256:"):
                ctx.published_digest = digest
                self._emit(ctx, "MESSAGE", f"🔖 Published digest: {digest}")

        # 5. SBOM + upload (only if we have a digest + bucket)
        if ctx.published_digest and (ctx.sbom_bucket or self.config.sbom_bucket):
            bucket = ctx.sbom_bucket or self.config.sbom_bucket
            key = f"sboms/{ctx.published_digest}.spdx.json"
            sbom_cmd = f"syft {image_ref} -o spdx-json=/tmp/harden-sbom.spdx.json"
            if step(5, "generate SBOM", sbom_cmd, 300):
                step(
                    6,
                    "upload SBOM",
                    f"aws s3 cp /tmp/harden-sbom.spdx.json s3://{bucket}/{key}",
                    120,
                )

        return results

    # ==================================================================
    # Phase 4 — validate (trivy scan gate)
    # ==================================================================
    def validate(self, ctx: HardenContext) -> list[ValidationResult]:
        executor = self._executor(ctx)
        wd = self._build_dir(ctx)
        image_ref = self._image_ref(ctx)
        sev = self.config.scan_gate_severities

        # The scan GATE: exit 1 if any finding at the gate severities. This is
        # the mandatory re-scan equivalent (is_rescan=True).
        cmd = f"trivy image --severity {sev} --exit-code 1 --quiet {image_ref}"
        passed = False
        actual = ""
        try:
            r = self._run(executor, cmd, workdir=wd, timeout_s=600)
            passed = r.exit_code == 0  # exit 0 = no gated findings
            actual = f"exit={r.exit_code}; {(r.stdout or '')[:1000]}"
        except (RemoteExecError, CommandTimeoutError) as e:
            actual = f"{type(e).__name__}: {e}"
            passed = False

        return [
            ValidationResult(
                test_name=f"trivy scan gate ({sev})",
                method="cli",
                command=cmd,
                expected="0 CRITICAL/HIGH vulnerabilities (exit 0)",
                actual=actual,
                passed=passed,
                is_rescan=True,
            )
        ]

    # ==================================================================
    # Phase 5 — rollback (idempotent)
    # ==================================================================
    def rollback(self, ctx: HardenContext) -> list[RollbackResult]:
        """Re-point the tag to the prior digest recorded in backup, if any.
        Idempotent + safe if nothing was published / no prior existed."""
        if not ctx.backup_reference or "prior:" not in ctx.backup_reference:
            return []

        prior = ctx.backup_reference.split("prior:", 1)[1].strip()
        if not prior or not prior.startswith("sha256"):
            return []

        # For the MVP we record the rollback intent; actually re-pointing an
        # ECR tag to a prior digest is a registry operation we note but keep
        # conservative (no destructive retag in the demo slice).
        self._emit(
            ctx,
            "MESSAGE",
            f"↩ Rollback: prior digest for {self._image_ref(ctx)} was {prior} "
            f"(tag re-point left to operator in MVP).",
        )
        return [
            RollbackResult(
                step_num=1,
                action="record prior digest for tag re-point",
                command="(noop in MVP — operator re-points tag)",
                exit_code=0,
                status="success",
                started_at=utcnow(),
                finished_at=utcnow(),
            )
        ]
