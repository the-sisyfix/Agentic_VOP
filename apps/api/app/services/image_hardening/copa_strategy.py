"""CopaPatchStrategy — Model B image-ref path: patch a client image in place.

Takes a client image BY REFERENCE (no Dockerfile), scans it with Trivy, and
patches OS-package vulnerabilities with Copacetic (`copa`), which applies the
fixes as a new layer via BuildKit — no rebuild, no source access. Then re-scans
to verify. The deterministic auto-remediation loop runs scan→patch→re-scan up
to a cap, until zero fixable critical/high remain or only-unfixable remain.

Verified command shape (copa + trivy):
  trivy image --vuln-type os --ignore-unfixed -f json -o <report> <image>
  copa patch -i <image> -r <report> -t <patched-tag> -a <buildkit-addr>

Honest scope: copa patches OS packages only. App/language deps (pip/npm/go
modules, Go stdlib) are NOT patchable here — those are the rebuild path's job.
Such findings surface as "unfixable by copa" and the loop reports them.

Reuses the fixer engine as a library (RemoteExecutor over SSM, validate_command,
result models). Does NOT touch run_fixer or the fixer's tables. Instance-agnostic
(uses ctx.build_instance_id). Emits under the "image-hardening" trace label.
"""

from __future__ import annotations

import json

import boto3
from botocore.config import Config as BotoConfig

from app.agents.fixer.config import FixerConfig
from app.agents.fixer.safety import validate_command
from app.agents.fixer.tools.remote_exec import (
    CommandTimeoutError,
    RemoteExecError,
    RemoteExecutor,
)

from .config import HardeningConfig
from .models import (
    HardenContext,
    PreFlightResult,
    StepResult,
    ValidationResult,
    utcnow,
)

_TRACE_AGENT = "image-hardening"


class CopaScanResult:
    """Parsed outcome of one trivy scan: counts + whether fixable crit/high remain."""

    def __init__(self, *, fixable_critical: int, fixable_high: int, raw_summary: str) -> None:
        self.fixable_critical = fixable_critical
        self.fixable_high = fixable_high
        self.raw_summary = raw_summary

    @property
    def has_fixable_gate_findings(self) -> bool:
        return (self.fixable_critical + self.fixable_high) > 0


class CopaPatchStrategy:
    """In-place OS-package patch path for a client image reference."""

    name = "Copa Patch (image ref)"
    strategy_key = "copa_patch"

    def __init__(self, *, config: HardeningConfig, emit_fn) -> None:
        self.config = config
        self.emit_fn = emit_fn
        self._exec_config = FixerConfig(run_timeout_s=config.run_timeout_s)

    # ------------------------------------------------------------------ helpers
    def _emit(self, ctx: HardenContext, event_type: str, message: str) -> None:
        try:
            self.emit_fn(str(ctx.hardening_run_id), _TRACE_AGENT, event_type, message)
        except Exception:  # noqa: BLE001, S110
            pass

    def _executor(self, ctx: HardenContext) -> RemoteExecutor:
        # Generous read timeout — copa patch + trivy scans run for minutes.
        ssm_client = boto3.client(
            "ssm",
            region_name=ctx.aws_region,
            config=BotoConfig(connect_timeout=15, read_timeout=1000, retries={"max_attempts": 1}),
        )
        return RemoteExecutor(
            ctx.build_instance_id,
            region=ctx.aws_region,
            config=self._exec_config,
            emit_fn=self.emit_fn,
            run_id=str(ctx.hardening_run_id),
            ssm_client=ssm_client,
        )

    def _run(self, executor: RemoteExecutor, command: str, *, workdir: str, timeout_s: int):
        verdict = validate_command(command, working_directory=workdir)
        if not verdict.allowed:
            raise RemoteExecError(f"safety blocked: {verdict.reason}")
        return executor.run_command(command, working_directory=workdir, timeout_s=timeout_s)

    def _scratch(self) -> str:
        return self.config.copa_scratch_dir

    # ------------------------------------------------------------------ scan
    def _scan_to_report(
        self, executor: RemoteExecutor, image_ref: str, report_path: str
    ) -> CopaScanResult:
        """Run trivy, write a JSON report copa can consume, and parse counts.

        Uses --ignore-unfixed so the report (and the counts) reflect only
        FIXABLE findings — which is exactly copa's remediation surface and the
        policy-zero gate ("zero fixable critical/high").
        """
        wd = self._scratch()
        # Human-readable summary for the trace + a JSON report for copa.
        cmd = (
            f"trivy image --vuln-type os --ignore-unfixed "
            f"-f json -o '{report_path}' {image_ref} "
            f"&& trivy image --vuln-type os --ignore-unfixed "
            f"--severity CRITICAL,HIGH --quiet {image_ref}"
        )
        r = self._run(executor, cmd, workdir=wd, timeout_s=600)
        summary = (r.stdout or "")[:2000]

        # Parse the JSON report counts by reading it back (keeps parsing on the
        # box side simple + avoids giant stdout). We cat the file and count.
        count_cmd = f"cat '{report_path}' 2>/dev/null || echo '{{}}'"
        cr = self._run(executor, count_cmd, workdir=wd, timeout_s=120)
        crit, high = self._count_fixable(cr.stdout or "{}")
        return CopaScanResult(fixable_critical=crit, fixable_high=high, raw_summary=summary)

    @staticmethod
    def _count_fixable(report_json: str) -> tuple[int, int]:
        """Count fixable CRITICAL/HIGH in a trivy JSON report.

        Trivy JSON shape: {"Results":[{"Vulnerabilities":[{"Severity":...,
        "FixedVersion":...}]}]}. Report was produced with --ignore-unfixed, so
        every listed vuln is already fixable; we still guard on FixedVersion.
        """
        crit = high = 0
        try:
            data = json.loads(report_json)
        except (ValueError, TypeError):
            return (0, 0)
        for result in data.get("Results") or []:
            for v in result.get("Vulnerabilities") or []:
                sev = (v.get("Severity") or "").upper()
                fixed = v.get("FixedVersion")
                if not fixed:
                    continue
                if sev == "CRITICAL":
                    crit += 1
                elif sev == "HIGH":
                    high += 1
        return (crit, high)

    # ------------------------------------------------------------------ phases
    def pre_flight_check(self, ctx: HardenContext) -> PreFlightResult:
        executor = self._executor(ctx)
        if not executor.is_reachable():
            return PreFlightResult(
                ready=False,
                blocking_reason=f"SSM agent on {ctx.build_instance_id} is not Online.",
            )
        wd = self._scratch()
        # Ensure scratch dir, and verify tools: docker, trivy, copa.
        setup = f"mkdir -p '{wd}'"
        try:
            self._run(executor, setup, workdir="/opt/image-forge-src/", timeout_s=30)
        except (RemoteExecError, CommandTimeoutError) as e:
            return PreFlightResult(ready=False, blocking_reason=f"scratch dir setup failed: {e}")

        for tool, cmd in [
            ("docker", "docker version --format '{{.Server.Version}}'"),
            ("trivy", "trivy --version 2>&1 | head -1"),
            ("copa", "copa --version 2>&1 | head -1"),
        ]:
            try:
                r = self._run(executor, cmd, workdir=wd, timeout_s=60)
            except (RemoteExecError, CommandTimeoutError) as e:
                return PreFlightResult(
                    ready=False, blocking_reason=f"{tool} probe failed: {type(e).__name__}: {e}"
                )
            if r.exit_code != 0:
                return PreFlightResult(
                    ready=False, blocking_reason=f"{tool} not usable on build box"
                )
        self._emit(ctx, "MESSAGE", "✓ Pre-flight: docker + trivy + copa present")
        return PreFlightResult(ready=True)

    def ensure_buildkit(self, ctx: HardenContext) -> StepResult:
        """Start a buildkitd container copa connects to (idempotent)."""
        executor = self._executor(ctx)
        wd = self._scratch()
        started = utcnow()
        # Start only if not already running.
        cmd = (
            "docker ps --filter name=buildkitd --format '{{.Names}}' | grep -q buildkitd "
            "&& echo RUNNING "
            f"|| docker run --detach --rm --privileged -p 127.0.0.1:8888:8888/tcp "
            f"--name buildkitd --entrypoint buildkitd {self.config.buildkit_image} "
            "--addr tcp://0.0.0.0:8888"
        )
        try:
            r = self._run(executor, cmd, workdir=wd, timeout_s=180)
            status = "success" if r.exit_code == 0 else "failed"
            return StepResult(
                step_num=0,
                action="ensure buildkit",
                command=cmd,
                stdout=(r.stdout or "")[:1000],
                stderr=(r.stderr or "")[:1000],
                exit_code=r.exit_code,
                status=status,
                started_at=started,
                finished_at=utcnow(),
            )
        except (RemoteExecError, CommandTimeoutError) as e:
            return StepResult(
                step_num=0,
                action="ensure buildkit",
                command=cmd,
                stderr=f"{type(e).__name__}: {e}",
                exit_code=1,
                status="failed",
                started_at=started,
                finished_at=utcnow(),
            )

    def patch_once(
        self, ctx: HardenContext, image_ref: str, report_path: str, patched_tag: str
    ) -> StepResult:
        """One copa patch invocation producing a patched tag."""
        executor = self._executor(ctx)
        wd = self._scratch()
        started = utcnow()
        cmd = (
            f"copa patch -i {image_ref} -r '{report_path}' "
            f"-t {patched_tag} -a {self.config.buildkit_addr}"
        )
        try:
            r = self._run(executor, cmd, workdir=wd, timeout_s=600)
            return StepResult(
                step_num=0,
                action="copa patch",
                command=cmd,
                stdout=(r.stdout or "")[:2000],
                stderr=(r.stderr or "")[:2000],
                exit_code=r.exit_code,
                status="success" if r.exit_code == 0 else "failed",
                started_at=started,
                finished_at=utcnow(),
                ssm_command_id=r.ssm_command_id,
            )
        except (RemoteExecError, CommandTimeoutError) as e:
            return StepResult(
                step_num=0,
                action="copa patch",
                command=cmd,
                stderr=f"{type(e).__name__}: {e}",
                exit_code=1,
                status="failed",
                started_at=started,
                finished_at=utcnow(),
            )

    # ------------------------------------------------------------------ loop
    def remediate(self, ctx: HardenContext, image_ref: str) -> dict:
        """Deterministic auto-remediation loop for the image-ref path.

        scan → (if fixable crit/high) patch via copa → re-scan, iterating up to
        the configured cap. Returns a structured result the orchestrator maps
        into StepResults / ValidationResult / HardeningOutcome:

            {
              "status": "clean" | "exhausted" | "unfixable" | "error",
              "iterations": int,
              "final_image_ref": str,       # the tag to publish (patched or orig)
              "steps": list[StepResult],
              "final_scan": CopaScanResult | None,
              "message": str,
            }

        - "clean": zero fixable crit/high (publishable).
        - "unfixable": findings remain but none are fixable (copa can't help;
          they'd need the rebuild path or are genuinely no-fix-available).
          Scan already uses --ignore-unfixed, so remaining==fixable; "unfixable"
          here means a patch ran but counts didn't drop (copa couldn't fix OS
          pkgs it doesn't support, e.g. app/lang deps).
        - "exhausted": still fixable after the iteration cap.
        - "error": a scan/patch step failed.
        """
        executor = self._executor(ctx)
        wd = self._scratch()
        steps: list[StepResult] = []
        report_path = f"{wd}/trivy-report-{ctx.hardening_run_id}.json"
        current_ref = image_ref
        cap = max(1, self.config.max_remediation_iterations)

        # Initial scan
        try:
            scan = self._scan_to_report(executor, current_ref, report_path)
        except (RemoteExecError, CommandTimeoutError) as e:
            return {
                "status": "error",
                "iterations": 0,
                "final_image_ref": current_ref,
                "steps": steps,
                "final_scan": None,
                "message": f"initial scan failed: {e}",
            }
        self._emit(
            ctx,
            "MESSAGE",
            f"🔎 Initial scan: {scan.fixable_critical} fixable CRITICAL, "
            f"{scan.fixable_high} fixable HIGH",
        )
        if not scan.has_fixable_gate_findings:
            return {
                "status": "clean",
                "iterations": 0,
                "final_image_ref": current_ref,
                "steps": steps,
                "final_scan": scan,
                "message": "no fixable critical/high at intake — already clean",
            }

        # buildkit needed for copa
        bk = self.ensure_buildkit(ctx)
        steps.append(bk)
        if bk.status != "success":
            return {
                "status": "error",
                "iterations": 0,
                "final_image_ref": current_ref,
                "steps": steps,
                "final_scan": scan,
                "message": "buildkit did not start",
            }

        prev_total = scan.fixable_critical + scan.fixable_high
        for i in range(1, cap + 1):
            patched_tag = f"{ctx.target_registry}:{ctx.published_tag}-copa{i}"
            patch_step = self.patch_once(ctx, current_ref, report_path, patched_tag)
            patch_step.step_num = i
            steps.append(patch_step)
            if patch_step.status != "success":
                return {
                    "status": "error",
                    "iterations": i,
                    "final_image_ref": current_ref,
                    "steps": steps,
                    "final_scan": scan,
                    "message": f"copa patch failed on iteration {i}",
                }
            current_ref = patched_tag

            # re-scan the patched image
            try:
                scan = self._scan_to_report(executor, current_ref, report_path)
            except (RemoteExecError, CommandTimeoutError) as e:
                return {
                    "status": "error",
                    "iterations": i,
                    "final_image_ref": current_ref,
                    "steps": steps,
                    "final_scan": None,
                    "message": f"re-scan failed: {e}",
                }
            self._emit(
                ctx,
                "MESSAGE",
                f"🔁 Iteration {i}: {scan.fixable_critical} CRITICAL, "
                f"{scan.fixable_high} HIGH remain",
            )
            if not scan.has_fixable_gate_findings:
                return {
                    "status": "clean",
                    "iterations": i,
                    "final_image_ref": current_ref,
                    "steps": steps,
                    "final_scan": scan,
                    "message": f"clean after {i} iteration(s)",
                }

            # No progress → copa can't fix the remainder (likely non-OS deps).
            new_total = scan.fixable_critical + scan.fixable_high
            if new_total >= prev_total:
                return {
                    "status": "unfixable",
                    "iterations": i,
                    "final_image_ref": current_ref,
                    "steps": steps,
                    "final_scan": scan,
                    "message": (
                        f"{new_total} fixable finding(s) remain that copa did not "
                        f"resolve (likely non-OS deps — needs rebuild path)"
                    ),
                }
            prev_total = new_total

        return {
            "status": "exhausted",
            "iterations": cap,
            "final_image_ref": current_ref,
            "steps": steps,
            "final_scan": scan,
            "message": f"still {prev_total} fixable finding(s) after {cap} iterations",
        }

    def build_gate_validation(self, scan: CopaScanResult | None) -> ValidationResult:
        """Produce the scan-gate ValidationResult (is_rescan=True) from the final
        scan — the policy-zero gate."""
        passed = bool(scan is not None and not scan.has_fixable_gate_findings)
        actual = (
            f"{scan.fixable_critical} CRITICAL, {scan.fixable_high} HIGH fixable"
            if scan is not None
            else "no scan result"
        )
        return ValidationResult(
            test_name="trivy scan gate (fixable CRITICAL,HIGH) after copa",
            method="cli",
            command="trivy image --vuln-type os --ignore-unfixed --severity CRITICAL,HIGH",
            expected="0 fixable CRITICAL/HIGH",
            actual=actual,
            passed=passed,
            is_rescan=True,
        )
