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

import time

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
from .scanning import (
    ScanClassification,
    ScanParseError,
    box_count_command,
    parse_box_summary,
)

_TRACE_AGENT = "image-hardening"


# Line prefixes/substrings that carry the ACTUAL cause of a copa/apt failure.
# These lines are HOISTED into the captured output so a verbose buildkit
# progress log can never push the real error out of the retained window.
# (run #9 lost the "404 Not Found" line because a plain char-tail dropped it.)
_ERROR_SIGNAL_SUBSTRINGS = (
    "err:",  # apt: "Err:1 http://... 404"
    "404",
    "e:",  # apt: "E: Unable to fetch ..."
    "error:",
    "failed",
    "not found",
    "cannot",
    "no space left",
    "denied",
    "unable to",
    "could not",
)


def _capture(text: str | None, limit: int) -> str:
    """Capture copa/buildkit output for a StepResult without losing the error.

    Keeps the LAST `limit` chars (errors live at the end), but FIRST hoists any
    error-signal lines to the top so they survive even when the tail is full of
    trailing progress noise. This guarantees the actual failure line (e.g. an
    apt `Err: ... 404 Not Found`) is always present in the persisted output.
    """
    if not text:
        return ""
    signal_lines = [
        ln for ln in text.splitlines() if any(s in ln.lower() for s in _ERROR_SIGNAL_SUBSTRINGS)
    ]
    tail = text if len(text) <= limit else "…(truncated head)…" + text[-limit:]
    if not signal_lines:
        return tail
    # De-dup while preserving order; cap the hoisted block so it can't dominate.
    seen: set[str] = set()
    hoisted: list[str] = []
    for ln in signal_lines:
        if ln not in seen:
            seen.add(ln)
            hoisted.append(ln)
    hoisted_block = "\n".join(hoisted[-20:])
    return f"⚠ error signals:\n{hoisted_block}\n--- full tail ---\n{tail}"


# Substrings in copa's output that indicate a TRANSIENT failure (worth a
# retry) rather than a deterministic one. These are package-mirror / CDN /
# network flakes — e.g. a stale Debian mirror edge node 404-ing a helper
# package copa needs. A deterministic failure (bad report, unsupported image)
# will NOT match and will fail fast.
_TRANSIENT_COPA_SIGNATURES = (
    "404  not found",
    "404 not found",
    "failed to fetch",
    "unable to fetch",
    "fix-missing",
    "temporary failure resolving",
    "could not resolve",
    "connection timed out",
    "connection reset",
    "tls handshake timeout",
    "i/o timeout",
    "503 service unavailable",
    "502 bad gateway",
)


def _is_transient_copa_failure(step) -> bool:
    """True if a failed copa StepResult looks like a retryable mirror/CDN/network flake."""
    blob = f"{step.stdout or ''}\n{step.stderr or ''}".lower()
    return any(sig in blob for sig in _TRANSIENT_COPA_SIGNATURES)


def _repo_of(image_ref: str) -> str:
    """Return the repository part of an image ref (no tag, no digest).

    copa's `-t` flag is a TAG only, not a full image reference — copa produces
    a NEW image at `<repo-of-source>:<tag>` locally. So to name the patched
    image we must split the source ref into its repository and reattach the
    new tag ourselves.

    Handles:
      - `debian:11.0`                  → `debian`
      - `nginx`                        → `nginx`
      - `registry.io:5000/foo/bar:tag` → `registry.io:5000/foo/bar`
      - `foo@sha256:abc...`            → `foo`
      - `registry.io/foo@sha256:abc`   → `registry.io/foo`

    A digest (`@sha256:...`) is stripped first. A tag is the last `:` AFTER the
    final `/` (so a registry port like `registry.io:5000/...` is not mistaken
    for a tag).
    """
    ref = image_ref.strip()
    # Strip a digest if present.
    at = ref.find("@")
    if at != -1:
        ref = ref[:at]
    # A tag colon only counts if it appears after the last '/'.
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    if colon > slash:
        ref = ref[:colon]
    return ref


def copa_local_patched_ref(source_ref: str, plain_tag: str) -> str:
    """The LOCAL image ref copa produces for `copa patch -i source -t plain_tag`.

    = `<repo-of-source>:<plain_tag>`. This is what we re-scan and then
    retag/push to the client's ECR tag in the publish step.
    """
    return f"{_repo_of(source_ref)}:{plain_tag}"


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
        # 1. Write the OS-only JSON report copa consumes, then COUNT ON THE BOX.
        #    We never `cat` the (multi-MB) report back over SSM stdout — SSM's
        #    GetCommandInvocation truncates StandardOutputContent at ~24 KB,
        #    which corrupts the JSON and historically produced a silent zero
        #    count (false "clean"). The box-side counter prints a tiny summary.
        scan_cmd = (
            f"trivy image --vuln-type os --ignore-unfixed "
            f"-f json -o '{report_path}' {image_ref} "
            f"&& {box_count_command(report_path)}"
        )
        r = self._run(executor, scan_cmd, workdir=wd, timeout_s=600)
        if r.exit_code != 0:
            raise RemoteExecError(
                f"trivy OS scan failed (exit {r.exit_code}): {(r.stderr or '')[:300]}"
            )
        cls = parse_box_summary(r.stdout or "")  # raises ScanParseError on any failure
        summary = (
            f"OS fixable: {cls.os_critical} CRITICAL, {cls.os_high} HIGH (report: {report_path})"
        )
        return CopaScanResult(
            fixable_critical=cls.os_critical,
            fixable_high=cls.os_high,
            raw_summary=summary,
        )

    def full_scope_scan(self, ctx: HardenContext, image_ref: str) -> ScanClassification:
        """FULL-SCOPE scan (OS + language deps) → classified fixable crit/high.

        This is the source of truth for the policy-zero GATE and for the
        orchestrator's decision (copa for OS, rebuild for deps). Distinct from
        the OS-only report copa consumes as its patch input.
        """
        executor = self._executor(ctx)
        wd = self._scratch()
        report_path = f"{wd}/trivy-full-{ctx.hardening_run_id}.json"
        # Write the full-scope report to a FILE, then COUNT ON THE BOX. A
        # `cat` of this report over SSM stdout is truncated at ~24 KB and
        # historically produced a silent zero → false gate pass. The box-side
        # counter emits a tiny bounded summary that is never truncated, and
        # parse_box_summary HARD-FAILS if the scan/parse failed (so an
        # unscanned image can never be certified).
        cmd = (
            f"trivy image --vuln-type os,library --ignore-unfixed "
            f"-f json -o '{report_path}' {image_ref} "
            f"&& {box_count_command(report_path)}"
        )
        r = self._run(executor, cmd, workdir=wd, timeout_s=600)
        if r.exit_code != 0:
            raise ScanParseError(
                f"full-scope trivy scan failed (exit {r.exit_code}): {(r.stderr or '')[:300]}"
            )
        return parse_box_summary(r.stdout or "")

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
        """One copa patch invocation.

        `patched_tag` MUST be a PLAIN tag (e.g. "v0.1.0-copa1") — NOT a full
        registry/repo:tag. copa's `-t` flag names only the tag; copa produces
        the patched image locally at `<repo-of-image_ref>:<patched_tag>`.
        Passing a full ECR ref here fails with "invalid tag format".
        """
        executor = self._executor(ctx)
        wd = self._scratch()
        started = utcnow()
        cmd = (
            f"copa patch -i {image_ref} -r '{report_path}' "
            f"-t {patched_tag} -a {self.config.buildkit_addr}"
        )
        try:
            r = self._run(executor, cmd, workdir=wd, timeout_s=600)
            # copa streams a buildkit progress log; the ACTUAL error is at the
            # END. Keep the TAIL (not the head) so failures are diagnosable.
            return StepResult(
                step_num=0,
                action="copa patch",
                command=cmd,
                stdout=_capture(r.stdout, 4000),
                stderr=_capture(r.stderr, 6000),
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

    def patch_once_with_retry(
        self, ctx: HardenContext, image_ref: str, report_path: str, patched_tag: str
    ) -> StepResult:
        """`patch_once` with bounded retries for TRANSIENT failures.

        copa's internal `apt-get install <helper>` (e.g. busybox-static) has no
        retry, so a single stale Debian mirror edge-node 404 or a network flake
        aborts an otherwise-valid patch. Since copa is idempotent (it rebuilds
        from the source each time), we retry the whole invocation on a transient
        signature, with backoff. A DETERMINISTIC failure (bad report,
        unsupported image, real package conflict) does NOT match the transient
        signatures and fails fast on the first attempt — no wasted retries.
        """
        attempts = max(0, self.config.copa_transient_retries) + 1
        last = None
        for attempt in range(1, attempts + 1):
            step = self.patch_once(ctx, image_ref, report_path, patched_tag)
            last = step
            if step.status == "success":
                if attempt > 1:
                    step.adaptation_note = f"succeeded on copa attempt {attempt}/{attempts}"
                return step
            if attempt < attempts and _is_transient_copa_failure(step):
                self._emit(
                    ctx,
                    "MESSAGE",
                    f"↻ copa patch hit a transient mirror/network error "
                    f"(attempt {attempt}/{attempts}) — retrying after backoff",
                )
                time.sleep(self.config.copa_retry_backoff_s * attempt)
                continue
            # Non-transient, or retries exhausted → return the failure as-is.
            if attempt >= attempts and _is_transient_copa_failure(step):
                step.adaptation_note = (
                    f"transient copa failure persisted across {attempts} attempts "
                    f"(package mirror/CDN flake — e.g. apt 404)"
                )
            return step
        return last  # unreachable; keeps type-checkers happy

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
            # copa's -t is a PLAIN tag; it produces <repo-of-current_ref>:<tag>
            # locally. Keep the tag docker-valid: no registry/repo, no slashes,
            # no colons. We publish this to the client's ECR tag later.
            plain_tag = f"{ctx.published_tag}-copa{i}"
            patch_step = self.patch_once_with_retry(ctx, current_ref, report_path, plain_tag)
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
            # The LOCAL ref copa just produced (what we re-scan + eventually push).
            current_ref = copa_local_patched_ref(current_ref, plain_tag)

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
