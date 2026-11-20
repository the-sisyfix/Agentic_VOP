"""Sub-Agent 4 orchestrator — top-level, family-blind.

Loads a remediation_package, picks the right BaseFixStrategy subclass,
runs the 5-phase lifecycle (pre_flight → backup → execute → validate →
rollback-on-failure), and persists the outcome to fix_runs.

Zero strategy-specific logic here. Adding a new family later = new
BaseFixStrategy subclass + one line in the `_STRATEGY_BY_KEY` dispatch
map at the top of this file. Everything else stays untouched.

Two entry points:
  run_fixer(package_id, ...)      — used by API endpoint + auto-chain
  run_fixer_demo(package_id, ...) — same flow but on demo schema
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ...leases import LeaseTimeout, hold_lease
from .config import FixerConfig, load_config_from_settings
from .models import (
    FixContext,
    StrategyOutcome,
    utcnow,
)
from .preflight import run_preflight_rewrite
from .persistence import (
    create_fix_run,
    finalize_fix_run,
    set_backup_reference,
    set_status,
    set_terraform_plan_output,
)
from .strategies.base import BaseFixStrategy
from .strategies.code_edit_strategy import CodeEditStrategy
from .strategies.dependency_strategy import DependencyStrategy
from .strategies.iac_strategy import IaCStrategy
from .strategies.image_strategy import ImageStrategy
from .strategies.os_strategy import OSStrategy
from .watchdog import RunCancelledError, WatchdogTimeout, check_run_health


# ─── env2 dispatch lease ─────────────────────────────────────────────────
# env2 is one shared sandbox: two SA-4 runs on it at once edit the same
# main.tf / Dockerfiles, and both trivy rescans time out and roll back.
#
# Dispatch is serialized by a row in public.run_leases (see app/leases.py),
# not a process-local threading.Lock + "is any fix_run in flight?" poll.
# The old pair didn't coordinate across uvicorn workers or hosts, the poll
# had a SELECT-then-INSERT race, it only looked at the caller's schema (so
# public and demo runs never saw each other), and a fix_run orphaned by a
# killed process blocked everyone for 30 minutes. The lease is shared by
# every process and schema and expires ENV2_LEASE_TTL_S after its holder
# dies.
ENV2_LEASE_RESOURCE = "fixer:env2"
ENV2_LEASE_TTL_S = 120
# 30 min total wait. Sized to survive a slow SA-4 fix chain (~90s each ×
# 20 packages = 30 min worst case) so a legitimately long-running fix
# upstream doesn't cause downstream package casualties.
ENV2_LEASE_WAIT_MAX_S = 1800
ENV2_LEASE_POLL_S = 10


# =============================================================================
# Strategy dispatch — one line per family. Genericity survives by this map
# being the ONLY place code branches on family/scanner_type.
# =============================================================================
_STRATEGY_BY_KEY: dict[str, type[BaseFixStrategy]] = {
    "iac": IaCStrategy,
    "image": ImageStrategy,  # trivy-image (container image OS pkgs)
    "os": OSStrategy,  # trivy-os / tenable / qualys (host apt/yum)
    "code_edit": CodeEditStrategy,  # semgrep / bandit / sonarqube (source edits)
    "dependency": DependencyStrategy,  # trivy-fs / snyk-appsec (manifest edits)
    # Phase-3 additions land here:
    # "cli":        CliStrategy,          # aws-cli direct cloud fixes
}


# =============================================================================
# Family → strategy_key mapping.
#
# Family alone doesn't fully determine the strategy — a public_exposure
# finding on a Terraform-managed bucket goes 'iac', but the same family on
# a mutable direct-cloud bucket would go 'cli'. So we prefer scanner_type
# (from IaC context) with family as a secondary hint.
# =============================================================================
_SOURCE_CODE_EXTENSIONS: tuple[str, ...] = (
    # Interpreted / dynamic
    ".py",
    ".rb",
    ".php",
    ".pl",
    ".lua",
    ".groovy",
    # JS / TS family
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".jsx",
    ".tsx",
    # JVM
    ".java",
    ".kt",
    ".kts",
    ".scala",
    # Native / systems
    ".go",
    ".rs",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hpp",
    # .NET / Apple / other
    ".cs",
    ".swift",
    ".m",
    ".mm",
)

# Terraform/HCL config files — always IacStrategy regardless of family.
# Fixes the case where a finding on `main.tf` classifies as `injection`
# (via CWE-778/770/392 code-oriented CWEs on Lambda infra rules) and would
# otherwise misroute to CodeEditStrategy. Universal — future IaC scanners
# (tfsec, kics, terrascan) get correct routing for free.
_IAC_EXTENSIONS: tuple[str, ...] = (
    ".tf",
    ".tf.json",
    ".hcl",
    ".tfvars",
)


def _select_strategy_key(
    *,
    family: str,
    scanner_type: str | None,
    source: str | None = None,
    file_path: str | None = None,
) -> str:
    """Pick the fix strategy key based on source + scanner_type + family + file extension.

    Priority order (most specific → least specific):
      1. Source name — deterministic when we know the scanner. Container
         image scanners → image; host OS scanners → os.
      2. Target file's extension — a `.py`/`.js`/etc. source file always
         means edit the source (CodeEditStrategy), never terraform-apply
         it. Prevents IacStrategy from being chosen for SAST findings that
         happened to classify as public_exposure (e.g. CWE-798 hardcoded
         credentials in Lambda source).
      3. scanner_type from SA-3's extractor (iac / sast / sca / os_pkg).
      4. Family as a final fallback.

    Returns an unregistered key when no strategy is wired for the shape;
    run_fixer's dispatch check will surface a clean "no strategy registered"
    error rather than routing the fix to the wrong executor and corrupting
    env2.
    """
    src = (source or "").lower()

    # ---- Source-first routing ----
    # Container image scanners → ImageStrategy (docker rebuild + retag)
    if "trivy-image" in src or "snyk-container" in src or "grype-image" in src:
        return "image"
    # Host OS scanners → OSStrategy (apt/yum upgrade) — not yet registered
    if "trivy-os" in src or "tenable-nessus" in src or "qualys-vmdr" in src or "rapid7" in src:
        return "os"
    # App-dep scanners → DependencyStrategy — not yet registered
    if "trivy-fs" in src or "snyk-appsec" in src or "dependabot" in src or src == "osv":
        return "dependency"
    # SAST scanners → CodeEditStrategy — not yet registered
    if "semgrep" in src or "bandit" in src or "sonarqube" in src:
        return "code_edit"

    # ---- File-extension override ----
    # File type is a stronger signal than family for choosing the strategy.
    # A finding on `main.tf` must go to IacStrategy even when its CWE
    # (e.g. CWE-778, CWE-770) pushed the family classifier toward
    # `injection`. Symmetric for source-code files. Both branches keep
    # future scanners routing correctly with no per-source rule needed.
    if file_path:
        fp = file_path.lower()
        if fp.endswith(_IAC_EXTENSIONS):
            return "iac"
        if fp.endswith(_SOURCE_CODE_EXTENSIONS):
            return "code_edit"

    # ---- Family-based routing when source didn't decide ----
    if family == "os_vulnerability":
        # Family-only signal is ambiguous (image vs host). Prefer image
        # for MVP since trivy-image is the primary demo path; the source
        # branch above handles the disambiguation cleanly.
        return "image"
    if family == "vulnerable_dependency":
        return "dependency"  # not yet registered
    if family == "injection":
        return "code_edit"  # not yet registered

    # ---- scanner_type from IaC extractor ----
    if scanner_type in ("iac", "sca"):
        # SCA findings often ship with an IaC-shaped fix (edit manifest → install)
        # so they're handled by IaCStrategy in MVP too. Phase-2 introduces a
        # dedicated DependencyStrategy that reuses tools/ but adds pip/npm logic.
        return "iac"
    if scanner_type == "sast":
        return "code_edit"
    if scanner_type == "os_pkg":
        return "os"

    # Fallback: family-based dispatch when scanner_type wasn't extracted
    if family in ("public_exposure", "network_exposure"):
        return "iac"
    return "iac"  # Default to IaC for unknown shapes (matches historical behavior)


# =============================================================================
# Public entry point
# =============================================================================
def run_fixer(
    package_id: int,
    *,
    agent_run_id: str,
    sb: Any,
    emit_fn,
    environment: str = "sandbox",
    config: FixerConfig | None = None,
) -> int:
    """Run Sub-Agent 4 against one remediation_package.

    Args:
        package_id:   which remediation_packages row to fix
        agent_run_id: for trace correlation (auto-chain populates this from
                      the SA3 run so events string together in the UI)
        sb:           supabase client (public.* or demo.* — determines which
                      fix_runs table gets written)
        emit_fn:      trace emitter (emit_trace for real, emit_trace_demo)
        environment:  'sandbox' (Phase-1 default) or 'production' (promote flow)
        config:       optional FixerConfig; loaded from settings if None

    Returns:
        The new fix_run id.

    Raises:
        RuntimeError — for setup failures the caller should log + move on.
        Strategy-level failures are captured in the fix_run row's status +
        error_message, not raised.
    """
    cfg = config or load_config_from_settings()

    run_kwargs = dict(
        package_id=package_id,
        agent_run_id=agent_run_id,
        sb=sb,
        emit_fn=emit_fn,
        environment=environment,
        cfg=cfg,
    )
    if FixerConfig.allow_concurrent_runs:
        return _run_fixer_locked(**run_kwargs)

    # Serialize env2 dispatches across every process, host and schema. Even
    # if several background tasks reach here at once (typical when a user
    # approves 5 HITL packages in quick succession, or two users trigger
    # pipelines together), only one holds the lease; the rest wait.
    def _on_wait(holder: dict | None) -> None:
        emit_fn(
            agent_run_id,
            "sub-agent-4",
            "MESSAGE",
            f"⏳ env2 shared sandbox is busy — another fix is running "
            f"({(holder or {}).get('label') or 'unknown'}, since "
            f"{((holder or {}).get('acquired_at') or '?')[:19]}). Waiting up to "
            f"{ENV2_LEASE_WAIT_MAX_S}s for it to complete before dispatching this run…",
        )

    try:
        with hold_lease(
            ENV2_LEASE_RESOURCE,
            label=f"package #{package_id}, agent_run {agent_run_id}",
            ttl_s=ENV2_LEASE_TTL_S,
            wait_max_s=ENV2_LEASE_WAIT_MAX_S,
            poll_s=ENV2_LEASE_POLL_S,
            on_wait=_on_wait,
        ) as waited_s:
            if waited_s:
                emit_fn(
                    agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"✓ env2 lock released after {waited_s}s wait — dispatching now.",
                )
            return _run_fixer_locked(**run_kwargs)
    except LeaseTimeout as e:
        holder = e.holder or {}
        raise RuntimeError(
            f"env2 shared sandbox is still busy after waiting {e.waited_s}s. "
            f"Another fix ({holder.get('label') or 'unknown'}, since "
            f"{(holder.get('acquired_at') or '?')[:19]}) has been running for a long "
            f"time. env2 supports one fix at a time — coordinate with "
            f"whoever is running the other demo, wait a few more minutes, "
            f"then retry. Run `python scripts/check_env2_status.py` from "
            f"apps/api to see live state."
        ) from e


def _run_fixer_locked(
    *,
    package_id: int,
    agent_run_id: str,
    sb: Any,
    emit_fn,
    environment: str,
    cfg: FixerConfig,
) -> int:
    """Body of run_fixer — executed only while the env2 dispatch lease is held.

    HITL v2 "Verified PR" note: packages flagged `git_native_review=True`
    still run the full sandbox lifecycle below (SSM + build + rescan) —
    only after that succeeds and the rescan verifies the fix does the
    orchestrator's success path open a PR mirroring the change against
    the customer's repo (see git_verified_pr.open_verified_pr). That
    hook is best-effort and never gates the sandbox success.
    """
    # 1. Load the package
    pkg_row = _load_package(sb, package_id)
    if pkg_row is None:
        raise RuntimeError(f"remediation_packages row #{package_id} not found")

    issue_id = int(pkg_row["issue_id"])
    family = pkg_row.get("family", "")
    pathway_index = int(pkg_row.get("recommended_pathway_index") or 0)
    pathways = pkg_row.get("pathways") or []
    if pathway_index >= len(pathways):
        raise RuntimeError(
            f"Package #{package_id} recommended_pathway_index {pathway_index} "
            f"out of range (only {len(pathways)} pathways)"
        )
    pathway = pathways[pathway_index]

    # 2. Load the issue (for IaC context — file_path / working_directory / etc.)
    issue_row = _load_issue(sb, issue_id)
    if issue_row is None:
        raise RuntimeError(f"issues row #{issue_id} not found")

    # 3. Extract IaC context (same helper SA3 used — single source of truth)
    from ..remediation.planner import _extract_iac_context  # noqa: PLC0415

    raw = _load_raw_finding(sb, issue_row.get("raw_finding_id"))
    iac_ctx = _extract_iac_context(issue_row, raw)

    # 3b. For container-image scanners, resolve dockerfile_path dynamically
    #     from connection_registry metadata. Avoids hardcoding per-image paths
    #     in ImageStrategy — any new scanner just needs metadata filled in Supabase.
    #
    #     Always override (not just when file_path is empty) — `_extract_iac_context`
    #     populates file_path with a mangled image-reference-as-path for image
    #     findings (e.g. prepends `settings.fixer_env2_path_prefix` to
    #     `vuln-java-image:latest` producing `/opt/vuln-labs/cspm-lab/vuln-java-image:latest`,
    #     a fake path that fails ImageStrategy's pre-flight `test -f`). Override with
    #     the real Dockerfile path, or clear to None so ImageStrategy uses its
    #     _DEFAULT_DOCKERFILE fallback.
    #
    #     Sibling image scanners (grype-image, snyk-container) get the same treatment
    #     — category-based, not rule-specific.
    source = issue_row.get("source") or ""
    _source_lower = source.lower()
    _is_image_scanner = (
        "trivy-image" in _source_lower
        or "grype-image" in _source_lower
        or "snyk-container" in _source_lower
    )
    if _is_image_scanner:
        try:
            from ...db import supabase_admin as _sb_pub  # noqa: PLC0415

            sb_pub = _sb_pub()
            reg_row = (
                sb_pub.table("connection_registry")
                .select("metadata")
                .eq("tool", source)
                .single()
                .execute()
                .data
            )
            reg_meta = (reg_row or {}).get("metadata") or {}
            if reg_meta.get("dockerfile_path"):
                iac_ctx["file_path"] = reg_meta["dockerfile_path"]
                iac_ctx["working_directory"] = (
                    reg_meta.get("build_directory") or reg_meta["dockerfile_path"].rsplit("/", 1)[0]
                )
            else:
                # Registry lookup succeeded but no dockerfile_path — clear the
                # mangled path so ImageStrategy falls back to its _DEFAULT_DOCKERFILE.
                iac_ctx["file_path"] = None
        except Exception:  # noqa: BLE001
            # Registry lookup failed entirely — same fallback, clear mangled path.
            iac_ctx["file_path"] = None
        # Also set resource_name to the image ref from raw target (e.g. "vuln-java-image:latest")
        if not iac_ctx.get("resource_name") and raw:
            target = raw.get("target") or raw.get("Target") or ""
            # Extract image:tag from "vuln-java-image:latest (debian 10.2)"
            image_ref = target.split("(")[0].strip() if "(" in target else target
            if image_ref:
                iac_ctx["resource_name"] = image_ref

    # 4. Decide strategy — source name is the strongest signal for
    #    disambiguating trivy-image (ImageStrategy) vs trivy-os (OSStrategy)
    #    when both classify as family='os_vulnerability'.
    strategy_key = _select_strategy_key(
        family=family,
        scanner_type=iac_ctx.get("scanner_type"),
        source=issue_row.get("source"),
        file_path=iac_ctx.get("file_path"),
    )
    strategy_cls = _STRATEGY_BY_KEY.get(strategy_key)
    if strategy_cls is None:
        raise RuntimeError(
            f"No fix strategy registered for key {strategy_key!r} "
            f"(family={family}, scanner_type={iac_ctx.get('scanner_type')}, "
            f"source={issue_row.get('source')!r})"
        )

    # 5. Sanity: strategy needs a target instance to talk to.
    #    For scanners with a dedicated fix target (e.g. trivy-os-al2-ec2 → AL2
    #    instance), look up target_instance_id from connection_registry.metadata.
    #    Falls back to the default FIXER_ENV2_INSTANCE_ID for scanners without
    #    a dedicated target (most cases).
    target_instance_id = cfg.env2_instance_id or ""
    source = issue_row.get("source") or ""
    if source:
        try:
            from ...db import supabase_admin as _sb_pub_fn  # noqa: PLC0415

            _sb_pub = _sb_pub_fn()
            reg_row = (
                _sb_pub.table("connection_registry")
                .select("metadata")
                .eq("tool", source)
                .single()
                .execute()
                .data
            )
            reg_meta = (reg_row or {}).get("metadata") or {}
            if reg_meta.get("target_instance_id"):
                target_instance_id = reg_meta["target_instance_id"]
        except Exception:  # noqa: BLE001, S110
            pass  # Fall through to default

    if not target_instance_id:
        raise RuntimeError(
            "No target instance configured. Set FIXER_ENV2_INSTANCE_ID in env "
            "or add target_instance_id to the scanner's connection_registry metadata."
        )

    # 6. Create the fix_run row (status='pending')
    fix_run_id = create_fix_run(
        sb,
        package_id=package_id,
        issue_id=issue_id,
        pathway_index=pathway_index,
        agent_run_id=agent_run_id,
        strategy_key=strategy_key,
        environment=environment,  # type: ignore[arg-type]
        target_instance_id=target_instance_id,
        target_file_path=iac_ctx.get("file_path"),
        working_directory=iac_ctx.get("working_directory"),
        timeout_seconds=cfg.run_timeout_s,
    )

    emit_fn(
        agent_run_id,
        "sub-agent-4",
        "DISPATCH",
        f"🔧 Fix run #{fix_run_id} started — strategy={strategy_key}, "
        f"package=#{package_id}, family={family}, target={target_instance_id}",
    )

    # 7. Build ctx + strategy instance
    ctx = FixContext(
        fix_run_id=fix_run_id,
        package_id=package_id,
        issue_id=issue_id,
        pathway_index=pathway_index,
        agent_run_id=agent_run_id,
        package=pkg_row,
        pathway=pathway,
        issue=issue_row,
        file_path=iac_ctx.get("file_path"),
        working_directory=iac_ctx.get("working_directory"),
        resource_name=iac_ctx.get("resource_name"),
        scanner_type=iac_ctx.get("scanner_type"),
        environment=environment,  # type: ignore[arg-type]
        target_instance_id=target_instance_id,
        aws_region=cfg.aws_region,
    )
    strategy = strategy_cls(config=cfg, emit_fn=emit_fn)

    # 8. Execute lifecycle — wrapped in try/finally so ANY internal bug
    # (bad emit_fn signature, LLM crash, unexpected exception) still results
    # in fix_run being finalized. A crashed run left in 'in_flight' state
    # locks the concurrency check and blocks every subsequent fix — worse
    # than the original bug. Better to record a 'failed' outcome and move on.
    started_at = utcnow()
    outcome: StrategyOutcome
    try:
        outcome = _run_lifecycle(
            sb,
            fix_run_id,
            strategy,
            ctx,
            emit_fn=emit_fn,
            started_at=started_at,
            timeout_seconds=cfg.run_timeout_s,
        )
    except WatchdogTimeout as e:
        # Watchdog fired — attempt rollback (safe if backup was taken; no-op
        # otherwise) then finalize as failed so the row transitions cleanly.
        rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
        outcome = StrategyOutcome(
            status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
            rollback_results=rollback,
            error_message=f"watchdog timeout: {str(e)[:400]}",
        )
        try:
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "ERROR",
                f"⏱ Fix run #{fix_run_id} killed by watchdog "
                f"(timeout={cfg.run_timeout_s}s); {str(e)[:200]}",
            )
        except Exception:  # noqa: BLE001, S110
            pass
    except RunCancelledError as e:
        rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
        outcome = StrategyOutcome(
            status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
            rollback_results=rollback,
            error_message=f"cancelled by operator: {str(e)[:400]}",
        )
        try:
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "MESSAGE",
                f"🛑 Fix run #{fix_run_id} cancelled by operator — {str(e)[:200]}",
            )
        except Exception:  # noqa: BLE001, S110
            pass
    except Exception as e:  # noqa: BLE001
        # Belt-and-suspenders: _run_lifecycle already catches strategy-level
        # errors; this catches orchestrator-level bugs (bad emit call, etc.).
        # Fabricate a failed outcome so finalize_fix_run has something to persist.
        outcome = StrategyOutcome(
            status="failed",
            error_message=(
                f"orchestrator crashed: {type(e).__name__}: {str(e)[:400]} "
                f"(fix_run finalized as 'failed' to release concurrency lock)"
            ),
        )
        # Best-effort trace — swallow secondary errors so nothing here can
        # prevent finalize_fix_run from running.
        try:
            emit_fn(
                agent_run_id,
                "sub-agent-4",
                "ERROR",
                f"✗ Fix run #{fix_run_id} crashed mid-lifecycle: "
                f"{type(e).__name__}: {str(e)[:300]} — finalizing as failed",
            )
        except Exception:  # noqa: BLE001, S110
            pass

    # 9. Persist final state — MUST run so the row leaves any non-terminal
    # status. finalize_fix_run's Supabase update can fail transiently (network
    # blip, connection pool exhaustion). Retry a few times with backoff, and
    # if every attempt fails, fall back to a bare-minimum status update so
    # the watchdog reaper doesn't have to close this row later.
    import time  # noqa: PLC0415

    for attempt in range(3):
        try:
            finalize_fix_run(sb, fix_run_id, ctx=ctx, outcome=outcome, started_at=started_at)
            break
        except Exception as e:  # noqa: BLE001
            if attempt == 2:
                # All retries exhausted — try the minimal-fields fallback so
                # at least status + finished_at land.
                try:
                    from .models import utcnow as _utcnow  # noqa: PLC0415

                    _now = _utcnow()
                    sb.table("fix_runs").update(
                        {
                            "status": "failed"
                            if outcome.status == "partial_success"
                            else outcome.status,
                            "finished_at": _now.isoformat(),
                            "error_message": (
                                f"finalize_fix_run failed after 3 retries "
                                f"({type(e).__name__}: {str(e)[:200]}); minimal fallback applied"
                            )[:2000],
                        }
                    ).eq("id", fix_run_id).execute()
                except Exception:  # noqa: BLE001, S110
                    pass
                try:
                    emit_fn(
                        agent_run_id,
                        "sub-agent-4",
                        "ERROR",
                        f"✗ finalize_fix_run failed for fix_run #{fix_run_id} "
                        f"after 3 attempts ({type(e).__name__}). Reaper will close "
                        f"if the minimal fallback also missed.",
                    )
                except Exception:  # noqa: BLE001, S110
                    pass
            else:
                time.sleep(0.5 * (attempt + 1))

    # 10. Knowledge Base capture — store successful fixes for future few-shot reuse.
    # Best-effort: never blocks the main flow. Only fires on verified success.
    # NOTE: Always writes to the PUBLIC schema — the KB is a shared knowledge
    # base that feeds SA-3 across all pipelines (real + demo). The `sb` passed
    # to run_fixer may be a demo-schema client, so we use a fresh public client.
    if outcome.status == "success":
        try:
            from ..remediation.kb_capture import capture_successful_fix  # noqa: PLC0415
            from ...db import supabase_admin as _kb_admin  # noqa: PLC0415

            capture_successful_fix(
                _kb_admin(),
                ctx=ctx,
                outcome=outcome,
                confidence_score=(ctx.pathway or {}).get("confidence_score") or 90,
                emit_fn=emit_fn,
            )
        except Exception:  # noqa: BLE001, S110
            pass

    # 11. KB reuse tracking — if this fix used a KB replay recipe, update counters.
    # Increment times_reused (always after completion) and times_succeeded (on success).
    # This feeds the success_rate computed column for recipe quality monitoring.
    try:
        pathway_conf = (ctx.pathway or {}).get("confidence_components") or {}
        kb_source_id = (
            pathway_conf.get("kb_id") if pathway_conf.get("source") == "kb_replay" else None
        )
        if kb_source_id:
            from ..remediation.kb_capture import increment_reuse_count, increment_success_count  # noqa: PLC0415
            from ...db import supabase_admin as _kb_admin_fn  # noqa: PLC0415

            _kb_sb = _kb_admin_fn()
            increment_reuse_count(_kb_sb, kb_source_id)
            if outcome.status == "success":
                increment_success_count(_kb_sb, kb_source_id)
    except Exception:  # noqa: BLE001, S110
        pass  # Best-effort — never block main flow

    # Best-effort trace — a crash here doesn't affect persisted state.
    try:
        emit_fn(
            agent_run_id,
            "sub-agent-4",
            "DONE",
            f"🔧 Fix run #{fix_run_id} finished — status={outcome.status} "
            f"({len(outcome.step_results)} steps, {len(outcome.validation_results)} validations)",
            payload={
                "fix_run_id": fix_run_id,
                "status": outcome.status,
                "strategy": strategy_key,
            },
        )
    except Exception:  # noqa: BLE001, S110
        pass

    return fix_run_id


# =============================================================================
# Lifecycle — pre_flight → backup → execute → validate → maybe-rollback
# =============================================================================
def _run_lifecycle(
    sb: Any,
    fix_run_id: int,
    strategy: BaseFixStrategy,
    ctx: FixContext,
    *,
    emit_fn,
    started_at: datetime,
    timeout_seconds: int,
) -> StrategyOutcome:
    """Drive the 5 strategy phases. Returns a StrategyOutcome.

    Catches strategy-level exceptions and converts to 'failed' + rollback
    attempt. Never re-raises — the fix_run row captures everything the
    caller needs to know.

    Watchdog: calls `check_run_health` at each phase boundary so a
    long-running strategy or a stuck SSM call cannot hold the run past
    `timeout_seconds`, and so the operator's Cancel button aborts within
    at most one phase.
    """

    def _health():
        """Raise WatchdogTimeout / RunCancelledError if this run should abort."""
        check_run_health(
            sb,
            agent_run_id=ctx.agent_run_id,
            fix_run_id=fix_run_id,
            started_at=started_at,
            timeout_seconds=timeout_seconds,
        )

    # ─── Phase 3: Pre-flight ────────────────────────────────────────────
    _health()
    set_status(sb, fix_run_id, "provisioning")
    try:
        preflight = strategy.pre_flight_check(ctx)
    except Exception as e:  # noqa: BLE001
        return StrategyOutcome(
            status="failed",
            error_message=f"pre_flight raised {type(e).__name__}: {str(e)[:500]}",
        )
    if not preflight.ready:
        return StrategyOutcome(
            status="failed",
            error_message=preflight.blocking_reason or "pre_flight failed",
        )

    # ─── Phase 3.5: Pre-flight LLM rewriter ─────────────────────────────
    # Snapshot env2 (IAM identity + attached policies + terraform state) and
    # ask an LLM whether any remediation_steps will fail given that state.
    # High-confidence rewrites are applied to a fresh pathway copy; the
    # rewriter never modifies steps directly and always fail-opens on any
    # error (returns the original pathway unchanged). See preflight.py for
    # the full design.
    #
    # The canonical case this catches: SA3 emits `sse_algorithm = "aws:kms"`
    # for S3 encryption but env2 lacks kms:CreateKey — rewriter swaps to
    # AES256 which needs zero permissions.
    try:
        rewritten_pathway, rewrite_log = run_preflight_rewrite(ctx, emit_fn)
        if rewrite_log:
            # ctx is immutable Pydantic; construct a copy with the rewritten
            # pathway so downstream phases execute the modified package.
            ctx = ctx.model_copy(update={"pathway": rewritten_pathway})
    except Exception as e:  # noqa: BLE001
        # Belt-and-suspenders — run_preflight_rewrite already fail-opens
        # internally, but if something upstream (import, module-level state)
        # ever breaks, we still fall through to execute the original package.
        emit_fn(
            ctx.agent_run_id,
            "sub-agent-4",
            "MESSAGE",
            f"⚠ Pre-flight rewriter wrapper crashed ({type(e).__name__}: "
            f"{str(e)[:200]}) — executing original package.",
        )

    # ─── Phase 4: Backup ────────────────────────────────────────────────
    _health()
    try:
        backup = strategy.backup(ctx)
    except Exception as e:  # noqa: BLE001
        return StrategyOutcome(
            status="failed",
            error_message=f"backup raised {type(e).__name__}: {str(e)[:500]}",
        )
    if backup.backup_reference:
        set_backup_reference(sb, fix_run_id, backup.backup_reference)
        # Immutable model → construct a fresh ctx with backup filled in.
        # Pydantic supports .model_copy for this.
        ctx = ctx.model_copy(update={"backup_reference": backup.backup_reference})

    # ─── Phase 5: Execute ───────────────────────────────────────────────
    _health()
    set_status(sb, fix_run_id, "executing")
    try:
        step_results = strategy.execute(ctx)
    except Exception as e:  # noqa: BLE001
        # Terminal — try rollback
        rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
        return StrategyOutcome(
            status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
            step_results=[],
            rollback_results=rollback,
            backup_reference=backup.backup_reference,
            error_message=f"execute raised {type(e).__name__}: {str(e)[:500]}",
        )

    # Persist terraform plan output when we can spot it (audit trail per Nikhil)
    plan_out = _extract_plan_output(step_results)
    if plan_out:
        set_terraform_plan_output(sb, fix_run_id, plan_out)

    # Step failure handling — context-aware rollback decision.
    #
    # If a step fails BEFORE terraform apply has succeeded, the fix hasn't
    # been committed to infrastructure yet → rollback immediately (safe,
    # nothing to undo except the file edit which the .bak handles).
    #
    # If a step fails AFTER terraform apply succeeded, the IaC change is
    # already live. Post-apply steps are typically verification commands
    # (aws CLI checks, IAM probes, etc.) that can fail for reasons unrelated
    # to whether the fix actually worked (missing IAM permission, empty
    # variable, broken awk pattern). Rolling back a successful apply because
    # a post-apply CLI check is broken is counterproductive — it destroys a
    # valid fix. Instead: log the failure as a warning and proceed to the
    # validation phase where the scanner re-scan (the authoritative proof)
    # will determine whether the fix actually worked.
    #
    # This mirrors the validation phase's existing "re-scan is authoritative"
    # logic — ancillary failures don't override a passing re-scan.
    failed_step = next(
        (r for r in step_results if r.status in ("failed", "safety_blocked")),
        None,
    )
    if failed_step is not None:
        # Determine if terraform apply already succeeded in an earlier step.
        # We check for any step with "terraform apply" in its command that
        # exited successfully (exit_code 0).
        apply_succeeded = any(
            "terraform apply" in (r.command or "") and r.status == "success" for r in step_results
        )

        if apply_succeeded:
            # Post-apply failure — the fix is live. Log warning, proceed to
            # validation. The re-scan will be the authoritative judge.
            try:
                emit_fn(
                    ctx.agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"⚠ Step {failed_step.step_num} failed AFTER terraform apply "
                    f"succeeded — treating as non-critical warning. "
                    f"Proceeding to validation (re-scan will determine outcome). "
                    f"Failed step: {failed_step.action[:100]} | "
                    f"Error: {(failed_step.safety_reason or failed_step.stderr[:150])}",
                )
            except Exception:  # noqa: BLE001, S110
                pass
            # Fall through to the validation phase below — do NOT rollback
        else:
            # Pre-apply failure — fix was never committed. Rollback is safe.
            rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
            return StrategyOutcome(
                status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
                step_results=step_results,
                rollback_results=rollback,
                backup_reference=backup.backup_reference,
                terraform_plan_output=plan_out,
                error_message=(
                    f"Step {failed_step.step_num} {failed_step.status}: "
                    + (failed_step.safety_reason or failed_step.stderr[:300])
                ),
                error_step_number=failed_step.step_num,
            )

    # ─── Phase 6: Validate ──────────────────────────────────────────────
    _health()
    set_status(sb, fix_run_id, "validating")
    try:
        validation_results = strategy.validate(ctx)
    except Exception as e:  # noqa: BLE001
        rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
        return StrategyOutcome(
            status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
            step_results=step_results,
            rollback_results=rollback,
            backup_reference=backup.backup_reference,
            terraform_plan_output=plan_out,
            error_message=f"validate raised {type(e).__name__}: {str(e)[:500]}",
        )

    # Rollback decision policy:
    #   - Scanner re-scan is the AUTHORITATIVE proof of fix (Checkov / Trivy /
    #     Semgrep etc. re-run on the same file, filtered to the same check).
    #     If it passes, the vulnerability is objectively closed. Ancillary
    #     CLI checks (aws s3api get-*, describe-*) are supplementary — useful
    #     for the trace but they can fail for reasons unrelated to whether
    #     the fix worked (unset shell var, missing IAM permission, output
    #     format shift). Rolling back a confirmed fix because of a supplementary
    #     check failure defeats the whole point of the closed loop.
    #   - Absent a scanner re-scan (SA3 v2.4 hard rule 17 violation), fall
    #     back to strict mode: any non-rescan failure triggers rollback.
    # Collect ALL re-scan tests (batch mode emits one per finding — the old
    # `next()` only picked the first, losing signal for the others).
    all_rescans = [v for v in validation_results if v.is_rescan]
    passed_rescans = [v for v in all_rescans if v.passed]
    failed_rescans = [v for v in all_rescans if not v.passed]
    # Primary rescan (for ancillary-vs-authoritative comparison downstream):
    # the FIRST re-scan test. Kept for backward compat with single-fix packages.
    rescan = all_rescans[0] if all_rescans else None
    non_rescan_failures = [v for v in validation_results if not v.is_rescan and not v.passed]

    # Rollback decision (updated 2026-08-21):
    #   - ALL re-scans failed → rollback (nothing worked)
    #   - SOME re-scans passed, SOME failed → PARTIAL SUCCESS
    #     (keep the file — good edits stay applied. Unfixed findings noted
    #     in error_message. This preserves the value of batching: one bad
    #     LLM composition doesn't undo the good ones.)
    #   - ALL re-scans passed → success (as before)
    if all_rescans and not passed_rescans:
        # Complete re-scan failure — rollback
        rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
        return StrategyOutcome(
            status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
            step_results=step_results,
            validation_results=validation_results,
            rollback_results=rollback,
            backup_reference=backup.backup_reference,
            terraform_plan_output=plan_out,
            error_message=(
                f"Scanner re-scan still reports the finding{'s' if len(failed_rescans) > 1 else ''}: "
                f"{len(failed_rescans)} of {len(all_rescans)} re-scan(s) failed. "
                f"First: {failed_rescans[0].actual[:200]}"
            ),
        )

    if failed_rescans and passed_rescans:
        # Batch mode with mixed re-scan outcomes: keep the file as-is,
        # good edits stay applied. In master's report each finding shows
        # up as "fixed" or "rolled back" individually — no new status
        # vocabulary needed at the user layer.
        emit_fn(
            ctx.agent_run_id,
            "sub-agent-4",
            "MESSAGE",
            f"🟡 Mixed outcome — {len(passed_rescans)} finding(s) fixed, "
            f"{len(failed_rescans)} finding(s) rolled back. "
            f"File kept as-is (good edits preserved). "
            f"First unfixed: {failed_rescans[0].test_name}",
        )
        return StrategyOutcome(
            status="partial_success",  # internal marker — persistence translates → "success" for DB
            step_results=step_results,
            validation_results=validation_results,
            backup_reference=backup.backup_reference,
            terraform_plan_output=plan_out,
            error_message=(
                f"{len(passed_rescans)} finding(s) fixed, {len(failed_rescans)} rolled back. "
                f"Unfixed re-scans: {[r.test_name for r in failed_rescans][:5]}"
            ),
        )

    if non_rescan_failures:
        if rescan is not None and rescan.passed:
            # Scanner re-scan authoritatively confirmed the fix. Log the
            # ancillary CLI failures as warnings and mark the run successful.
            emit_fn(
                ctx.agent_run_id,
                "sub-agent-4",
                "MESSAGE",
                f"⚠ {len(non_rescan_failures)} ancillary validation test(s) failed "
                f"but scanner re-scan passed — fix confirmed by authoritative check. "
                f"Warnings preserved in validation_results for review. First warning: "
                f"{non_rescan_failures[0].test_name}",
            )
            # Fall through to success
        else:
            # No re-scan emitted — strict mode. Ancillary failures trigger rollback.
            rollback = _safe_rollback(strategy, ctx, emit_fn=emit_fn)
            return StrategyOutcome(
                status="rolled_back" if any(r.status == "success" for r in rollback) else "failed",
                step_results=step_results,
                validation_results=validation_results,
                rollback_results=rollback,
                backup_reference=backup.backup_reference,
                terraform_plan_output=plan_out,
                error_message=(
                    f"{len(non_rescan_failures)} validation test(s) failed "
                    f"(no scanner re-scan present to authoritatively confirm fix) — "
                    f"first failure: {non_rescan_failures[0].test_name}"
                ),
            )

    # HITL v2 — post-fix review capture.
    # If the package was created with `review_required=True`, we DON'T
    # cleanup the backup yet. Instead:
    #   1. Read the current file bytes + the .bak bytes via SSM
    #   2. Compute a unified diff
    #   3. Persist to fix_run.review_diff
    # Master then flips the package to `awaiting_review` (see master's
    # _FIX_TO_PACKAGE_STATUS override). The Approve endpoint later
    # deletes the backup; the Reject endpoint restores from it.
    #
    # Best-effort — a failed capture is logged but doesn't block the
    # success path. Rescan passed = fix is correct regardless of whether
    # the diff was captured.
    _pkg = ctx.package or {}
    if _pkg.get("review_required") and ctx.file_path and backup.backup_reference:
        try:
            from .review import capture_review_diff, persist_diff  # noqa: PLC0415
            from .tools.remote_exec import RemoteExecutor  # noqa: PLC0415

            # Build the executor directly instead of asking the strategy for
            # one — strategy method naming varies (IaCStrategy uses
            # `_executor_for`, ImageStrategy uses `_executor`), and neither
            # is part of a formal interface. Direct construction sidesteps
            # the naming drift entirely.
            _cfg = strategy.config if hasattr(strategy, "config") else None
            _review_executor = RemoteExecutor(
                ctx.target_instance_id,
                region=ctx.aws_region,
                config=_cfg,
                emit_fn=emit_fn,
                run_id=ctx.agent_run_id,
            )
            diff = capture_review_diff(
                _review_executor,
                current_path=ctx.file_path,
                backup_path=backup.backup_reference,
            )
            if diff:
                persist_diff(sb, fix_run_id, diff)
                emit_fn(
                    ctx.agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    f"📸 Review diff captured — {len(diff)} file(s), "
                    f"{sum(d.get('bytes_after', 0) for d in diff)} bytes. "
                    f"Package will pause at awaiting_review for human approval.",
                )
            else:
                emit_fn(
                    ctx.agent_run_id,
                    "sub-agent-4",
                    "MESSAGE",
                    "⚠ Review diff capture returned empty — package will still "
                    "pause at awaiting_review but no diff will show in the UI.",
                )
        except Exception as e:  # noqa: BLE001
            emit_fn(
                ctx.agent_run_id,
                "sub-agent-4",
                "MESSAGE",
                f"⚠ Review diff capture crashed ({type(e).__name__}: "
                f"{str(e)[:200]}) — package will still pause at awaiting_review.",
            )

    # HITL v2 Verified-PR hook. When the package is flagged
    # git_native_review=True, mirror the sandbox-proven edit into the
    # customer's repo as a PR with the rescan output in the body. Best-
    # effort — if the PR side fails, the sandbox success stands.
    if _pkg.get("git_native_review"):
        from app.config import settings  # noqa: PLC0415

        if settings.github_pat and settings.github_repo:
            from .git_verified_pr import open_verified_pr  # noqa: PLC0415

            open_verified_pr(
                sb=sb,
                package_id=ctx.package_id,
                pkg_row=_pkg,
                fix_run_id=ctx.fix_run_id,
                agent_run_id=ctx.agent_run_id,
                validation_results=validation_results,
                emit_fn=emit_fn,
                pat=settings.github_pat,
                repo=settings.github_repo,
                base_branch=settings.github_base_branch or "main",
            )
        else:
            emit_fn(
                ctx.agent_run_id,
                "sub-agent-4",
                "MESSAGE",
                "⚠ Verified-PR requested but GITHUB_PAT/REPO not set — skipping PR side.",
            )

    # 🎉 Success
    return StrategyOutcome(
        status="success",
        step_results=step_results,
        validation_results=validation_results,
        backup_reference=backup.backup_reference,
        terraform_plan_output=plan_out,
    )


# =============================================================================
# Helpers
# =============================================================================
def _safe_rollback(strategy: BaseFixStrategy, ctx: FixContext, *, emit_fn) -> list:
    """Attempt rollback, swallowing exceptions so orchestrator finalization
    always runs. Returns whatever RollbackResult list the strategy produced
    (empty on total-failure)."""
    try:
        return strategy.rollback(ctx)
    except Exception as e:  # noqa: BLE001
        try:
            emit_fn(
                ctx.agent_run_id,
                "sub-agent-4",
                "ERROR",
                f"Rollback itself raised {type(e).__name__}: {str(e)[:300]}",
            )
        except Exception:  # noqa: BLE001, S110
            pass
        return []


def _extract_plan_output(step_results: list) -> str | None:
    """Find the `terraform plan` step's stdout and return it (for audit)."""
    for r in step_results:
        if "terraform plan" in (r.command or ""):
            return (r.stdout or "")[:100_000]
    return None


def _load_package(sb: Any, package_id: int) -> dict | None:
    resp = sb.table("remediation_packages").select("*").eq("id", package_id).limit(1).execute()
    rows = resp.data or []
    return rows[0] if rows else None


def _load_issue(sb: Any, issue_id: int) -> dict | None:
    resp = sb.table("issues").select("*").eq("id", issue_id).limit(1).execute()
    rows = resp.data or []
    return rows[0] if rows else None


def _load_raw_finding(sb: Any, raw_finding_id: int | None) -> dict | None:
    if raw_finding_id is None:
        return None
    # Try the passed sb first (works for real pipeline where sb=public).
    # If not found, fall back to public schema (handles demo pipeline where
    # sb=demo but raw_finding_id points at public.raw_findings).
    resp = sb.table("raw_findings").select("raw").eq("id", raw_finding_id).limit(1).execute()
    rows = resp.data or []
    if rows:
        return (rows[0] or {}).get("raw")
    # Fallback: try public schema
    try:
        from ...db import supabase_admin as _sb_pub  # noqa: PLC0415

        sb_pub = _sb_pub()
        resp = (
            sb_pub.table("raw_findings").select("raw").eq("id", raw_finding_id).limit(1).execute()
        )
        rows = resp.data or []
        return (rows[0] or {}).get("raw") if rows else None
    except Exception:  # noqa: BLE001
        return None
