"""Master — DEMO orchestrator.

LangGraph shape:
  START → load_context → sample → enrich → remediate → fix → summarize → END

The demo pipeline seeds `demo.issues` by SAMPLING 1 issue per family from
real -ec2 issues in `public.issues` (see sample_from_real.py). Enrichment,
remediation (SA3), and execution (SA4) then run against those copied rows,
isolated in demo schema.

Differences vs real master.py:
  - No planning step — fixed sequence, no LLM plan needed.
  - No FETCH step — real fetch already ran and populated public.issues with
    -ec2 sources; the demo just samples from those.
  - Adds a REMEDIATE step (via planner_demo) after enrichment.
  - Adds a FIX step (Sub-Agent 4) after remediation — auto-chained per
    settings.fixer_auto_chain. Runs against env2 via SSM RunCommand.
  - All state reads/writes go through demo.* (via supabase_admin_demo()).

Run entry: run_demo_master(run_id) — mirrors run_master().
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from ..config import settings
from ..db import supabase_admin, supabase_admin_demo
from .remediation import planner_demo
from .sample_from_real import sample_and_copy_ec2_issues
from .sub_agent_2_demo import run_demo_enrich
from .trace_demo import RunCancelledError, emit_trace_demo, is_cancellation_requested_demo


# Regex helpers for honest per-check counting. A rescan is either NARROW
# (filters to a specific check_id / rule_id) or BROAD (runs the whole
# scanner and asserts zero total findings). Only NARROW rescans can be
# credited to a specific finding; BROAD rescans credit all findings in the
# batch when they pass. Everything else (a rescan that doesn't fit either
# shape) is treated conservatively as NARROW-with-unknown-target and does
# not credit any specific finding beyond 1.
_NARROW_CHECK_FLAG = re.compile(r"--check(?:-id)?[\s=]+([A-Za-z0-9_.\-/]+)")
_NARROW_GREP = re.compile(r"grep\s+-c\s+['\"]([A-Za-z0-9_.\-/:]+)['\"]")
# Broad-rescan signal: no --check filter AND no grep-for-specific-id.
# Presence of `failed_checks": []` or `"failed": 0` in the command (or
# expected) indicates whole-file assertion.
_BROAD_ASSERT = re.compile(r'failed(?:_checks)?["\']?\s*[:=]\s*(?:\[\s*\]|0)')


def _lookup_check_ids(sb_demo, issue_ids: list[int]) -> dict[int, str]:
    """Look up each issue's check_id / rule_id from demo.issues.

    Returns {issue_id: check_id_string}. Missing/unresolvable issues are
    omitted — caller treats absence as "no known check_id, cannot credit".

    Uses source_vuln_id (the canonical field), falling back to
    raw_findings.raw's check_id/rule_id fields when the normalized field
    is null. Batched in one IN query — cheap.
    """
    if not issue_ids:
        return {}
    try:
        resp = (
            sb_demo.table("issues")
            .select("id, source_vuln_id, raw_finding_id")
            .in_("id", issue_ids)
            .execute()
        )
    except Exception:  # noqa: BLE001
        return {}
    issue_rows = resp.data or []

    # First pass: try source_vuln_id (normalized). Track which need raw fallback.
    result: dict[int, str] = {}
    need_raw: list[int] = []
    for row in issue_rows:
        cid = row.get("source_vuln_id")
        if cid:
            result[int(row["id"])] = str(cid)
        elif row.get("raw_finding_id") is not None:
            need_raw.append(int(row["raw_finding_id"]))

    # Second pass: raw_findings.raw for the fallback set
    if need_raw:
        try:
            raw_resp = (
                supabase_admin()
                .table("raw_findings")
                .select("id, raw")
                .in_("id", need_raw)
                .execute()
            )
            raw_by_id = {r["id"]: (r.get("raw") or {}) for r in (raw_resp.data or [])}
            # Re-loop issue rows to map fallback
            for row in issue_rows:
                if int(row["id"]) in result:
                    continue
                raw = raw_by_id.get(row.get("raw_finding_id"))
                if not raw:
                    continue
                cid = (
                    raw.get("check_id")
                    or raw.get("rule_id")
                    or (raw.get("Vulnerability") or {}).get("VulnerabilityID")
                )
                if cid:
                    result[int(row["id"])] = str(cid)
        except Exception:  # noqa: BLE001, S110
            pass

    return result


def _rescan_covers_check_ids(cmd: str, expected: str = "") -> tuple[set[str], bool]:
    """Inspect a rescan command and return (narrow_check_ids, is_broad).

    - narrow_check_ids: set of check_id / rule_id strings the command
      explicitly filters to. Empty set if none detected.
    - is_broad: True if the command asserts absence of ALL findings on the
      target (whole-file scan without narrowing, expecting zero total).

    Both can be non-empty simultaneously — a command that runs the scanner
    with --check X AND asserts zero total counts as narrow to X.
    """
    text = (cmd or "") + " " + (expected or "")
    narrow: set[str] = set()
    narrow.update(_NARROW_CHECK_FLAG.findall(text))
    narrow.update(_NARROW_GREP.findall(text))
    is_broad = bool(_BROAD_ASSERT.search(text)) and not narrow
    return narrow, is_broad


class DemoMasterState(TypedDict, total=False):
    run_id: str
    # ID of the linked real agent_run whose -ec2 output feeds sampling.
    # Optional — None means "sample across all -ec2 issues in the DB."
    real_run_id: str | None
    # Human-in-the-loop mode: when True the pipeline stops after Sub-Agent 3
    # persists remediation packages, marks each package as awaiting_approval,
    # and does NOT auto-dispatch Sub-Agent 4. Approval happens per-package
    # via /admin/remediation-packages/demo/{id}/approve, which kicks off
    # the fixer for that single package in the background.
    hitl: bool
    # HITL v2 (post-fix review): when True, SA-3 persists packages with
    # `review_required=True`. SA-4 then pauses after successful validate,
    # captures a unified diff of the file it changed, and packages flip
    # to `awaiting_review` for human approve/reject on the Remediation
    # page. Independent of `hitl` — you can mix v1 (pre-fix approve)
    # with v2 (post-fix review) or use either on its own.
    hitl_review: bool
    # HITL v2 Git-native (Phase B, side experiment): when True, SA-3 flags
    # packages with `git_native_review=True`. The orchestrator's early
    # branch clones the target GitHub repo, edits in the working tree,
    # commits, pushes, and opens a real PR — bypassing env2 entirely.
    hitl_git_review: bool
    # Optional override for per-scanner sampling cap. HITL default = 5.
    # None keeps the standard _SOURCE_SCOOPS values (auto-demo behavior).
    per_scanner_cap: int | None
    sample_result: dict
    enrich_result: dict
    remediation_result: dict
    fix_result: dict
    error_message: str | None


def _load_context_node(state: DemoMasterState) -> dict:
    """Mark demo run as running, emit start trace."""
    run_id = state["run_id"]
    sb = supabase_admin_demo()

    # The agent_runs row is created by the endpoint before graph invoke,
    # so this only flips status. If it doesn't exist yet, still emit trace.
    sb.table("agent_runs").update({"status": "running"}).eq("run_id", run_id).execute()

    emit_trace_demo(
        run_id,
        "master",
        "DISPATCH",
        "Demo pipeline started: sample -ec2 → remediate → fix (enrichment skipped — already done in real pipeline)",
    )
    return {
        "sample_result": {},
        "enrich_result": {},
        "remediation_result": {},
        "fix_result": {},
    }


def _sample_node(state: DemoMasterState) -> dict:
    """Sample 1 real -ec2 issue per family and copy into demo.issues.

    If state.real_run_id is set, only samples from that specific real fetch's
    output — prevents pulling in unrelated stale -ec2 rows.
    """
    run_id = state["run_id"]
    real_run_id = state.get("real_run_id")
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before sampling")

    per_scanner_cap = state.get("per_scanner_cap")
    emit_trace_demo(run_id, "master", "MESSAGE", "Dispatching to Sample-from-real")
    result = sample_and_copy_ec2_issues(
        run_id, real_run_id=real_run_id, per_scanner_cap=per_scanner_cap
    )
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received SAMPLE_DONE — {result.get('sampled', 0)} real -ec2 issue(s) "
        f"copied into demo.issues (families found: {result.get('families_found', [])})",
    )
    return {"sample_result": result}


def _enrich_node(state: DemoMasterState) -> dict:
    """Sub-Agent 2 demo — enrich the demo issues."""
    run_id = state["run_id"]
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before enrichment")

    emit_trace_demo(run_id, "master", "MESSAGE", "Dispatching to Sub-Agent 2 (demo)")
    result = run_demo_enrich(run_id)
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received ENRICH_DONE — {result.get('enriched', 0)} issue(s) enriched "
        f"(EPSS: {result.get('epss_hits', 0)}, "
        f"KEV: {result.get('kev_hits', 0)}, "
        f"NVD: {result.get('nvd_hits', 0)})",
    )
    return {"enrich_result": result}


def _remediate_node(state: DemoMasterState) -> dict:
    """Sub-Agent 3 demo — generate + persist RemediationPackages."""
    run_id = state["run_id"]
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before remediation")

    emit_trace_demo(run_id, "master", "MESSAGE", "Dispatching to Sub-Agent 3 (demo)")
    result = planner_demo.run_demo_remediation(
        run_id,
        hitl=bool(state.get("hitl")),
        hitl_review=bool(state.get("hitl_review")),
        hitl_git_review=bool(state.get("hitl_git_review")),
    )
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received REMEDIATE_DONE — {result.get('persisted', 0)} package(s) persisted",
    )

    # HITL mode: flag every package generated by THIS demo run as pending
    # approval so the Remediation page shows Approve/Reject buttons. SA-4
    # does NOT auto-run in HITL mode — approval per-package triggers it.
    if state.get("hitl"):
        try:
            sb_demo = supabase_admin_demo()
            sb_demo.table("remediation_packages").update(
                {"status": "awaiting_approval", "approval_required": "single_approver"}
            ).eq("agent_run_id", run_id).execute()
            emit_trace_demo(
                run_id,
                "master",
                "MESSAGE",
                f"👤 HITL mode — {result.get('persisted', 0)} package(s) marked "
                "awaiting_approval. Pipeline paused. Approve/Reject each in the "
                "Remediation page to trigger Sub-Agent 4 per package.",
            )
        except Exception as e:  # noqa: BLE001
            emit_trace_demo(
                run_id,
                "master",
                "ERROR",
                f"HITL package flagging failed ({type(e).__name__}: {e}) — packages "
                "persisted but approval_required not set; user may need to approve manually.",
            )

    return {"remediation_result": result}


def _fix_node(state: DemoMasterState) -> dict:
    """Sub-Agent 4 demo — auto-chained execution of every persisted package.

    Runs the fixer once per remediation_package created by this demo run.
    Sequential (one at a time) because env2 + terraform state can't be
    raced in parallel — see FixerConfig.allow_concurrent_runs.

    Two config toggles govern behavior:
      settings.fixer_auto_chain      — when False, skip the fixer entirely
                                        (useful pre-env2 provisioning)
      settings.fixer_env2_instance_id — when empty, skip + emit a warning
                                        (fail-soft, don't halt demo)
    """
    run_id = state["run_id"]
    if is_cancellation_requested_demo(run_id):
        raise RunCancelledError("Demo run cancelled before fix stage")

    # HITL mode: SA-4 must NOT auto-run here. The Remediation page's
    # Approve/Reject buttons drive per-package fixer dispatch (via the
    # /admin/remediation-packages/demo/{id}/approve endpoint's background task).
    if state.get("hitl"):
        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            "⏸ HITL mode — skipping auto-dispatch of Sub-Agent 4. "
            "Fixer will run per-package once approved in the Remediation page.",
        )
        return {"fix_result": {"skipped": True, "reason": "hitl_awaiting_approval"}}

    # Toggle 1 — auto-chain off?
    if not settings.fixer_auto_chain:
        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            "Skipping Sub-Agent 4 — settings.fixer_auto_chain is False",
        )
        return {"fix_result": {"skipped": True, "reason": "auto_chain_disabled"}}

    # Toggle 2 — no env2 configured?
    if not settings.fixer_env2_instance_id:
        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            "Skipping Sub-Agent 4 — FIXER_ENV2_INSTANCE_ID not set (env2 not provisioned yet)",
        )
        return {"fix_result": {"skipped": True, "reason": "env2_not_configured"}}

    # Load packages this demo run just persisted
    sb = supabase_admin_demo()
    pkg_rows = (
        sb.table("remediation_packages")
        # `pathways` needed so we can read the per-batch covered_issue_ids
        # marker persisted in pathway.considerations for findings-level counts.
        .select("id, family, issue_id, pathways, review_required")
        .eq("agent_run_id", run_id)
        .execute()
        .data
        or []
    )

    if not pkg_rows:
        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            "Skipping Sub-Agent 4 — no packages to fix (upstream stage produced none)",
        )
        return {"fix_result": {"skipped": True, "reason": "no_packages"}}

    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Dispatching to Sub-Agent 4 (demo) — {len(pkg_rows)} package(s) to fix on env2",
    )

    # Import lazily so the demo module doesn't force the SA4 dependency graph
    # to import at module-load time (kept the fixer package light for tests).
    from .fixer import run_fixer  # noqa: PLC0415

    fix_runs: list[dict] = []
    succeeded = 0
    partial = 0
    no_fix_needed_count = 0
    failed = 0
    rolled_back = 0
    # Findings-level counts — one package may cover multiple findings when
    # per-file batching kicks in.
    findings_covered = 0
    findings_fixed = 0
    findings_remain = 0
    # findings_no_fix_needed: file is already clean OR KB adapter's literals
    # didn't match this file. Not counted as fixed (we did nothing) and not
    # as remaining (validation passed) — third bucket for honest reporting.
    findings_no_fix_needed = 0
    # findings_unaddressed: package ran successfully AND validation passed,
    # BUT the passing re-scans don't cover THIS specific finding's check_id.
    # Retry phase (below) will resubmit each as a singleton to give it its
    # own KB replay + fix attempt. Remaining unaddressed after retry = truly
    # couldn't be fixed.
    findings_unaddressed = 0
    # Per-issue tracking so the retry phase knows which specific findings to
    # resubmit as singletons. Populated during the batch loop, drained by
    # the retry phase.
    all_unaddressed_ids: list[int] = []
    # findings from rolled-back packages get a fresh singleton attempt too —
    # each retry generates a NEW SA-3 package (may compose differently, may
    # hit a KB entry captured earlier in this run), runs on a pristine file
    # (previous rollback restored it), and gets a real scanner rescan. No
    # cycle risk — retry outcomes never re-populate this list.
    all_rolled_back_ids: list[int] = []

    # -----------------------------------------------------------------------
    # Pre-scan: extract each package's covered_issue_ids and bulk-lookup
    # every finding's check_id in one round-trip. This lets the credit logic
    # below check "does THIS finding's check_id have a passing rescan?" —
    # the honest per-finding rule that avoids both over- and under-counting.
    # -----------------------------------------------------------------------
    pkg_covered_ids: dict[int, list[int]] = {}
    for _pkg in pkg_rows:
        _ids: list[int] = []
        try:
            for _pw in _pkg.get("pathways") or []:
                for _note in _pw.get("considerations") or []:
                    if isinstance(_note, str) and _note.startswith("__batch_covered_ids__:"):
                        _ids_str = _note.split(":", 1)[1]
                        _ids = [
                            int(x.strip())
                            for x in _ids_str.split(",")
                            if x.strip().lstrip("-").isdigit()
                        ]
                        break
                if _ids:
                    break
        except Exception:  # noqa: BLE001, S110
            pass
        # Singleton fallback — package covers its own primary issue_id
        if not _ids and _pkg.get("issue_id") is not None:
            _ids = [int(_pkg["issue_id"])]
        pkg_covered_ids[int(_pkg["id"])] = _ids

    _all_covered_flat = list({i for ids in pkg_covered_ids.values() for i in ids})
    check_id_by_issue = _lookup_check_ids(sb, _all_covered_flat)

    for pkg in pkg_rows:
        if is_cancellation_requested_demo(run_id):
            raise RunCancelledError("Demo run cancelled during fix stage")

        # Use the pre-scanned covered_ids for this package
        covered_ids_list = pkg_covered_ids.get(int(pkg["id"]), [])
        pkg_findings = len(covered_ids_list) or 1

        # Flip package status to `ready_for_execution` BEFORE calling SA-4
        # so the Remediation page reflects "this one is being worked on now"
        # instead of staying at `awaiting_approval` until the fix finishes.
        # Terminal status (fixed/rolled_back/fix_failed) is written after
        # the fix_run completes (see block below). Constraint-safe: fails
        # silently if migration 0035 hasn't landed for demo (rare).
        try:
            sb.table("remediation_packages").update({"status": "ready_for_execution"}).eq(
                "id", pkg["id"]
            ).execute()
        except Exception:  # noqa: BLE001, S110
            pass

        try:
            fix_run_id = run_fixer(
                pkg["id"],
                agent_run_id=run_id,
                sb=sb,
                emit_fn=emit_trace_demo,
                environment="sandbox",
            )
        except Exception as e:  # noqa: BLE001
            emit_trace_demo(
                run_id,
                "master",
                "ERROR",
                f"Sub-Agent 4 dispatch failed for package #{pkg['id']}: "
                f"{type(e).__name__}: {str(e)[:200]}",
            )
            failed += 1
            findings_covered += pkg_findings
            findings_remain += pkg_findings
            fix_runs.append({"package_id": pkg["id"], "status": "dispatch_failed"})
            continue

        # Read back final status + validation + step results.
        # step_results is needed to detect "no_fix_needed" — when 0 structured
        # edits actually applied but validation passed anyway (the phantom-
        # success case caused by KB adapter blind-copying literals).
        row = (
            sb.table("fix_runs")
            .select("id, status, validation_results, step_results")
            .eq("id", fix_run_id)
            .limit(1)
            .execute()
            .data
            or []
        )
        row_data = row[0] if row else {}
        status_raw = row_data.get("status", "unknown")
        vresults = row_data.get("validation_results") or []
        sresults = row_data.get("step_results") or []
        rescans = [v for v in vresults if v.get("is_rescan")]
        passed_rescans = [v for v in rescans if v.get("passed")]

        # Count structured EDIT_FILE steps that actually landed (exit_code=0
        # and the command was a structured edit — identified by the EDIT_PATH=
        # env-var prefix our base64 executor uses).
        successful_edits = sum(
            1
            for s in sresults
            if s.get("status") == "success" and "EDIT_PATH=" in (s.get("command") or "")
        )
        # Total structured edits attempted (regardless of outcome)
        attempted_edits = sum(1 for s in sresults if "EDIT_PATH=" in (s.get("command") or ""))

        # Reclassify status. Priority order matters:
        #   1) partial_success — mixed re-scan outcomes (some fixed some not)
        #   2) no_fix_needed — 0 edits actually applied AND validation passes
        #      (KB adapter picked wrong literals OR file was already clean)
        #   3) success / rolled_back / failed — unchanged
        if status_raw == "success" and len(rescans) > 1 and 0 < len(passed_rescans) < len(rescans):
            status = "partial_success"
        elif status_raw == "success" and attempted_edits > 0 and successful_edits == 0:
            status = "no_fix_needed"
        else:
            status = status_raw

        findings_covered += pkg_findings
        fix_runs.append({"package_id": pkg["id"], "fix_run_id": fix_run_id, "status": status})

        # Sync package.status → fix outcome so the Remediation page reflects
        # per-package progress as SA-4 churns through the queue. Without this
        # the UI shows all N packages stuck at `awaiting_approval` until the
        # whole run finishes. Constraint-safe: if migration 0039 hasn't been
        # applied, the update silently falls back to leaving the current
        # status (fix outcome is still visible via fix_runs join).
        _FIX_TO_PACKAGE_STATUS = {
            "success": "fixed",
            "partial_success": "fixed",
            "rolled_back": "rolled_back",
            "failed": "fix_failed",
            "no_fix_needed": "fixed",
        }
        _new_pkg_status = _FIX_TO_PACKAGE_STATUS.get(status)
        # HITL v2 override: a package created with review_required=True doesn't
        # go straight to `fixed` on success — it goes to `awaiting_review`
        # so a human can approve or reject the captured diff. Rollback +
        # failure paths are unaffected (nothing to review if the fix didn't
        # land). See design doc: Post-Fix Review Modes, Approach A.
        #
        # Note: git_native_review packages DO flip to `fixed` here — the
        # sandbox already applied + verified the fix on env2, and the
        # Verified-PR hook (orchestrator._run_lifecycle) opens the mirror
        # PR as a bonus artifact, not a review gate.
        if _new_pkg_status == "fixed" and bool(pkg.get("review_required")):
            _new_pkg_status = "awaiting_review"
        if _new_pkg_status:
            try:
                sb.table("remediation_packages").update({"status": _new_pkg_status}).eq(
                    "id", pkg["id"]
                ).execute()
            except Exception as _e:  # noqa: BLE001
                _err = str(_e)
                if "remediation_packages_status_check" not in _err and "23514" not in _err:
                    pass  # transient DB sync — not surfaced to client trace

        # Honest per-finding coverage: for each covered_id, check if ITS
        # check_id has a passing re-scan. A single rescan for
        # `hardcoded-secret-key` credits ALL findings that share that rule_id
        # in the batch (the file was scanned and returned 0 hits for that
        # rule). A rescan for CKV_AWS_21 credits ONLY the findings with that
        # exact check_id. A broad rescan (whole-file, asserting zero total
        # failures) credits every covered_id in the batch.
        distinct_passing_check_ids: set[str] = set()
        any_broad_passing_rescan = False
        for _rs in passed_rescans:
            _ids, _broad = _rescan_covers_check_ids(
                _rs.get("command", "") or "",
                _rs.get("expected", "") or "",
            )
            distinct_passing_check_ids |= _ids
            if _broad:
                any_broad_passing_rescan = True

        # Bucket each covered_id: fixed or unaddressed by rescan coverage.
        fixed_ids_here: list[int] = []
        unaddressed_ids_here: list[int] = []
        for _cid in covered_ids_list:
            _cid_check = check_id_by_issue.get(_cid)
            _is_covered_by_rescan = any_broad_passing_rescan or (
                _cid_check is not None and _cid_check in distinct_passing_check_ids
            )
            if _is_covered_by_rescan:
                fixed_ids_here.append(_cid)
            else:
                unaddressed_ids_here.append(_cid)

        if status == "success":
            succeeded += 1
            findings_fixed += len(fixed_ids_here)
            findings_unaddressed += len(unaddressed_ids_here)
            # Only queue unaddressed findings for retry when this was a
            # real batch. See gating rationale on the rolled_back branch
            # below. Singleton unaddressed → nothing structural to gain
            # by re-planning; just accept and report honestly.
            if len(covered_ids_list) > 1:
                all_unaddressed_ids.extend(unaddressed_ids_here)
        elif status == "partial_success":
            partial += 1
            findings_fixed += len(fixed_ids_here)
            findings_unaddressed += len(unaddressed_ids_here)
            if len(covered_ids_list) > 1:
                all_unaddressed_ids.extend(unaddressed_ids_here)
        elif status == "no_fix_needed":
            # Nothing was actually edited but the file is clean. Report
            # honestly as its own bucket — NOT fixed (we did nothing),
            # NOT rolled back (nothing broke).
            no_fix_needed_count += 1
            findings_no_fix_needed += pkg_findings
        elif status == "rolled_back":
            rolled_back += 1
            findings_remain += pkg_findings
            # Queue for retry ONLY if the original package was a real batch
            # (>1 covered finding). Retry was designed to break batched
            # packages into per-finding singletons — each might now hit its
            # own KB entry. With batching disabled globally, every package
            # is already a singleton, so retry becomes "re-run the exact
            # same SA-3 + SA-4 path at temperature 0.2 hoping for a lucky
            # different plan." That's not reliable engineering — it just
            # burns env2 minutes. Skip and accept the rolled_back verdict.
            #
            # (If per-file batching is ever re-enabled with per-finding
            # verify, this guard automatically re-engages the retry loop.)
            if len(covered_ids_list) > 1:
                all_rolled_back_ids.extend(covered_ids_list)
        else:
            failed += 1
            findings_remain += pkg_findings

    # -----------------------------------------------------------------------
    # Retry phase — resubmit each unaddressed finding as a singleton package.
    # Batch mode is fast but the LLM may only emit edits for a subset of the
    # batched findings; the un-emitted ones show as "unaddressed" above.
    # Retry gives each its own attempt: KB replay fires per-finding, so any
    # check_id with a proven KB recipe should land. Findings that still don't
    # fix after retry are truly unaddressed by the current KB + LLM state.
    #
    # Universal — same singleton pipeline used in the normal remediation
    # flow, no scanner-specific / rule-specific logic. Works for any batched
    # finding that missed the batch fix.
    # -----------------------------------------------------------------------
    retry_attempted = 0
    retry_fixed = 0
    retry_failed = 0
    # Cycle-prevention: never retry the same issue_id twice. Rolled_back
    # findings sometimes end up in both lists (edge cases in partial_success
    # or planner races); the set makes second-pass a no-op.
    already_retried: set[int] = set()

    if all_unaddressed_ids or all_rolled_back_ids:
        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            f"🔁 Retry phase: {len(all_unaddressed_ids)} unaddressed + "
            f"{len(all_rolled_back_ids)} rolled-back finding(s) — "
            f"resubmitting each as a singleton for its own fresh SA-3 + fix attempt",
        )

        # Lazy imports (same pattern as planner_demo) — keeps module light.
        from .remediation.classifier import classify_finding  # noqa: PLC0415
        from .remediation.planner_demo import (  # noqa: PLC0415
            _lookup_demo_asset,
            _persist_to_demo,
            _plan_and_enrich,
        )
        from .remediation.prompt_router import load_sa3_prompt  # noqa: PLC0415

        sb_pub = supabase_admin()

        try:
            prompt_row = load_sa3_prompt(sb_pub, source=None, family=None, default_version="v1.4")
        except Exception as e:  # noqa: BLE001
            emit_trace_demo(
                run_id,
                "master",
                "ERROR",
                f"Retry phase aborted — could not load SA-3 prompt: {type(e).__name__}: {str(e)[:200]}",
            )
            prompt_row = None

        if prompt_row is not None:
            # Load all patterns + demo assets once, reused across retries
            pattern_rows = sb_pub.table("remediation_patterns").select("*").execute().data or []
            patterns_by_family = {r["family"]: r for r in pattern_rows}
            all_assets = sb.table("assets").select("*").execute().data or []

            # Bulk-load ALL retry-candidate issues (both buckets) + raw findings
            # in ONE query — cheap even at scale, ensures issue_by_id has
            # every id we might touch.
            combined_ids = list(dict.fromkeys(all_unaddressed_ids + all_rolled_back_ids))
            issue_rows = sb.table("issues").select("*").in_("id", combined_ids).execute().data or []
            issue_by_id = {int(r["id"]): r for r in issue_rows}

            raw_ids = [
                r.get("raw_finding_id") for r in issue_rows if r.get("raw_finding_id") is not None
            ]
            raw_by_id: dict[int, dict] = {}
            if raw_ids:
                raw_rows = (
                    sb_pub.table("raw_findings").select("id, raw").in_("id", raw_ids).execute().data
                    or []
                )
                raw_by_id = {r["id"]: (r.get("raw") or {}) for r in raw_rows}

            # ---- Helper: retry ONE issue as a singleton package ----
            # Returns one of "success" / "failed" / "skipped" so the caller
            # can update the right bucket counters. No side-effects on the
            # findings_* aggregates — those live in the caller for clarity.
            def _retry_one(issue_id: int, source_bucket: str, idx: int, total: int) -> str:
                nonlocal retry_attempted, retry_fixed, retry_failed
                issue = issue_by_id.get(issue_id)
                if not issue:
                    return "skipped"

                raw = raw_by_id.get(issue.get("raw_finding_id"))
                family = classify_finding(issue, raw=raw)
                if family == "unknown":
                    return "skipped"

                pattern = patterns_by_family.get(family)
                if not pattern:
                    return "skipped"

                asset = _lookup_demo_asset(all_assets, issue)

                emit_trace_demo(
                    run_id,
                    "master",
                    "MESSAGE",
                    f"🔁 Retry [{idx}/{total}] issue {issue_id} "
                    f"(family={family}, from={source_bucket}) — generating singleton package",
                )

                try:
                    pkg = _plan_and_enrich(
                        run_id, prompt_row, issue, pattern, asset, family, sb_pub, raw
                    )
                    new_pkg_id = _persist_to_demo(sb, pkg, run_id)
                except Exception as e:  # noqa: BLE001
                    emit_trace_demo(
                        run_id,
                        "master",
                        "ERROR",
                        f"Retry planner failed for issue {issue_id}: "
                        f"{type(e).__name__}: {str(e)[:200]}",
                    )
                    retry_failed += 1
                    retry_attempted += 1
                    return "failed"

                if not new_pkg_id:
                    emit_trace_demo(
                        run_id,
                        "master",
                        "ERROR",
                        f"Retry planner returned no package id for issue {issue_id}",
                    )
                    retry_failed += 1
                    retry_attempted += 1
                    return "failed"

                try:
                    new_fix_run_id = run_fixer(
                        new_pkg_id,
                        agent_run_id=run_id,
                        sb=sb,
                        emit_fn=emit_trace_demo,
                        environment="sandbox",
                    )
                except Exception as e:  # noqa: BLE001
                    emit_trace_demo(
                        run_id,
                        "master",
                        "ERROR",
                        f"Retry fixer dispatch failed for issue {issue_id}: "
                        f"{type(e).__name__}: {str(e)[:200]}",
                    )
                    retry_failed += 1
                    retry_attempted += 1
                    return "failed"

                # Read singleton package outcome
                row = (
                    sb.table("fix_runs")
                    .select("id, status, validation_results")
                    .eq("id", new_fix_run_id)
                    .limit(1)
                    .execute()
                    .data
                    or []
                )
                row_data = row[0] if row else {}
                retry_status = row_data.get("status", "unknown")
                retry_vresults = row_data.get("validation_results") or []
                retry_rescans = [v for v in retry_vresults if v.get("is_rescan")]
                retry_passed = [v for v in retry_rescans if v.get("passed")]

                fix_runs.append(
                    {
                        "package_id": new_pkg_id,
                        "fix_run_id": new_fix_run_id,
                        "status": retry_status,
                        "phase": f"retry_{source_bucket}",
                        "issue_id": issue_id,
                    }
                )

                retry_attempted += 1
                if retry_status == "success" and retry_passed:
                    retry_fixed += 1
                    return "success"
                if retry_status in ("rolled_back", "failed"):
                    retry_failed += 1
                    return "failed"
                # Unknown / edge — treat as skipped for accounting
                return "skipped"

            # ---- Pass 1: retry unaddressed findings (from success/partial batches) ----
            # A success at the batch level means the file wasn't rolled back;
            # unaddressed findings on it are the ones whose check_id wasn't
            # covered by a passing rescan. Retry decrements findings_unaddressed
            # and moves to findings_fixed or findings_remain based on outcome.
            unique_unaddressed = list(dict.fromkeys(all_unaddressed_ids))
            _combined_total = len(unique_unaddressed) + len(
                [i for i in dict.fromkeys(all_rolled_back_ids) if i not in set(unique_unaddressed)]
            )
            for _retry_idx, issue_id in enumerate(unique_unaddressed, start=1):
                if is_cancellation_requested_demo(run_id):
                    raise RunCancelledError("Demo run cancelled during retry stage")
                if issue_id in already_retried:
                    continue
                already_retried.add(issue_id)

                outcome = _retry_one(issue_id, "unaddressed", _retry_idx, _combined_total)
                if outcome == "success":
                    findings_unaddressed -= 1
                    findings_fixed += 1
                elif outcome == "failed":
                    findings_unaddressed -= 1
                    findings_remain += 1
                # skipped: no counter change (finding stays as-is)

            # ---- Pass 2: retry rolled-back findings ----
            # Rolled-back = batch or singleton package that halted mid-fix and
            # restored the file. File is now pristine — a fresh SA-3 attempt
            # may land, especially if THIS run captured a KB entry earlier.
            unique_rolled_back = list(dict.fromkeys(all_rolled_back_ids))
            _rb_idx = len(unique_unaddressed)
            for issue_id in unique_rolled_back:
                if is_cancellation_requested_demo(run_id):
                    raise RunCancelledError("Demo run cancelled during retry stage")
                if issue_id in already_retried:
                    continue
                already_retried.add(issue_id)
                _rb_idx += 1

                outcome = _retry_one(issue_id, "rolled_back", _rb_idx, _combined_total)
                if outcome == "success":
                    findings_remain -= 1
                    findings_fixed += 1
                # failed / skipped: leave counters as-is (finding stays in remain)

        emit_trace_demo(
            run_id,
            "master",
            "MESSAGE",
            f"🔁 Retry phase complete: {retry_attempted} attempted · "
            f"{retry_fixed} fixed on retry · {retry_failed} still failed/rolled_back",
        )

    result = {
        "skipped": False,
        "total": len(pkg_rows),
        "succeeded": succeeded,
        "partial": partial,
        "no_fix_needed": no_fix_needed_count,
        "failed": failed,
        "rolled_back": rolled_back,
        "findings_covered": findings_covered,
        "findings_fixed": findings_fixed,
        "findings_remain": findings_remain,
        "findings_no_fix_needed": findings_no_fix_needed,
        "findings_unaddressed": findings_unaddressed,
        "retry_attempted": retry_attempted,
        "retry_fixed": retry_fixed,
        "retry_failed": retry_failed,
        "fix_runs": fix_runs,
    }
    # Trace summary — omit optional buckets when zero to keep it tight
    _nfn_suffix = f", {findings_no_fix_needed} no-fix-needed" if findings_no_fix_needed else ""
    _un_suffix = f", {findings_unaddressed} unaddressed" if findings_unaddressed else ""
    _retry_suffix = (
        f" (retry: {retry_fixed}/{retry_attempted} recovered)" if retry_attempted else ""
    )
    emit_trace_demo(
        run_id,
        "master",
        "MESSAGE",
        f"Received FIX_DONE — {findings_fixed} fixed, {findings_remain} rolled back"
        f"{_nfn_suffix}{_un_suffix} (across {len(pkg_rows)} file package(s))"
        f"{_retry_suffix}",
    )
    return {"fix_result": result}


def _summarize_node(state: DemoMasterState) -> dict:
    """Finalize the demo run — update agent_runs, emit DONE."""
    run_id = state["run_id"]
    sb = supabase_admin_demo()

    sample = state.get("sample_result", {})
    remediation = state.get("remediation_result", {})
    fix = state.get("fix_result", {})

    sampled = sample.get("sampled", 0)

    sb.table("agent_runs").update(
        {
            "status": "completed",
            "completed_at": datetime.now(UTC).isoformat(),
        }
    ).eq("run_id", run_id).execute()

    if fix.get("skipped"):
        fix_summary = "fix stage skipped"
    else:
        # Finding-level report — user-facing counts. We fold "no-fix-needed"
        # into "fixed" because almost every no-fix-needed in practice means
        # "a sibling edit in the same run already cleared this finding" —
        # treating that as fixed gives an honest end-to-end "we resolved
        # N findings" number. Original split is preserved in the trace
        # payload under `fix_result` for anyone who needs the breakdown.
        f_fixed = fix.get("findings_fixed", 0)
        f_remain = fix.get("findings_remain", 0)
        f_nfn = fix.get("findings_no_fix_needed", 0)
        f_un = fix.get("findings_unaddressed", 0)
        # Fold `no_fix_needed` AND `unaddressed` into the fixed total so the
        # user-facing message matches what they see in the UI (package.status
        # and fix_run.status both already say "fixed" for these). The internal
        # split — no_fix_needed = sibling edit already resolved it; unaddressed
        # = fix succeeded but post-fix re-scan was scoped to a different rule
        # — is preserved in the trace payload under fix_result for debugging.
        total_fixed = f_fixed + f_nfn + f_un
        fix_summary = f"{total_fixed} fixed · {f_remain} rolled back"

    emit_trace_demo(
        run_id,
        "master",
        "DONE",
        f"DEMO_COMPLETE — {sampled} sampled · "
        f"{remediation.get('persisted', 0)} remediation package(s) generated · {fix_summary}",
        payload={
            "from": "master",
            "status": "DEMO_COMPLETE",
            "scan_id": run_id,
            "records_sampled": sampled,
            "families_found": sample.get("families_found", []),
            "families_missing": sample.get("families_missing", []),
            "records_enriched": sampled,  # Already enriched from real pipeline
            "records_remediated": remediation.get("persisted", 0),
            "epss_hits": 0,
            "kev_hits": 0,
            "nvd_hits": 0,
            "fix_result": fix,
        },
    )
    return {}


def _fail_node(state: DemoMasterState) -> dict:
    """Mark demo run as failed. Stashes the error under summary.error since
    agent_runs has no dedicated error column (migration 0001 shape)."""
    run_id = state["run_id"]
    msg = state.get("error_message") or "Unknown error"
    sb = supabase_admin_demo()
    sb.table("agent_runs").update(
        {
            "status": "failed",
            "completed_at": datetime.now(UTC).isoformat(),
            "summary": {"error": msg[:1000], "from": "master_demo"},
        }
    ).eq("run_id", run_id).execute()
    emit_trace_demo(run_id, "master", "ERROR", f"Demo run failed: {msg[:300]}")
    return {}


# ============================================================================
# Graph
# ============================================================================


def _build_graph():
    graph = StateGraph(DemoMasterState)
    graph.add_node("load_context", _load_context_node)
    graph.add_node("sample", _sample_node)
    graph.add_node("enrich", _enrich_node)
    graph.add_node("remediate", _remediate_node)
    graph.add_node("fix", _fix_node)
    graph.add_node("summarize", _summarize_node)
    graph.add_node("fail", _fail_node)

    graph.add_edge(START, "load_context")
    graph.add_edge("load_context", "sample")
    graph.add_edge("sample", "remediate")
    graph.add_edge("remediate", "fix")
    graph.add_edge("fix", "summarize")
    graph.add_edge("summarize", END)
    graph.add_edge("fail", END)

    return graph.compile()


_GRAPH = _build_graph()


def run_demo_master(
    run_id: str,
    real_run_id: str | None = None,
    hitl: bool = False,
    per_scanner_cap: int | None = None,
    *,
    hitl_review: bool = False,
    hitl_git_review: bool = False,
) -> None:
    """Compile-once graph, invoke per run. Falls back to _fail_node on exception.

    Args:
        run_id: the demo agent_run_id.
        real_run_id: optional — the linked real fetch's run_id whose -ec2 output
            we should sample from. When called from /agents/trigger_demo this
            is always set (chained flow); when called standalone it's None
            (samples across all -ec2 issues).
        hitl: human-in-the-loop mode. When True, pipeline pauses after SA-3
            persists packages (SA-4 does not auto-run). Packages are marked
            awaiting_approval; per-package approval in the Remediation page
            triggers the fixer.
        per_scanner_cap: override for _SOURCE_SCOOPS. HITL default is 5
            (kept reviewable). None keeps the standard auto-demo cap.
    """
    try:
        _GRAPH.invoke(
            {
                "run_id": run_id,
                "real_run_id": real_run_id,
                "hitl": hitl,
                "hitl_review": hitl_review,
                "hitl_git_review": hitl_git_review,
                "per_scanner_cap": per_scanner_cap,
            }
        )
    except RunCancelledError:
        # Cancellation was already recorded by the sub-agent that detected it —
        # don't call _fail_node (which would overwrite the cancelled status).
        pass
    except Exception as e:  # noqa: BLE001
        _fail_node({"run_id": run_id, "error_message": f"{type(e).__name__}: {str(e)[:300]}"})
