"""Sub-Agent 3 (Remediation Planner) — DEMO orchestrator.

For each enriched issue in demo.issues (agent_run_id = current demo run):
  1. Classify family (public_exposure / network_exposure / injection /
     vulnerable_dependency / os_vulnerability)
  2. Load the pattern from public.remediation_patterns (shared config)
  3. Load the asset from demo.assets (via asset_identity match — no view)
  4. Load the sub-agent-3 prompt from public.prompt_db (shared config)
  5. Call the LLM (v1.4 prompt — includes issue.solution +
     issue.remediation_suggestion as hints)
  6. Attach validation metadata + confidence to each pathway
  7. Persist the RemediationPackage to demo.remediation_packages

Reuses pure helpers from `planner.py`:
  _validation_metadata_for, _issue_payload, _pattern_payload,
  _derive_approval, classify_finding, compute_confidence

Key schema difference vs planner.py's plan_remediation():
  planner.py uses `issue_with_asset` VIEW for asset lookup — that view
  doesn't exist in the demo schema (migration 0046 only mirrored the 6
  base tables, not views). This orchestrator does the asset match directly
  against demo.assets using the same identity keys the view checks.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from ...config import settings
from ...db import supabase_admin, supabase_admin_demo
from ...models import LLMRemediationOutput, RemediationPackage, RemediationPathway
from ..llm import invoke_structured_with_retry
from ..trace_demo import emit_trace_demo
from .classifier import classify_finding
from .confidence import compute_confidence, compute_confidence_agentic
from .planner import (
    _agent_validation_metadata,
    _extract_iac_context,
    _issue_payload,
    _pattern_payload,
    _validation_metadata_for,
)


# Hard cap on packages generated per demo run. Belt-and-suspenders with the
# sample_from_real cap — trims here even if upstream loosens later.
_MAX_PACKAGES = 20


def run_demo_remediation(
    run_id: str,
    hitl: bool = False,
    *,
    hitl_review: bool = False,
    hitl_git_review: bool = False,
) -> dict:
    """Generate + persist RemediationPackages for every demo issue in this run.

    Args:
        run_id: the DEMO agent_run this planning belongs to.
        hitl: when True, disables per-file batching so every finding gets its
            own package. HITL exists so a human can review + approve per-
            finding; batching collapses that granularity and (empirically)
            produces under-covered fix plans once the batch grows past ~5
            findings. Auto-demo keeps batching for speed.
        hitl_review: HITL v2 Sandbox. When True, packages are persisted with
            `review_required=True` so SA-4 pauses after successful validate
            and captures a diff for human approve/reject on the Remediation
            page. Independent of `hitl`.
        hitl_git_review: HITL v2 Git-native (Phase B, side experiment). When
            True, packages are persisted with `git_native_review=True` AND
            `review_required=True`. The orchestrator's early branch detects
            git_native_review and runs the git flow (clone/branch/commit/PR)
            instead of the SSM flow. Existing pipelines untouched.

    Returns {"planned": N, "persisted": N, "failed": N}.
    """
    sb_demo = supabase_admin_demo()
    sb_pub = supabase_admin()  # for prompt_db + remediation_patterns (shared)

    emit_trace_demo(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        "Loading enriched issues from demo.issues for this run",
    )

    issues = sb_demo.table("issues").select("*").eq("agent_run_id", run_id).execute().data or []

    if not issues:
        emit_trace_demo(
            run_id,
            "sub-agent-3",
            "DONE",
            "REMEDIATE_DONE — no issues to remediate",
            payload={"from": "sub-agent-3", "status": "REMEDIATE_DONE", "planned": 0},
        )
        return {"planned": 0, "persisted": 0, "failed": 0}

    # Batch-fetch raw_findings so the classifier can use raw.resource for
    # deterministic family classification (Checkov normalized titles are
    # just the check_id, so title-keyword rules fail without this).
    raw_by_id: dict[int, dict] = {}
    raw_ids = [i["raw_finding_id"] for i in issues if i.get("raw_finding_id") is not None]
    if raw_ids:
        raw_rows = (
            sb_pub.table("raw_findings").select("id, raw").in_("id", raw_ids).execute().data or []
        )
        raw_by_id = {r["id"]: (r.get("raw") or {}) for r in raw_rows}

    def _raw_for(issue: dict) -> dict | None:
        return raw_by_id.get(issue.get("raw_finding_id"))

    # Load pattern index for all seen families in ONE query (cheap).
    families_seen = {classify_finding(i, raw=_raw_for(i)) for i in issues}
    families_seen.discard("unknown")
    patterns_by_family: dict[str, dict] = {}
    if families_seen:
        rows = (
            sb_pub.table("remediation_patterns")
            .select("*")
            .in_("family", list(families_seen))
            .execute()
            .data
            or []
        )
        patterns_by_family = {r["family"]: r for r in rows}

    # Load Sub-Agent 3 (HYBRID fallback) prompt via the master router.
    # Router picks the most-specific prompt available in prompt_db based on
    # (source, family) with fallback to the generic sub-agent-3 v1.4 row.
    # Today only the generic row exists so behavior is identical to the old
    # hardcoded query. Specialized prompts (e.g. sub-agent-3-trivy-os) will
    # be picked up automatically once seeded.
    #
    # NOTE: source/family are per-issue, but we load a default prompt once
    # here for the outer loop's trace event. Per-issue routing happens inside
    # _plan_and_enrich (agent_v2) so each issue gets its own specialized prompt.
    from .prompt_router import load_sa3_prompt  # noqa: PLC0415

    prompt_row = load_sa3_prompt(sb_pub, source=None, family=None, default_version="v1.4")

    # Pre-load all demo.assets rows once and build a lookup index by identity.
    all_assets = sb_demo.table("assets").select("*").execute().data or []

    emit_trace_demo(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        f"Loaded {len(issues)} issue(s), {len(patterns_by_family)} pattern(s), "
        f"{len(all_assets)} asset(s). Prompt {prompt_row['agent']}@{prompt_row['version']} "
        f"({prompt_row['model']})",
    )

    planned = persisted = failed = 0

    # --- Per-file batching ---
    # Per-finding packaging — one package per finding, always.
    file_groups = {f"__singleton__:{iss['id']}": [iss] for iss in issues}
    mode_label = "👤 HITL mode" if hitl else "🤖 Auto-demo"
    emit_trace_demo(
        run_id,
        "sub-agent-3",
        "MESSAGE",
        f"{mode_label} — one package per finding: "
        f"{len(issues)} finding(s) → {len(issues)} package(s)",
    )

    # Lazy import validators once outside the worker so the import lock
    # isn't hit N times in parallel threads.
    from .plan_validators import (  # noqa: PLC0415
        has_errors as _has_val_errors,
        summary as _val_summary,
        validate_package,
    )

    # Cap how many groups we even submit to workers.
    groups_to_run = list(file_groups.items())[:_MAX_PACKAGES]
    if len(file_groups) > _MAX_PACKAGES:
        emit_trace_demo(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"Package cap ({_MAX_PACKAGES}) — limiting to first {_MAX_PACKAGES} "
            f"of {len(file_groups)} group(s)",
        )

    def _plan_one(file_key: str, group: list[dict]) -> dict:
        """Worker: classify → LLM plan → validate. No DB writes here.

        Returns a result dict consumed by the main thread for persistence.
        Keys: status ('ok'|'skip'|'error'), pkg, primary, family, file_key,
              val_issues, batch_label (for multi-finding trace).
        """
        primary = _select_primary(group)
        related = [i for i in group if i.get("id") != primary.get("id")]

        family = classify_finding(primary, raw=_raw_for(primary))
        if family == "unknown":
            return {
                "status": "skip",
                "reason": "unclassified",
                "primary": primary,
                "file_key": file_key,
            }

        pattern = patterns_by_family.get(family)
        if pattern is None:
            return {
                "status": "skip",
                "reason": f"no_pattern:{family}",
                "primary": primary,
                "file_key": file_key,
            }

        asset = _lookup_demo_asset(all_assets, primary)

        if related:
            pkg = _plan_and_enrich_batch(
                run_id, prompt_row, primary, related, pattern, asset, family, sb_pub, _raw_for
            )
            batch_label = (
                f"🧩 Batched {1 + len(related)} finding(s) for {file_key} into 1 package "
                f"(primary issue={primary['id']}, related={[i['id'] for i in related]})"
            )
        else:
            pkg = _plan_and_enrich(
                run_id, prompt_row, primary, pattern, asset, family, sb_pub, _raw_for(primary)
            )
            batch_label = None

        val_issues = validate_package(pkg, primary_issue=primary, family=family)
        return {
            "status": "ok",
            "pkg": pkg,
            "primary": primary,
            "family": family,
            "file_key": file_key,
            "val_issues": val_issues,
            "batch_label": batch_label,
        }

    # Parallel planning — workers call LLM concurrently; main thread
    # serializes DB inserts to avoid Supabase client contention.
    workers = max(1, int(settings.llm_parallel_workers or 5))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sa3-plan") as executor:
        future_map = {executor.submit(_plan_one, fk, grp): (fk, grp) for fk, grp in groups_to_run}

        for future in as_completed(future_map):
            file_key, group = future_map[future]
            primary_fallback = _select_primary(group)

            try:
                result = future.result()
            except Exception as e:  # noqa: BLE001
                failed += 1
                emit_trace_demo(
                    run_id,
                    "sub-agent-3",
                    "ERROR",
                    f"Package generation failed for file={file_key} "
                    f"(primary issue={primary_fallback.get('id')}, "
                    f"{type(e).__name__}): {str(e)[:250]}",
                )
                continue

            primary = result["primary"]

            if result["status"] == "skip":
                reason = result.get("reason", "")
                if reason == "unclassified":
                    emit_trace_demo(
                        run_id,
                        "sub-agent-3",
                        "ERROR",
                        f"Primary issue {primary.get('id')} in file group did not classify — skipping",
                    )
                else:
                    family_str = reason.replace("no_pattern:", "")
                    emit_trace_demo(
                        run_id,
                        "sub-agent-3",
                        "ERROR",
                        f"No pattern for family='{family_str}' — skipping file={file_key}",
                    )
                failed += 1
                continue

            # status == 'ok'
            pkg = result["pkg"]
            family = result["family"]
            planned += 1

            if result.get("batch_label"):
                pass  # batch grouping detail — not shown in client trace

            val_issues = result["val_issues"]
            if val_issues:
                _msg = _val_summary(val_issues)
                _details = "; ".join(
                    f"[{i.severity} {i.check}] {i.message[:180]}" for i in val_issues[:5]
                )
                if _has_val_errors(val_issues):
                    emit_trace_demo(
                        run_id,
                        "sub-agent-3",
                        "ERROR",
                        f"✗ Plan rejected by validators for issue {primary['id']}: "
                        f"{_msg}. {_details}",
                    )
                    failed += 1
                    continue
                emit_trace_demo(
                    run_id,
                    "sub-agent-3",
                    "MESSAGE",
                    f"⚠ Plan validators reported warnings for issue "
                    f"{primary['id']}: {_msg}. {_details}",
                )

            _persist_to_demo(
                sb_demo,
                pkg,
                run_id,
                review_required=hitl_review or hitl_git_review,
                git_native_review=hitl_git_review,
            )
            persisted += 1

            emit_trace_demo(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"Package generated for issue {primary['id']} "
                f"(family={family}, confidence="
                f"{pkg.pathways[pkg.recommended_pathway_index].confidence_score})",
            )

    emit_trace_demo(
        run_id,
        "sub-agent-3",
        "DONE",
        f"REMEDIATE_DONE — {planned} planned, {persisted} persisted, {failed} failed",
        payload={
            "from": "sub-agent-3",
            "status": "REMEDIATE_DONE",
            "planned": planned,
            "persisted": persisted,
            "failed": failed,
        },
    )
    return {"planned": planned, "persisted": persisted, "failed": failed}


# =============================================================================
# Per-file batching helpers
# =============================================================================
# Group findings by the file they target so a single package can fix multiple
# vulnerabilities in one place — eliminates within-run state drift AND matches
# how enterprise coding agents (Cursor, Aider, Copilot Workspaces) work.
# Universal — no scanner-specific logic, works for any tool that emits a file.

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "": 0}


def _file_key_for(issue: dict, raw: dict | None) -> str:
    """Return the file path this issue targets. Empty string when unattributable
    (findings without a file path fall through as their own group, one per issue,
    which preserves current per-finding behavior for OS/CVE-style findings).

    For file-based scanners (SAST, SCA, IaC): uses `_extract_iac_context` so
    batching agrees with SA-3's downstream file_path resolution. Same
    consequences noted for SCA (`raw.target` lowercase + relative-path
    resolution → all findings on same file batch together).

    For container-image scanners (trivy-image, grype-image, snyk-container)
    AND host-OS scanners (trivy-os, tenable-nessus, qualys-vmdr, rapid7):
    returns an EMPTY string so each finding falls through to a singleton
    `__no_file__:<issue_id>` key — one package per CVE, not one batched
    package covering everything on the image / host.

    Rationale: image fixes edit a Dockerfile line per CVE (e.g. add / bump a
    `RUN apt-get install --only-upgrade` for that specific package). OS fixes
    run `apt-get install --only-upgrade <pkg>` per package on the host. Both
    have the same "no shared file, no shared edit" property — batching N CVEs
    into one package puts N independent commands into one LLM composition,
    where a single bad step takes down the whole batch. Meanwhile the ONE
    rescan the LLM emits typically covers only one check_id, so the honest
    counting layer only credits 1 fix even when N landed. Per-CVE packages
    match the natural unit of work: one CVE → one package upgrade → one
    rescan for that specific CVE.

    Per-file batching is genuinely helpful for SAST (all findings on one
    source file share a plan/apply cycle) and SCA (all pip pins in one
    requirements.txt). Image + OS fixes don't share that "one file, N cheap
    edits" property — every fix triggers its own build or its own apt
    transaction anyway.
    """
    raw = raw or {}
    src = (issue.get("source") or "").lower()
    if (
        "trivy-image" in src
        or "grype-image" in src
        or "snyk-container" in src
        or "trivy-os" in src
        or "tenable-nessus" in src
        or "qualys-vmdr" in src
        or "rapid7" in src
    ):
        return ""

    ctx = _extract_iac_context(issue, raw)
    fp = ctx.get("file_path")
    if isinstance(fp, str) and fp:
        return fp
    # Fallback for older shapes / no path (OS CVEs) — keep as singleton
    identity_file = (issue.get("asset_identity") or {}).get("file")
    return identity_file or ""


def _group_issues_by_file(issues: list[dict], raw_for) -> dict:
    """Group issues by target file. Preserves insertion order (dict).

    Returns dict[file_key, list[issues]]. Files sharing a path get one entry
    with all their findings. Findings without a file path get a unique key
    per issue (fall through as singletons) so we don't accidentally batch
    unrelated no-path findings together.
    """
    groups: dict = {}
    for iss in issues:
        key = _file_key_for(iss, raw_for(iss))
        if not key:
            # Unattributable — synthesize a unique key so it stays a singleton
            key = f"__no_file__:{iss.get('id')}"
        groups.setdefault(key, []).append(iss)
    return groups


def _select_primary(group: list[dict]) -> dict:
    """Pick the highest-risk finding in a file group as the primary.
    Others ride along in the payload as additional_findings. Highest
    derived_risk wins; ties broken by severity rank, then by earliest id."""

    def _score(iss: dict) -> tuple[float, int, int]:
        risk = iss.get("derived_risk")
        risk_val = float(risk) if risk is not None else -1.0
        sev_val = _SEVERITY_ORDER.get((iss.get("severity") or "").upper(), 0)
        # Negate id so lower id wins the tiebreak (stable ordering)
        return (risk_val, sev_val, -int(iss.get("id") or 0))

    return max(group, key=_score)


def _plan_and_enrich_batch(
    run_id: str,
    prompt_row: dict,
    primary: dict,
    related: list[dict],
    pattern: dict,
    asset: dict,
    family: str,
    sb_pub,
    raw_for,
) -> RemediationPackage:  # noqa: F821
    """Plan a batched fix package covering primary + related findings for one file.

    SA-3 sees the primary as the main issue and the related findings as
    `additional_findings` in the user_payload. The SAST execution_context
    guidance (in agent_v2) tells the LLM to emit ONE pathway containing
    ONE backup step + N #EDIT_FILE steps (one per finding) + verify_absent
    checks for each + a single re-scan at the end.
    """
    raw = raw_for(primary)
    related_payloads = [
        {
            "id": r.get("id"),
            "source_vuln_id": r.get("source_vuln_id"),
            "cve_id": r.get("cve_id"),
            "cwe_id": r.get("cwe_id"),
            "title": r.get("title"),
            "severity": r.get("severity"),
            "description": r.get("description"),
            "solution": r.get("solution"),
            "remediation_suggestion": r.get("remediation_suggestion"),
            # Include raw finding line-range hint if scanner provided one
            "raw_hint": {
                "check_id": (raw_for(r) or {}).get("check_id"),
                "start_line": (raw_for(r) or {}).get("start", {}).get("line"),
                "end_line": (raw_for(r) or {}).get("end", {}).get("line"),
            },
        }
        for r in related
    ]
    # Delegate to the same LLM path used for single-issue planning. Batch
    # context is attached to the issue dict itself (no signature churn) —
    # downstream _issue_payload / remediate_agentic pick it up and surface
    # `additional_findings` in the user_payload so SA-3 composes ONE
    # package covering all.
    covered_ids = [primary["id"]] + [r["id"] for r in related]
    primary_with_batch = dict(primary)
    primary_with_batch["_batch_related_findings"] = related_payloads
    primary_with_batch["_batch_covered_ids"] = covered_ids
    pkg = _plan_and_enrich(
        run_id, prompt_row, primary_with_batch, pattern, asset, family, sb_pub, raw
    )
    # Persist the covered-issue list on the package pathway so master can
    # count real findings per fix_run without a DB schema change. The
    # `__batch_covered_ids__:` prefix is a machine-readable audit note in
    # pathway.considerations (a list[str] the schema already supports).
    try:
        marker = f"__batch_covered_ids__:{','.join(str(i) for i in covered_ids)}"
        for pathway in pkg.pathways:
            existing = list(pathway.considerations or [])
            existing.append(marker)
            # Cap at schema max (15) — batch marker is important, drop oldest
            # (informational) items if we exceed
            if len(existing) > 15:
                existing = existing[:14] + [marker]
            pathway.considerations = existing
    except Exception:  # noqa: BLE001, S110 — audit best-effort, never blocks
        pass
    return pkg


def _lookup_demo_asset(all_assets: list[dict], issue: dict) -> dict:
    """Match an issue to a demo asset using the same identity keys as the
    real issue_with_asset view (project / repo / name / os → name/aliases; hostname; ipv4).
    Returns trimmed dict of fields the LLM needs, or {} if unattributed.
    """
    identity = issue.get("asset_identity") or {}
    project = identity.get("project")
    repo = identity.get("repo")
    name = identity.get("name")
    os_id = identity.get("os")
    hostname = identity.get("hostname")
    ipv4 = identity.get("ipv4")

    for a in all_assets:
        aliases = a.get("aliases") or []
        if project and (a.get("name") == project or project in aliases):
            return _trim_asset(a)
        if repo and (a.get("name") == repo or repo in aliases):
            return _trim_asset(a)
        if name and (a.get("name") == name or name in aliases):
            return _trim_asset(a)
        if os_id and (a.get("name") == os_id or os_id in aliases):
            return _trim_asset(a)
        if hostname and (a.get("hostname") == hostname or hostname in aliases):
            return _trim_asset(a)
        if ipv4 and a.get("ip_address") == ipv4:
            return _trim_asset(a)
    return {}


def _trim_asset(a: dict) -> dict:
    return {
        "name": a.get("name"),
        "application_name": a.get("application_name"),
        "environment": a.get("environment"),
        "exposure": a.get("exposure"),
        "business_criticality": a.get("business_criticality"),
        "data_classification": a.get("data_classification"),
        "compliance_tags": a.get("compliance_tags") or [],
    }


def _plan_and_enrich(
    run_id: str,
    prompt_row: dict,
    issue: dict,
    pattern: dict,
    asset: dict,
    family: str,
    sb_pub,
    raw: dict | None = None,
) -> RemediationPackage:
    """Try agentic path first (v2.0). On success, validation_metadata +
    confidence derive from the agent's actual citations + verifier report
    (pattern NOT used). On failure, fall back to hybrid v1.4 with pattern
    adaptation.

    `raw` is the raw_findings.raw jsonb for this issue (or None). Used for
    IaC context extraction (file_path, working_directory, resource_name,
    scanner_type) that SA3 v2.4's prompt needs to decide IaC-first vs
    direct-cloud fix shape.
    """
    agent_result = None  # tuple (LLMRemediationOutput, VerificationReport) | None
    llm_output: LLMRemediationOutput | None = None

    # --- Try KB DIRECT REPLAY first (fastest path — no web search) ---
    # If the knowledge base has a verified successful recipe for this exact
    # check_id + resource_type, adapt it via a single constrained LLM call
    # and return immediately. ~3 seconds, deterministic, no Tavily usage.
    try:
        from .kb_replay import try_kb_replay  # noqa: PLC0415

        kb_replay_output, kb_replay_id = try_kb_replay(
            issue=issue,
            family=family,
            raw=raw,
            sb=sb_pub,
            run_id=run_id,
            emit_fn=emit_trace_demo,
        )

        if kb_replay_output is not None:
            from ...models import RemediationPathway, ValidationMetadata  # noqa: PLC0415, F401
            from datetime import datetime as _dt, UTC as _UTC  # noqa: PLC0415

            # KB entries only exist because a prior fix succeeded (or we promoted
            # one from a prior success). Any KB replay is proven by definition.
            enriched_pathways: list[RemediationPathway] = []
            for pathway in kb_replay_output.pathways:
                pathway.validation_metadata = ValidationMetadata(
                    status="proven",
                    sources=[f"Knowledge Base #{kb_replay_id} (proven recipe)"],
                    timestamp=_dt.now(_UTC).isoformat(),
                    confidence="high",
                )
                pathway.confidence_score = 95
                pathway.confidence_components = {
                    "source": "kb_replay",
                    "kb_id": kb_replay_id,
                    "reason": "Proven fix replayed from knowledge base",
                }
                enriched_pathways.append(pathway)

            emit_trace_demo(
                run_id,
                "sub-agent-3",
                "MESSAGE",
                f"📚 KB replay path complete — returning package from KB #{kb_replay_id} "
                f"(confidence=95, family={family}). Skipping agentic/hybrid.",
            )

            return RemediationPackage(
                issue_id=int(issue["id"]),
                family=family,
                finding=kb_replay_output.finding,
                root_cause=kb_replay_output.root_cause,
                impact=kb_replay_output.impact,
                pathways=enriched_pathways,
                recommended_pathway_index=0,
                approval_required="auto",
            )
    except Exception as e:  # noqa: BLE001
        emit_trace_demo(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"KB replay module raised: {type(e).__name__}: {str(e)[:200]} "
            "— continuing with agentic/hybrid path.",
        )

    # --- AGENTIC path (Phase-2 default) ---
    if settings.tavily_api_key:
        from .agent_v2 import run_agentic_planner  # noqa: PLC0415

        try:
            # Augment issue with IaC context so SA3 v2.4's prompt has file_path,
            # working_directory, resource_name, scanner_type. Preserves original
            # issue for downstream persistence.
            agent_issue = {**issue, **_extract_iac_context(issue, raw)}

            # For container-image scanners, resolve dockerfile_path dynamically
            # from connection_registry metadata (same lookup SA4 does). This gives
            # SA3's LLM the correct paths to generate commands against.
            #
            # Always override (not just when file_path is empty) because
            # `_extract_iac_context` above populates file_path with a mangled
            # image-reference-as-path for image findings (e.g. it prepends
            # `settings.fixer_env2_path_prefix` to `vuln-java-image:latest`
            # producing `/opt/vuln-labs/cspm-lab/vuln-java-image:latest`,
            # which downstream `test -f` correctly reports as non-existent
            # and fails the fix run at pre-flight). Overriding with the real
            # Dockerfile path fixes that.
            source = (issue.get("source") or "").lower()
            _is_image_scanner = (
                "trivy-image" in source or "grype-image" in source or "snyk-container" in source
            )
            if _is_image_scanner:
                try:
                    reg_row = (
                        sb_pub.table("connection_registry")
                        .select("metadata")
                        .eq("tool", issue.get("source"))
                        .single()
                        .execute()
                        .data
                    )
                    reg_meta = (reg_row or {}).get("metadata") or {}
                    if reg_meta.get("dockerfile_path"):
                        agent_issue["file_path"] = reg_meta["dockerfile_path"]
                        agent_issue["working_directory"] = (
                            reg_meta.get("build_directory")
                            or reg_meta["dockerfile_path"].rsplit("/", 1)[0]
                        )
                        emit_trace_demo(
                            run_id,
                            "sub-agent-3",
                            "MESSAGE",
                            f"🖼 Image finding: overrode file_path with dockerfile_path="
                            f"{reg_meta['dockerfile_path']} (from connection_registry)",
                        )
                    else:
                        # Registry row exists but no dockerfile_path — clear the
                        # mangled path so downstream `test -f` doesn't fail on it.
                        # Fixer will still know it's a container_image finding
                        # via execution_context, but won't try to grep a file.
                        agent_issue["file_path"] = None
                        emit_trace_demo(
                            run_id,
                            "sub-agent-3",
                            "MESSAGE",
                            f"⚠ Image finding: no dockerfile_path in connection_registry "
                            f"for tool={issue.get('source')!r} — cleared mangled file_path "
                            f"(fixer needs registry row with dockerfile_path)",
                        )
                    # Also set resource_name to image ref from raw target
                    if not agent_issue.get("resource_name") and raw:
                        target = raw.get("target") or raw.get("Target") or ""
                        image_ref = target.split("(")[0].strip() if "(" in target else target
                        if image_ref:
                            agent_issue["resource_name"] = image_ref
                    # Inject fix_pattern so SA3 knows the correct fix shape for this image type
                    if reg_meta.get("fix_pattern"):
                        agent_issue["fix_pattern"] = reg_meta["fix_pattern"]
                except Exception as _e:  # noqa: BLE001
                    # Registry lookup failed entirely — clear mangled path so
                    # pre-flight doesn't fail on it.
                    agent_issue["file_path"] = None
                    emit_trace_demo(
                        run_id,
                        "sub-agent-3",
                        "MESSAGE",
                        f"⚠ Image finding: connection_registry lookup failed "
                        f"({type(_e).__name__}) — cleared mangled file_path",
                    )

            agent_result = run_agentic_planner(
                issue=agent_issue,
                asset=asset,
                family=family,
                run_id=run_id,
                sb_pub=sb_pub,
                emit_fn=emit_trace_demo,
            )
        except Exception as e:  # noqa: BLE001
            emit_trace_demo(
                run_id,
                "sub-agent-3",
                "ERROR",
                f"Agentic planner raised, falling back to hybrid: "
                f"{type(e).__name__}: {str(e)[:200]}",
            )

    enriched_pathways: list[RemediationPathway] = []

    if agent_result is not None:
        # --- AGENT SUCCESS PATH — no pattern used. Metadata + confidence from
        #     what the agent actually cited + what the verifier observed. ---
        llm_output, verification_report = agent_result
        for pathway in llm_output.pathways:
            pathway.validation_metadata = _agent_validation_metadata(pathway)
            confidence = compute_confidence_agentic(
                issue=issue,
                asset=asset,
                pathway=pathway,
                verification_report=verification_report,
            )
            pathway.confidence_score = confidence["score"]
            pathway.confidence_components = confidence["components"]
            enriched_pathways.append(pathway)
    else:
        # --- HYBRID fallback (pattern-based v1.4) ---
        # Per-issue prompt resolution — if a specialized prompt exists for this
        # finding's source+family, use it in the hybrid path too (not just agentic).
        # This makes the specialized trivy-image prompt work in BOTH paths.
        from .prompt_router import load_sa3_prompt as _router_load  # noqa: PLC0415

        issue_source = (issue.get("source") or "").strip()
        hybrid_prompt = _router_load(
            sb_pub, source=issue_source, family=family, default_version="v1.4"
        )
        params = hybrid_prompt.get("parameters") or {}
        base_temp = float(params.get("temperature", 0.3))
        max_tokens = int(params.get("max_tokens", 2500))
        primary_model = hybrid_prompt["model"]
        fallback_model = params.get("fallback_model", "gpt-4o")

        payload = {
            "issue": _issue_payload(issue, raw),
            "asset": asset,
            "pattern": _pattern_payload(pattern),
        }

        # Execution context — same injection as the agentic path. Tells the
        # generic prompt whether this is a container-image fix, host fix, or IaC.
        source = (issue.get("source") or "").lower()
        if "trivy-image" in source or "snyk-container" in source or "grype-image" in source:
            payload["execution_context"] = {
                "target_type": "container_image",
                "fix_approach": (
                    "Edit the Dockerfile to REMOVE the vulnerable package version pin entirely "
                    "(e.g. change 'openssl=1.1.1f-1ubuntu2' to just 'openssl'). "
                    "This lets apt-get install the latest available patched version at build time. "
                    "Do NOT specify a target version — just remove the =X.Y.Z pin. "
                    "Then rebuild with docker build --no-cache."
                ),
                "dockerfile_path": "/opt/vuln-labs/infra-lab/Dockerfile",
                "build_directory": "/opt/vuln-labs/infra-lab",
                "image_ref": "vuln-lab-image:latest",
                "rebuild_command": "cd /opt/vuln-labs/infra-lab && docker build --no-cache -t vuln-lab-image:latest .",
                "sed_pattern_example": "sed -i 's/<pkg>=<any_version>/<pkg>/' /opt/vuln-labs/infra-lab/Dockerfile",
                "rescan_command": "trivy image vuln-lab-image:latest --scanners vuln --severity HIGH,CRITICAL --format json",
                "rescan_target": "vuln-lab-image:latest (the rebuilt image, NOT ubuntu:20.04)",
                "validation_guidance": (
                    "IMPORTANT: The re-scan validation must check for the ABSENCE of the SPECIFIC CVE being fixed, "
                    "NOT for zero total vulnerabilities. The image has OTHER packages with their own CVEs — "
                    "fixing one CVE does not make the entire image vuln-free. "
                    "Use a command like: trivy image vuln-lab-image:latest --format json 2>&1 | grep -c '<CVE_ID>' || true "
                    "with expected='0' (zero occurrences of that specific CVE). "
                    "Do NOT use expected='\"Vulnerabilities\": []' — that will always fail on a multi-package image."
                ),
                "rescan_exit_code_note": (
                    "CRITICAL SHELL SEMANTICS: grep -c returns exit code 1 when match count is 0 "
                    "(i.e. when the CVE is GONE — the desired outcome). This will cause the execution "
                    "engine to treat a SUCCESSFUL fix as a failure. You MUST append '|| true' to any "
                    "grep -c command so the exit code is always 0. The validation engine checks the "
                    "OUTPUT value (expecting '0'), not the exit code. "
                    "Correct:  trivy image ... --format json 2>&1 | grep -c 'CVE-xxx' || true "
                    "Wrong:    trivy image ... --format json | grep -c 'CVE-xxx'"
                ),
                "remediation_steps_rules": (
                    "Do NOT put the re-scan/validation command in remediation_steps. "
                    "remediation_steps should contain ONLY actionable fix commands: "
                    "backup, sed edit, docker build, verify edit (grep Dockerfile). "
                    "The re-scan belongs EXCLUSIVELY in validation_tests with is_rescan=true."
                ),
                "prohibited_commands": [
                    "sudo reboot",
                    "apt-get install on host",
                    "edits to /etc/ or /usr/ on host",
                    "specifying a fixed version number in sed (just remove the pin)",
                    "expecting zero total vulnerabilities in validation (check only the specific CVE)",
                    "grep -c without || true (grep returns exit 1 on zero matches, which breaks execution)",
                ],
            }
        elif "trivy-os" in source or "tenable" in source or "qualys" in source:
            # Detect OS family: AL2/RHEL use yum, Ubuntu/Debian use apt.
            # Signal comes from the source name (trivy-os-al2 → yum) or
            # could come from connection_registry metadata in the future.
            is_yum = "al2" in source or "rhel" in source or "centos" in source or "amazon" in source
            if is_yum:
                payload["execution_context"] = {
                    "target_type": "host_os",
                    "os_family": "amazon_linux",
                    "package_manager": "yum",
                    "fix_approach": (
                        "Run yum update <pkg> -y directly on the host. "
                        "NEVER pin to a specific version — yum repos serve the latest available. "
                        "NEVER use 'yum install <pkg>-<version>' — the exact version likely doesn't exist in AL2 repos. "
                        "Always use: yum update <pkg> -y (no version suffix, no dash-version). "
                        "If the package name in the CVE is like 'python3-requests', the yum command is: "
                        "yum update python3-requests -y (NOT yum install python3-requests-2.32.4 -y)."
                    ),
                    "verification_approach": (
                        "After upgrade, verify installed version using: "
                        "rpm -q <pkg>. Do NOT check for an exact target version — just confirm the "
                        "package is installed and the version changed."
                    ),
                    "rescan_command": "trivy rootfs / --scanners vuln --severity HIGH,CRITICAL --format json",
                    "rescan_target": "/ (host root filesystem)",
                    "rescan_validation_note": (
                        "CRITICAL SHELL SEMANTICS: grep -c returns exit code 1 when match count is 0 "
                        "(i.e. when the CVE is GONE — the desired outcome). You MUST append '|| true' to any "
                        "grep -c command so the exit code is always 0. The validation engine checks the "
                        "OUTPUT value (expecting '0'), not the exit code. "
                        "Correct:  trivy rootfs / --format json 2>&1 | grep -c 'CVE-xxx' || true "
                        "Wrong:    trivy rootfs / --format json | grep -c 'CVE-xxx'"
                    ),
                    "remediation_steps_rules": (
                        "Do NOT put the re-scan in remediation_steps. "
                        "Steps should be EXACTLY: "
                        "1. Back up package state (rpm -qa > /tmp/backup.txt), "
                        "2. yum update <pkg> -y, "
                        "3. rpm -q <pkg> (verify installed version). "
                        "That's it — 3 core steps. You may add a 4th step for 'yum clean all' or "
                        "'yum makecache' BEFORE the update if useful. "
                        "Do NOT add 'yum versionlock' steps — that plugin is not installed. "
                        "Do NOT add 'yum update -y' (full system update) — only update the specific package. "
                        "Do NOT add 'yum update --security' — only update the specific package. "
                        "Re-scan goes EXCLUSIVELY in validation_tests with is_rescan=true."
                    ),
                    "reboot_policy": (
                        "NEVER reboot. OS package fixes do not require a reboot unless the CVE "
                        "is in kernel or glibc, and even then the reboot should be in validation_tests "
                        "not remediation_steps."
                    ),
                    "prohibited_commands": [
                        "sudo reboot / reboot / shutdown / halt / poweroff (severs SSM connection)",
                        "yum versionlock (plugin not installed on this host — will fail)",
                        "yum install <pkg>-<specific_version> (exact versions don't exist in AL2 repos — use yum update <pkg> -y instead)",
                        "yum update -y (full system update — only update the specific vulnerable package)",
                        "yum update --security (too broad — only update the specific package)",
                        "docker build (wrong strategy for host OS fix)",
                        "apt-get / dpkg (wrong package manager for Amazon Linux)",
                    ],
                }
            else:
                payload["execution_context"] = {
                    "target_type": "host_os",
                    "os_family": "debian_ubuntu",
                    "package_manager": "apt",
                    "fix_approach": (
                        "Run apt-get update && apt-get install --only-upgrade <pkg> -y directly on the host. "
                        "NEVER pin to a specific version — public repos only serve the latest point release. "
                        "Always use: apt-get install --only-upgrade <pkg> -y (no =<version> suffix)."
                    ),
                    "verification_approach": (
                        "After upgrade, verify installed version is GREATER than the vulnerable version "
                        "using: dpkg -l <pkg> | grep <pkg>. Do NOT check for an exact target version — "
                        "just confirm the package is installed. The version might not change if the "
                        "package is already at newest."
                    ),
                    "rescan_command": "trivy rootfs / --cache-dir /tmp/trivy-cache --scanners vuln --severity HIGH,CRITICAL --format json",
                    "rescan_target": "/ (host root filesystem)",
                    "rescan_validation_note": (
                        "CRITICAL SHELL SEMANTICS: grep -c returns exit code 1 when match count is 0 "
                        "(i.e. when the CVE is GONE — the desired outcome). You MUST append '|| true' to any "
                        "grep -c command so the exit code is always 0. The validation engine checks the "
                        "OUTPUT value (expecting '0'), not the exit code. "
                        "Correct:  trivy rootfs / --cache-dir /tmp/trivy-cache --format json 2>&1 | grep -c 'CVE-xxx' || true "
                        "Wrong:    trivy rootfs / --format json | grep -c 'CVE-xxx'"
                    ),
                    "remediation_steps_rules": (
                        "Do NOT put the re-scan in remediation_steps. Steps should be: "
                        "1. apt-get update, 2. apt-get install --only-upgrade <pkg> -y, "
                        "3. dpkg -l <pkg> (verify). Re-scan goes in validation_tests only. "
                        "Do NOT add 'apt list --upgradable' or 'apt autoremove' steps — they waste time. "
                        "Do NOT add 'systemctl restart <service>' unless the CVE is specifically in that service's daemon."
                    ),
                    "reboot_policy": (
                        "NEVER reboot. OS package fixes do not require a reboot unless the CVE "
                        "is in kernel (linux-image-*), libc6, or systemd."
                    ),
                    "prohibited_commands": [
                        "sudo reboot (unless kernel/libc/systemd CVE)",
                        "docker build",
                        "apt-get install <pkg>=<specific_version>",
                        "apt list --upgradable (wastes time, not useful for fix)",
                        "apt autoremove (not needed for single package upgrade)",
                    ],
                }

        llm_output = invoke_structured_with_retry(
            run_id=run_id,
            agent="sub-agent-3",
            schema=LLMRemediationOutput,
            messages=[
                SystemMessage(content=hybrid_prompt["prompt_text"]),
                HumanMessage(content=str(payload)),
            ],
            attempts=[
                (base_temp, primary_model, max_tokens),
                (0.5, primary_model, max_tokens + 500),
                (0.3, fallback_model, max_tokens + 1000),
            ],
            emit_fn=emit_trace_demo,
        )

        validation_meta = _validation_metadata_for(pattern)
        for pathway in llm_output.pathways:
            confidence = compute_confidence(
                issue=issue,
                asset=asset,
                pattern=pattern,
                pathway=pathway,
                affected_asset_count=1,
            )
            pathway.validation_metadata = validation_meta
            pathway.confidence_score = confidence["score"]
            pathway.confidence_components = confidence["components"]
            enriched_pathways.append(pathway)

    recommended_idx = max(
        range(len(enriched_pathways)),
        key=lambda i: enriched_pathways[i].confidence_score or 0,
    )

    return RemediationPackage(
        issue_id=int(issue["id"]),
        family=family,
        finding=llm_output.finding,
        root_cause=llm_output.root_cause,
        impact=llm_output.impact,
        pathways=enriched_pathways,
        recommended_pathway_index=recommended_idx,
        # Demo pipeline is end-to-end automation by definition.
        # Master overrides to "single_approver" when any HITL mode is on.
        approval_required="auto",
    )


def _persist_to_demo(
    sb_demo: Any,
    pkg: RemediationPackage,
    run_id: str,
    *,
    review_required: bool = False,
    git_native_review: bool = False,
) -> int:
    """INSERT a RemediationPackage into demo.remediation_packages.

    review_required (HITL v2): when True, the package carries a flag that
    tells SA-4 to pause after successful validate + capture a diff. The
    Remediation page then shows Approve/Reject buttons on the diff.

    git_native_review (HITL v2 Git-native, Phase B): when True, the
    orchestrator uses the git flow (clone/branch/commit/PR) instead of
    the SSM flow. Requires migration 0042; falls back to omitting the
    column when the DB pre-dates the migration.
    """
    row = {
        "issue_id": pkg.issue_id,
        "family": pkg.family,
        "finding": pkg.finding,
        "root_cause": pkg.root_cause,
        "impact": pkg.impact,
        "pathways": [p.model_dump(mode="json") for p in pkg.pathways],
        "recommended_pathway_index": pkg.recommended_pathway_index,
        "approval_required": pkg.approval_required or "single_approver",
        "status": "awaiting_approval",
        "agent_run_id": run_id,
    }
    # Only include the columns when set — omitting them lets us degrade
    # gracefully if migrations 0041 / 0042 haven't been applied yet.
    if review_required:
        row["review_required"] = True
    if git_native_review:
        row["git_native_review"] = True
    try:
        resp = sb_demo.table("remediation_packages").insert(row).execute()
    except Exception as e:  # noqa: BLE001
        # Migration pre-flight: retry without newer columns if the DB
        # doesn't know about them yet.
        err = str(e)
        stripped = False
        if "git_native_review" in err and git_native_review:
            row.pop("git_native_review", None)
            stripped = True
        if "review_required" in err and review_required:
            row.pop("review_required", None)
            stripped = True
        if stripped:
            resp = sb_demo.table("remediation_packages").insert(row).execute()
        else:
            raise
    rows = resp.data or []
    return rows[0]["id"] if rows else 0
