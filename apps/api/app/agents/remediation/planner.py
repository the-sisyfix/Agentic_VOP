"""Sub-Agent 3 — Remediation Planner.

Takes ONE issue, classifies it into a remediation family, loads the matching
pattern from the remediation_patterns table, and calls the LLM to produce a
RemediationPackage (per Phase-1 Working Model §2 — 10 fields).

The LLM only generates the dynamic prose + filled-in templates. Caller
attaches deterministic metadata (family, rollback_strategy, primary_sources,
issue_id) after the call. Confidence score + approval requirement are filled
later by the Day-4 Confidence Engine.
"""

from __future__ import annotations

import uuid
from datetime import datetime, UTC
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from urllib.parse import urlparse

from ...config import settings
from ...db import supabase_admin
from ...models import (
    LLMRemediationOutput,
    RemediationPackage,
    RemediationPathway,
    ValidationMetadata,
)
from ..llm import invoke_structured_with_retry
from .classifier import classify_finding
from .confidence import compute_confidence, compute_confidence_agentic


# Per Phase-1 doc §7.1, sources are tiered. Tier 1-3 = "validated";
# Tier 4-5 = "partial"; absent = "unvalidated". For Phase-1 our patterns
# all cite multiple Tier 1-3 sources, so packages land as "validated".
_TIER_1_3_KEYWORDS = (
    "aws",
    "microsoft",
    "red hat",
    "canonical",
    "oracle",
    "vmware",
    "apache",
    "openssl",
    "nvd",
    "cve",
    "cisa",
    "kev",
    "ubuntu security",
    "debian security",
    "rhsa",
    "advisory",
)
_TIER_4_5_KEYWORDS = (
    "owasp",
    "cnc",
    "cis",
    "nist",
    "internal",
    "playbook",
)


def _classify_source_tier(source: str) -> int:
    """Returns 1 if source matches Tier 1-3 (vendor/advisory/NVD/CISA),
    4 if Tier 4-5 (project docs / OWASP / CIS), 0 if unknown."""
    s = source.lower()
    if any(k in s for k in _TIER_1_3_KEYWORDS):
        return 1
    if any(k in s for k in _TIER_4_5_KEYWORDS):
        return 4
    return 0


def _validation_metadata_for(pattern: dict) -> ValidationMetadata:
    """Build the §7.1 audit metadata from the pattern's primary_sources.

    Phase-1: we trust the pattern's curated source list (since we built the
    patterns with vendor/CIS/OWASP citations). Phase-2 could add live URL
    fetching to verify the references.
    """
    sources = list(pattern.get("primary_sources") or [])
    if not sources:
        return ValidationMetadata(
            status="unvalidated",
            sources=[],
            timestamp=datetime.now(UTC).isoformat(),
            confidence="low",
        )

    tier_1_3 = sum(1 for s in sources if _classify_source_tier(s) == 1)
    if tier_1_3 >= 2:
        status, confidence = "validated", "high"
    elif tier_1_3 == 1:
        status, confidence = "validated", "medium"
    elif sources:
        status, confidence = "partial", "medium"
    else:
        status, confidence = "unvalidated", "low"

    return ValidationMetadata(
        status=status,
        sources=sources,
        timestamp=datetime.now(UTC).isoformat(),
        confidence=confidence,
    )


def _derive_approval(score: int, priority: str | None) -> str:
    """Package-level approval policy. Mirrors confidence._derive_approval
    but operates on the recommended pathway's score."""
    priority = priority or ""
    if priority == "P0" and score < 80:
        return "multi_stage"
    if score >= 90 and priority in ("P2", "P3"):
        return "auto"
    return "single_approver"


def _load_pattern(sb, family: str) -> dict | None:
    """Fetch the remediation_patterns row for a family."""
    resp = sb.table("remediation_patterns").select("*").eq("family", family).limit(1).execute()
    rows = resp.data or []
    return rows[0] if rows else None


# Domains considered authoritative for the agentic validation_metadata
# status/confidence heuristic. Mirrors the tier-1/2 set in web_search.py +
# confidence.py; keep in sync when adding new authoritative vendors.
_AGENT_AUTHORITATIVE_HOSTS = {
    # --- Cloud provider primary docs (Tier 1) ---
    "docs.aws.amazon.com",
    "aws.amazon.com",
    "docs.microsoft.com",
    "learn.microsoft.com",
    "cloud.google.com",
    "docs.oracle.com",
    # --- Standards bodies + governments (Tier 1) ---
    "cisecurity.org",
    "nvd.nist.gov",
    "csrc.nist.gov",
    "cisa.gov",
    "www.cisa.gov",
    "cwe.mitre.org",
    "capec.mitre.org",
    "attack.mitre.org",
    "cve.mitre.org",
    # --- Core project + community docs (Tier 2) ---
    "owasp.org",
    "cheatsheetseries.owasp.org",
    "kubernetes.io",
    "docs.kubernetes.io",
    "docs.docker.com",
    "developer.hashicorp.com",
    "hashicorp.com",
    "registry.terraform.io",
    "cert.org",
    "us-cert.gov",
    # --- Scanner vendor docs — canonical source for the findings we ingest ---
    "docs.prismacloud.io",
    "docs.paloaltonetworks.com",  # Checkov / Prisma Cloud
    "avd.aquasec.com",
    "docs.aquasec.com",
    "aquasec.com",  # Trivy (Aqua Vulnerability DB)
    "snyk.io",
    "security.snyk.io",
    "docs.snyk.io",  # Snyk
    "docs.wiz.io",  # Wiz
    "docs.tenable.com",  # Tenable / Nessus
    "www.qualys.com",
    "qualys.com",  # Qualys
    "docs.github.com",
    "github.com",  # GitHub advisories / security tab
    # --- OS-vendor security trackers (canonical for os_vulnerability family) ---
    "access.redhat.com",
    "ubuntu.com",
    "security-tracker.debian.org",
    "usn.ubuntu.com",
    "www.suse.com",
    # --- Language ecosystem advisory databases (canonical for vulnerable_dependency) ---
    "advisories.dependabot.com",
    "osv.dev",
    "python.org",
    "docs.python.org",
    "pypi.org",
    "nodejs.org",
    "npmjs.com",
    "maven.apache.org",
    "central.sonatype.com",
    "rubygems.org",
    "packagist.org",
}


def _agent_validation_metadata(pathway: RemediationPathway) -> ValidationMetadata:
    """Build ValidationMetadata from URLs the agent actually cited across the
    pathway. Called on the agentic-success path — pattern's static
    primary_sources are NOT used here.

    Status + confidence heuristic:
      validated / high    — 2+ distinct sources AND at least 1 is authoritative
      partial / medium    — 1+ source cited but only Tier-3/4
      unvalidated / low   — nothing cited (shouldn't happen post-verifier)
    """
    seen_urls: set[str] = set()
    display_sources: list[str] = []

    def _collect(step):
        if step is None:
            return
        url = getattr(step, "source_url", "") or ""
        name = getattr(step, "source", "") or ""
        if url and url not in seen_urls:
            seen_urls.add(url)
            display_sources.append(f"{name} — {url}" if name else url)

    for step in pathway.remediation_steps or []:
        _collect(step)
    if pathway.rollback_plan and pathway.rollback_plan.steps:
        for step in pathway.rollback_plan.steps:
            _collect(step)

    hosts = set()
    for u in seen_urls:
        try:
            h = urlparse(u).netloc.lower()
            if h:
                hosts.add(h)
        except Exception:  # noqa: BLE001, S110 — malformed URL, ignore
            pass
    authoritative_hits = hosts & _AGENT_AUTHORITATIVE_HOSTS

    if len(seen_urls) >= 2 and authoritative_hits:
        status = "validated"
        confidence = "high"
    elif seen_urls:
        status = "partial"
        confidence = "medium"
    else:
        status = "unvalidated"
        confidence = "low"

    return ValidationMetadata(
        status=status,
        sources=display_sources[:20],
        timestamp=datetime.now(UTC).isoformat(),
        confidence=confidence,
    )


def _load_asset(sb, issue: dict) -> dict:
    """Resolve the asset row for an issue via the issue_with_asset view.
    Returns trimmed asset dict (only fields useful for remediation prose) or {} if unattributed.
    """
    issue_id = issue.get("id")
    if issue_id is None:
        return {}
    resp = (
        sb.table("issue_with_asset")
        .select(
            "asset_name,asset_application_name,asset_environment,asset_exposure,"
            "asset_business_criticality,asset_data_classification,asset_compliance_tags"
        )
        .eq("id", issue_id)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows or not rows[0].get("asset_name"):
        return {}
    row = rows[0]
    return {
        "name": row.get("asset_name"),
        "application_name": row.get("asset_application_name"),
        "environment": row.get("asset_environment"),
        "exposure": row.get("asset_exposure"),
        "business_criticality": row.get("asset_business_criticality"),
        "data_classification": row.get("asset_data_classification"),
        "compliance_tags": row.get("asset_compliance_tags") or [],
    }


def _load_prompt(sb) -> dict:
    """Load the sub-agent-3 v1.4 (HYBRID pattern-based) prompt row.

    Explicitly selects v1.4 because both v1.4 (hybrid) and v2.0 (agentic)
    are active in prompt_db after migration 0048 — this function is called
    by the hybrid fallback path and needs the pattern-adaptation prompt.
    The agentic path uses a separate loader in agent_v2._load_prompt_v2.
    """
    resp = (
        sb.table("prompt_db")
        .select("agent,version,model,prompt_text,parameters")
        .eq("agent", "sub-agent-3")
        .eq("version", "v1.4")
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows:
        raise RuntimeError(
            "No sub-agent-3 v1.4 prompt row in prompt_db. "
            "Apply migration 0047_sub_agent_3_prompt_v1_4.sql."
        )
    return rows[0]


def _issue_payload(issue: dict, raw: dict | None = None) -> dict:
    """Trim the issue row to the fields Sub-Agent 3 actually uses.

    Includes upstream-derived hints:
      solution              — scanner-provided remediation text (Sub-Agent 1
                              extracts this from raw scanner output when
                              present: Snyk `remediation`, Trivy `FixedVersion`,
                              Tenable/Qualys `solution`, etc.).
      remediation_suggestion — Sub-Agent 2's LLM-generated summary derived
                              from the whole enriched context.

    And v2.4 IaC context (Nikhil review 2026-07-13):
      file_path             — the source artifact SA3 must edit (for IaC
                              findings). Extracted from raw + asset_identity.
      working_directory     — parent dir of file_path (for terraform/pip/etc.
                              commands that need `cd` first)
      resource_name         — Terraform address / Docker image ref / etc.
      scanner_type          — lexical hint: iac | sca | sast | os_pkg | other

    Sub-Agent 3's prompt v2.4 uses these to decide IaC-first vs direct-cloud
    remediation shape. See migration 0052 + iac-first-remediation memory rule.
    """
    return {
        "id": issue.get("id"),
        "source": issue.get("source"),
        "severity": issue.get("severity"),
        "priority": issue.get("priority"),
        "cve_id": issue.get("cve_id"),
        "cwe_id": issue.get("cwe_id"),
        "title": issue.get("title"),
        "description": issue.get("description"),
        "asset_identity": issue.get("asset_identity") or {},
        "package": issue.get("package"),
        "runtime_hostname": issue.get("runtime_hostname"),
        "runtime_ipv4": issue.get("runtime_ipv4"),
        "runtime_os_family": issue.get("runtime_os_family"),
        "runtime_purl": issue.get("runtime_purl"),
        # Upstream hints (v1.4)
        "solution": issue.get("solution"),
        "remediation_suggestion": issue.get("remediation_suggestion"),
        # IaC context (v2.4) — universal fields for the fixer downstream
        **_extract_iac_context(issue, raw),
    }


# ---------------------------------------------------------------------------
# IaC context extraction (v2.4)
#
# Universal signal extraction — no per-scanner branches in the shape of the
# output, only in the LOOKUP for each field. Each scanner emits the same raw
# concept (file path, resource name) under a different key; we normalize.
#
# Scanner keys we've observed in the wild:
#   Checkov     — raw.file_path, raw.resource, raw.check_id
#   Prisma      — raw.file_path, raw.resource
#   Tfsec       — raw.location.filename, raw.rule_id, raw.resource
#   Trivy misc  — raw.Target, raw.MisconfSummary.Successes / Failures / Exceptions
#   Trivy vuln  — raw.PkgName, raw.InstalledVersion, raw.FixedVersion
#   Semgrep     — raw.path, raw.check_id, raw.start.line
#   Bandit      — raw.filename, raw.test_id, raw.line_number
#   Snyk-code   — raw.locations[0].physicalLocation.artifactLocation.uri
#
# Add new scanners by extending the ordered dispatch lists below — no
# call-site changes needed.
# ---------------------------------------------------------------------------

_IAC_SOURCE_PREFIXES = (
    "checkov",
    "prisma",
    "tfsec",
    "kics",
    "terrascan",
    "conftest",
    "cfn-nag",
)
_SCA_SOURCE_PREFIXES = (
    "trivy-fs",
    "trivy-image",
    "snyk",
    "grype",
    "dependabot",
    "osv",
)
_OS_SOURCE_PREFIXES = (
    "trivy-os",
    "tenable",
    "qualys",
    "nessus",
    "wazuh",
)
_SAST_SOURCE_PREFIXES = (
    "semgrep",
    "bandit",
    "sonarqube",
    "codeql",
    "snyk-code",
)


def _extract_iac_context(issue: dict, raw: dict | None) -> dict:
    """Return {file_path, working_directory, resource_name, scanner_type}.

    Best-effort — any field may be None if the raw finding doesn't carry it.
    SA3's prompt handles missing signals gracefully (falls back to asset_identity).
    """
    raw = raw or {}
    identity = issue.get("asset_identity") or {}

    # file_path — try scanner-specific keys in priority order
    file_path = (
        raw.get("file_path")  # Checkov, Prisma
        or raw.get("FilePath")
        or raw.get("filename")  # Bandit
        or raw.get("path")  # Semgrep
        or (raw.get("location") or {}).get("filename")  # tfsec
        or (raw.get("location") or {}).get("path")
        or raw.get("Target")  # Trivy container/fs target (original casing)
        or raw.get("target")  # Trivy FS (scan-server normalizes to lowercase)
        or identity.get("file")  # canonical fallback
    )

    # Container-image scanners: raw.Target / raw.target is an IMAGE REFERENCE
    # (e.g. "vuln-lab-image:latest (ubuntu 20.04)"), NOT a file path. If left
    # in place, the prefix resolution below mangles it into a fake path like
    # "/opt/vuln-labs/cspm-lab/vuln-lab-image:latest (ubuntu 20.04)" which
    # contaminates SA-3's output. Clear it — the real Dockerfile path comes
    # from connection_registry.metadata (resolved by the orchestrator and
    # injected via execution_context).
    source_lower = (issue.get("source") or "").lower()
    if (
        "trivy-image" in source_lower
        or "snyk-container" in source_lower
        or "grype-image" in source_lower
    ):
        file_path = None

    # Translate raw-finding path to env2's real filesystem layout, if a
    # prefix is configured. Scanners often emit paths relative to their
    # scan root (Checkov shows `/main.tf` when scanning `/opt/lab/`), so
    # env2's actual path is `<prefix>/main.tf`. Without translation, SA4's
    # pre-flight file-existence check fails on the raw path.
    #
    # Two cases:
    #   a) Absolute path starting with "/" — may need prefix if it's root-relative
    #      (e.g., Checkov emits `/main.tf` meaning `<scan_root>/main.tf`)
    #   b) Relative path (no leading "/") — SCA scanners like TrivyFs emit just
    #      the filename (e.g., `requirements.txt`). Need to resolve to full path
    #      using the scanner's known scan directory from connection_registry or
    #      a source-based convention.
    if file_path and not file_path.startswith("/"):
        # Relative path — resolve to absolute using source-based scan directory.
        # SCA/SAST scanners scan /opt/vuln-labs/appsec-lab/ on env2.
        # IaC scanners scan /opt/vuln-labs/cspm-lab/ on env2.
        src_lower = (issue.get("source") or "").lower()
        if (
            "trivy-fs" in src_lower
            or "semgrep" in src_lower
            or "bandit" in src_lower
            or "snyk-appsec" in src_lower
        ):
            file_path = f"/opt/vuln-labs/appsec-lab/{file_path}"
        elif settings.fixer_env2_path_prefix:
            file_path = f"{settings.fixer_env2_path_prefix.rstrip('/')}/{file_path}"
        # else: leave as-is (relative) — SA-3 and SA-4 will handle or fail gracefully

    if file_path and file_path.startswith("/"):
        prefix = (settings.fixer_env2_path_prefix or "").rstrip("/")
        # Only prepend if the file_path isn't already inside the prefix
        # (idempotent — safe if raw_finding already emits full env2 paths).
        # Also skip if the path is already a full absolute path under a known
        # vuln-labs directory (SAST/SCA scanners emit full paths like
        # /opt/vuln-labs/appsec-lab/app.py that should NOT be prefixed).
        prefix_base = prefix.rsplit("/", 1)[0] if prefix else ""  # e.g. /opt/vuln-labs
        if (
            prefix
            and not file_path.startswith(prefix + "/")
            and not (prefix_base and file_path.startswith(prefix_base + "/"))
        ):
            file_path = prefix + file_path

    # working_directory — parent of file_path
    # Handles four cases:
    #   /main.tf              → working_directory = "/"      (root-level file)
    #   /opt/vuln/main.tf     → working_directory = "/opt/vuln"
    #   main.tf               → working_directory = "."      (no dir component)
    #   ""                    → working_directory = None
    working_directory = None
    if file_path:
        idx = file_path.rfind("/")
        if idx == 0:
            working_directory = "/"
        elif idx > 0:
            working_directory = file_path[:idx]
        else:
            working_directory = "."

    # resource_name — Terraform address / package name / image ref
    resource_name = (
        raw.get("resource")  # Checkov: "aws_s3_bucket.foo"
        or raw.get("Resource")
        or raw.get("PkgName")  # Trivy dep
        or raw.get("Repository")  # Trivy image
        or (raw.get("package") or {}).get("name")  # Snyk
        or identity.get("resource")
    )

    # scanner_type — lexical hint from source name (SA3 verifies)
    source = (issue.get("source") or "").lower()
    scanner_type: str | None = None
    if any(source.startswith(p) for p in _IAC_SOURCE_PREFIXES):
        scanner_type = "iac"
    elif any(source.startswith(p) for p in _SCA_SOURCE_PREFIXES):
        scanner_type = "sca"
    elif any(source.startswith(p) for p in _OS_SOURCE_PREFIXES):
        scanner_type = "os_pkg"
    elif any(source.startswith(p) for p in _SAST_SOURCE_PREFIXES):
        scanner_type = "sast"

    # Special case: Trivy misconfig on .tf/.yaml files is IaC even though
    # the source prefix says trivy-fs / trivy-image. If the file extension
    # points at an IaC artifact, upgrade the hint.
    if file_path and scanner_type == "sca":
        iac_extensions = (
            ".tf",
            ".tf.json",
            ".hcl",
            ".yaml",
            ".yml",
            ".json",
            ".dockerfile",
            "Dockerfile",
            ".jsonnet",
            ".libsonnet",
        )
        if any(file_path.endswith(ext) for ext in iac_extensions):
            scanner_type = "iac"

    # file_line_range — scanner-provided precise line range (checkov: [start, end],
    # semgrep: {start: {line}, end: {line}}, bandit: line_number). Lets SA-3 target
    # the exact lines instead of the whole file when it composes edits.
    file_line_range = (
        raw.get("file_line_range")  # Checkov: [117, 136]
        or (
            [raw["start"]["line"], raw["end"]["line"]]  # Semgrep
            if isinstance(raw.get("start"), dict) and isinstance(raw.get("end"), dict)
            else None
        )
        or ([raw["line_number"], raw["line_number"]] if raw.get("line_number") else None)  # Bandit
    )

    return {
        "file_path": file_path,
        "working_directory": working_directory,
        "resource_name": resource_name,
        "scanner_type": scanner_type,
        "file_line_range": file_line_range,
    }


def _pattern_payload(pattern: dict) -> dict:
    """Trim the pattern row to what Sub-Agent 3 needs."""
    return {
        "family": pattern["family"],
        "display_name": pattern["display_name"],
        "action_type": pattern["action_type"],
        "canonical_steps": pattern["canonical_steps"],
        "rollback_strategy": pattern["rollback_strategy"],
        "rollback_steps": pattern["rollback_steps"],
        "validation_tests": pattern["validation_tests"],
        "test_script_templates": pattern.get("test_script_templates") or [],
        "primary_sources": pattern["primary_sources"],
        "confidence_base": pattern["confidence_base"],
        "notes": pattern.get("notes"),
    }


def plan_remediation(
    issue: dict,
    *,
    run_id: str | None = None,
    sb: Any = None,
) -> RemediationPackage:
    """Produce a RemediationPackage for one issue.

    `issue` must be the full issues row (or issue_with_runtime row — must
    include runtime_* fields). Caller is responsible for fetching it.

    Returns a fully-populated RemediationPackage. Persistence to the
    remediation_packages table is the CALLER's responsibility (Day 5).
    """
    sb = sb or supabase_admin()
    run_id = run_id or str(uuid.uuid4())

    # Fetch raw_finding so the classifier can use raw.resource for
    # deterministic Checkov-style classification. Cheap single-row lookup.
    raw: dict | None = None
    if issue.get("raw_finding_id") is not None:
        raw_resp = (
            sb.table("raw_findings")
            .select("raw")
            .eq("id", issue["raw_finding_id"])
            .limit(1)
            .execute()
        )
        if raw_resp.data:
            raw = raw_resp.data[0].get("raw") or {}

    family = classify_finding(issue, raw=raw)
    if family == "unknown":
        raise ValueError(
            f"Issue {issue.get('id')} did not classify into a known family. "
            f"source={issue.get('source')} cwe={issue.get('cwe_id')} purl={issue.get('runtime_purl')}"
        )

    asset = _load_asset(sb, issue)

    # --- Try KB DIRECT REPLAY first (fastest path — no web search) ---
    # If the knowledge base has a verified successful recipe for this exact
    # check_id + resource_type, adapt it via a single constrained LLM call
    # and return immediately. This eliminates non-determinism for known fixes.
    # Falls through to agentic/hybrid if no candidate or adaptation fails.
    kb_replay_output = None
    kb_replay_id = None
    try:
        from ..trace import emit_trace  # noqa: PLC0415
        from .kb_replay import try_kb_replay  # noqa: PLC0415

        kb_replay_output, kb_replay_id = try_kb_replay(
            issue=issue,
            family=family,
            raw=raw,
            sb=sb,
            run_id=run_id,
            emit_fn=emit_trace,
        )
    except Exception as e:  # noqa: BLE001
        from ..trace import emit_trace  # noqa: PLC0415

        emit_trace(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"KB replay module raised: {type(e).__name__}: {str(e)[:200]} "
            "— continuing with agentic/hybrid path.",
        )

    if kb_replay_output is not None:
        # --- KB REPLAY SUCCESS — skip agentic + hybrid entirely ---
        from ..trace import emit_trace  # noqa: PLC0415

        # KB entries only exist because a prior fix succeeded. Any KB replay
        # is proven by definition — no counter check needed.
        enriched_pathways: list[RemediationPathway] = []
        for pathway in kb_replay_output.pathways:
            pathway.validation_metadata = ValidationMetadata(
                status="proven",
                sources=[f"Knowledge Base #{kb_replay_id} (proven recipe)"],
                timestamp=datetime.now(UTC).isoformat(),
                confidence="high",
            )
            # Carry forward the KB recipe's confidence score
            pathway.confidence_score = 95  # High — proven recipe
            pathway.confidence_components = {
                "source": "kb_replay",
                "kb_id": kb_replay_id,
                "reason": "Proven fix replayed from knowledge base",
            }
            enriched_pathways.append(pathway)

        recommended_idx = 0
        recommended_score = enriched_pathways[0].confidence_score or 95

        emit_trace(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            f"📚 KB replay path complete — returning package from KB #{kb_replay_id} "
            f"(confidence={recommended_score}, family={family})",
        )

        return RemediationPackage(
            issue_id=int(issue["id"]),
            family=family,
            finding=kb_replay_output.finding,
            root_cause=kb_replay_output.root_cause,
            impact=kb_replay_output.impact,
            pathways=enriched_pathways,
            recommended_pathway_index=recommended_idx,
            approval_required=_derive_approval(recommended_score, issue.get("priority")),
        )

    # --- Try the AGENTIC path first (Phase-2 default when Tavily key set) ---
    # Agent researches from live authoritative sources (AWS/CIS/NVD/CISA docs).
    # NO pattern loaded on this path — validation_metadata + confidence derive
    # from what the agent actually cited + what the verifier observed.
    # If the agent fails / hits budget cap / produces invalid output, we fall
    # through to the hybrid pattern-based path.
    agent_result = None  # tuple (LLMRemediationOutput, VerificationReport) | None
    if settings.tavily_api_key:
        from ..trace import emit_trace  # noqa: PLC0415 (defer import — circular)
        from .agent_v2 import run_agentic_planner  # noqa: PLC0415

        try:
            # Augment issue with IaC context so SA3 v2.4's prompt has file_path,
            # working_directory, resource_name, scanner_type to decide IaC-first
            # vs direct-cloud fix shape. Preserves original issue for downstream
            # persistence code.
            agent_issue = {**issue, **_extract_iac_context(issue, raw)}
            agent_result = run_agentic_planner(
                issue=agent_issue,
                asset=asset,
                family=family,
                run_id=run_id,
                sb_pub=sb,
                emit_fn=emit_trace,
            )
        except Exception as e:  # noqa: BLE001
            emit_trace(
                run_id,
                "sub-agent-3",
                "ERROR",
                f"Agentic planner raised, falling back to hybrid: "
                f"{type(e).__name__}: {str(e)[:200]}",
            )

    if agent_result is not None:
        # --- AGENT SUCCESS PATH — no pattern used. All authority from live research. ---
        llm_output, verification_report = agent_result
        enriched_pathways: list[RemediationPathway] = []
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
        # --- HYBRID FALLBACK — pattern-based (v1.4 prompt + pattern adaptation) ---
        from ..trace import emit_trace  # noqa: PLC0415

        emit_trace(
            run_id,
            "sub-agent-3",
            "MESSAGE",
            "Using hybrid pattern-based planner (v1.4)",
        )
        pattern = _load_pattern(sb, family)
        if pattern is None:
            raise RuntimeError(
                f"No row in remediation_patterns for family='{family}' AND agent path unavailable. "
                "Apply migration 0036 OR set TAVILY_API_KEY."
            )
        prompt_row = _load_prompt(sb)
        params = prompt_row.get("parameters") or {}

        payload = {
            "issue": _issue_payload(issue, raw),
            "asset": asset,
            "pattern": _pattern_payload(pattern),
        }

        # --- Knowledge Base injection (few-shot from proven fixes) ---
        kb_context = ""
        try:
            from .kb_retrieval import retrieve_examples, format_examples_for_prompt  # noqa: PLC0415

            check_id = (
                issue.get("source_vuln_id")
                or issue.get("cve_id")
                or (issue.get("source_raw") or {}).get("check_id")
            )
            kb_examples = retrieve_examples(sb, check_id=check_id, family=family)
            if kb_examples:
                kb_context = format_examples_for_prompt(kb_examples)
                emit_trace(
                    run_id,
                    "sub-agent-3",
                    "MESSAGE",
                    f"Injected {len(kb_examples)} proven fix(es) from knowledge base "
                    f"(checks: {[e.check_id for e in kb_examples]})",
                )
        except Exception:  # noqa: BLE001, S110
            pass  # KB retrieval is best-effort — never blocks planner

        base_temp = float(params.get("temperature", 0.3))
        max_tokens = int(params.get("max_tokens", 2500))
        primary_model = prompt_row["model"]
        fallback_model = params.get("fallback_model", "gpt-4o")

        llm_output = invoke_structured_with_retry(
            run_id=run_id,
            agent="sub-agent-3",
            schema=LLMRemediationOutput,
            messages=[
                SystemMessage(content=prompt_row["prompt_text"]),
                *([HumanMessage(content=kb_context)] if kb_context else []),
                HumanMessage(content=str(payload)),
            ],
            attempts=[
                (base_temp, primary_model, max_tokens),
                (0.5, primary_model, max_tokens + 500),
                (0.3, fallback_model, max_tokens + 1000),
            ],
        )

        # Attach pattern-derived validation metadata + confidence
        validation_meta = _validation_metadata_for(pattern)
        enriched_pathways = []
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

    # Pick the recommended pathway: highest confidence wins ties go to first.
    recommended_idx = max(
        range(len(enriched_pathways)),
        key=lambda i: enriched_pathways[i].confidence_score or 0,
    )
    recommended_score = enriched_pathways[recommended_idx].confidence_score or 0

    return RemediationPackage(
        issue_id=int(issue["id"]),
        family=family,
        finding=llm_output.finding,
        root_cause=llm_output.root_cause,
        impact=llm_output.impact,
        pathways=enriched_pathways,
        recommended_pathway_index=recommended_idx,
        approval_required=_derive_approval(recommended_score, issue.get("priority")),
    )


# ---------------------------------------------------------------------------
# Persistence — Day 5
# ---------------------------------------------------------------------------


def persist_package(
    pkg: RemediationPackage,
    *,
    run_id: str | None = None,
    sb: Any = None,
    initial_status: str = "awaiting_approval",
) -> int:
    """INSERT a RemediationPackage row into `remediation_packages`.

    Returns the new package row's `id`. The package's pathways are stored as
    a single jsonb blob (each pathway retains its confidence_score,
    confidence_components, validation_metadata fields).
    """
    sb = sb or supabase_admin()
    row = {
        "issue_id": pkg.issue_id,
        "family": pkg.family,
        "finding": pkg.finding,
        "root_cause": pkg.root_cause,
        "impact": pkg.impact,
        "pathways": [p.model_dump(mode="json") for p in pkg.pathways],
        "recommended_pathway_index": pkg.recommended_pathway_index,
        "approval_required": pkg.approval_required or "single_approver",
        "status": initial_status,
        "agent_run_id": run_id,
    }
    resp = sb.table("remediation_packages").insert(row).execute()
    rows = resp.data or []
    if not rows:
        raise RuntimeError("Insert into remediation_packages returned no row")
    return int(rows[0]["id"])
