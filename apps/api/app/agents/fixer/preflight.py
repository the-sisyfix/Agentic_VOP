"""Sub-Agent 4 pre-flight package rewriter.

Sits between pre_flight_check() and backup() in the SA4 lifecycle. Snapshots
env2's actual state (IAM identity, terraform resources, target-resource state)
then asks an LLM to review the package and rewrite any steps that will fail
given the observed reality.

The classic scenario this catches (surfaced by Nikhil's Kiro analysis, 2026-07-15):
SA3 emits `sse_algorithm = "aws:kms"` for S3 encryption, which is technically
the more secure choice — but env2's IAM role has no `kms:CreateKey` permission,
so `terraform apply` fails at runtime. Pre-flight sees the IAM policy list,
notices no KMS access, and rewrites the step to `sse_algorithm = "AES256"`
(zero permissions needed). SA4 then executes the rewritten package and
Checkov's re-scan passes.

Design principles:
  * FAIL-OPEN. If snapshot or LLM errors, execute the ORIGINAL package.
    Rewriter failures MUST NOT block fixes — this is a review layer, not a
    critical path.
  * MODIFY ONLY. The rewriter can update remediation_steps in place but
    cannot add, delete, or reorder them. Preserves the audit trail (package
    still has N steps, each with its rewrite reason stored inline).
  * HIGH CONFIDENCE ONLY. LLM emits confidence per rewrite; only 'high'
    rewrites are applied. Medium/low are logged as advisory so operators can
    review them but don't affect execution.
  * SAFETY LAYER. Every rewrite still passes through validate_command();
    any rewrite that fails safety is dropped, original step preserved.
  * TRUTHFUL TRACE. Every applied rewrite gets a MESSAGE line with
    (step_index, reason, first 200 chars of before). Unfixable concerns
    become WARNING lines so operators know the demo's honest limits.
"""

from __future__ import annotations

import copy as _copy
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..llm import invoke_structured_with_retry
from .config import FixerConfig
from .models import FixContext
from .safety import validate_command
from .tools.remote_exec import RemoteExecutor


# ─── Benchmark-only model override for the preflight rewriter LLM ─────────
# The SA-4 preflight path has exactly one LLM call. Production hardcodes
# gpt-4o. The benchmark pipeline flips this to e.g. claude-sonnet-4-6 when
# measuring the Claude stack end-to-end. When this list contains None (the
# default), behavior is identical to pre-override production code.
#
# Mutate as `preflight._PREFLIGHT_MODEL_OVERRIDE[0] = "claude-sonnet-4-6"`
# before calling run_fixer(), then reset to None in a try/finally.
_PREFLIGHT_MODEL_OVERRIDE: list[str | None] = [None]


# ============================================================================
# Hallucination guard for no-op rewrites
# ============================================================================
# Matches Terraform HCL resource addresses (e.g. `aws_s3_bucket.vulnerable_bucket`,
# `aws_security_group_rule.restrict_ssh_ingress`). Datasource addresses
# (data.aws_vpc.default) are matched by the same pattern via the `data.` alt.
# Not a strict HCL parser — good enough to spot address citations in prose.
_HCL_ADDRESS_RE = re.compile(r"\b((?:data\.)?[a-z][a-z0-9_]*\.[A-Za-z][A-Za-z0-9_-]*)")

# Prose signals that the rewriter is claiming a no-op due to state duplication.
# If any of these appear in either the `reason` OR the `new_step`, the rewrite
# is a "duplicate resource" no-op and its claimed addresses must be verifiable.
_NOOP_CLAIM_SIGNALS = (
    "already in state",
    "already present",
    "duplicate resource",
    "nothing to add",
    "no-op",
    "no edit needed",
    "no change",
    "already declared",
    "already exists",
)


def _verify_no_op_claim(
    reason: str,
    new_step: str,
    terraform_resources: list[str],
) -> tuple[bool, str]:
    """Sanity-check a rewriter's 'duplicate resource / already in state' claim
    against the actual snapshot. Returns (ok, diagnostic).

    The rewriter LLM sometimes hallucinates that a resource is 'already in
    state' when the snapshot's `terraform_resources` list clearly doesn't
    contain it — especially after a state reset when the snapshot only has
    the baseline resources. Applying such rewrites silently no-ops the fix
    (the step becomes `echo ...`) and the scanner re-scan then reports the
    vuln is still open.

    TWO failure modes this catches:
      1. LLM cites an address NOT in terraform_resources at all (pure hallucination).
      2. LLM cites a BASE resource (aws_s3_bucket.X, aws_security_group.Y)
         that always exists, and claims "adding it would duplicate" — when
         the step actually adds a COMPANION resource (aws_s3_bucket_versioning.X,
         aws_s3_bucket_public_access_block.X). The LLM confuses a Terraform
         reference INSIDE the HCL block (bucket = aws_s3_bucket.X.id) with
         the resource declaration itself.

    Logic:
      1. If neither the reason nor new_step contains no-op-claim language,
         this is not a duplicate-resource rewrite — pass through.
      2. If it IS a no-op claim, extract every HCL address (aws_X.Y form)
         from the reason and new_step text.
      3. Every extracted address MUST appear literally in terraform_resources.
         If ANY doesn't, the claim is unverifiable → reject as hallucination.
      4. At least one cited address must be a COMPANION resource — not just
         the base resources that always exist in state. If every cited address
         is a base resource (bucket, SG, VPC data source), the LLM likely
         confused an HCL reference with the resource being created → reject.

    Returns (True, "") when the rewrite is safe to apply, or
    (False, "<diagnostic>") when it should be rejected.
    """
    combined = f"{reason}\n{new_step}".lower()
    if not any(sig in combined for sig in _NOOP_CLAIM_SIGNALS):
        # Not a no-op claim (e.g. it's a KMS→AES256 rewrite). Nothing to verify.
        return True, ""

    # Extract every HCL address the LLM cited. Search both fields — the reason
    # is where the LLM usually names the resource; the new_step often echoes it.
    addrs_in_reason = set(_HCL_ADDRESS_RE.findall(reason))
    addrs_in_step = set(_HCL_ADDRESS_RE.findall(new_step))
    cited_addresses = addrs_in_reason | addrs_in_step

    if not cited_addresses:
        # LLM claimed no-op but didn't name any specific address. That's
        # itself a red flag — refuse without a concrete citation.
        return False, "no-op claim cites no specific HCL address"

    resources_set = set(terraform_resources)
    missing = [a for a in cited_addresses if a not in resources_set]
    if missing:
        return False, (
            f"no-op claim cites address(es) not in terraform_resources: "
            f"{sorted(missing)} (snapshot has: {sorted(resources_set) or '[]'})"
        )

    # Guard against the "parent confusion" hallucination: the LLM sees
    # `bucket = aws_s3_bucket.vulnerable_bucket.id` INSIDE the step's HCL
    # and concludes that the step is creating aws_s3_bucket.vulnerable_bucket
    # (which obviously exists). But the step is actually creating a COMPANION
    # resource (aws_s3_bucket_versioning, aws_s3_bucket_logging, etc.).
    #
    # A legitimate no-op claim should cite the COMPANION resource address
    # (e.g. aws_s3_bucket_versioning.vulnerable_bucket_versioning) — not just
    # the base resource. If all cited addresses are base resources that
    # ALWAYS exist in state (the immutable infrastructure), the claim is
    # almost certainly a false positive.
    #
    # Base resources = the ones that exist in a CLEAN state (before any fix).
    # These are typically: the bucket itself, the SG itself, data sources.
    _BASE_RESOURCE_TYPES = (
        "aws_s3_bucket.",
        "aws_security_group.",
        "data.",
    )
    non_base_cited = [
        a
        for a in cited_addresses
        if not any(a.startswith(prefix) for prefix in _BASE_RESOURCE_TYPES)
    ]
    if not non_base_cited:
        # Every cited address is a base resource — the LLM confused a
        # Terraform reference with the resource being created.
        return False, (
            f"no-op claim cites only base resource(s) {sorted(cited_addresses)} "
            f"that always exist in state. The step likely creates a COMPANION "
            f"resource (versioning, logging, encryption, etc.) — not the base "
            f"resource itself. Rejecting as parent-confusion hallucination."
        )

    return True, ""


# ============================================================================
# Env state snapshot — what we know about env2 before rewriting
# ============================================================================
@dataclass
class EnvSnapshot:
    """Compact snapshot of env2 state at the moment pre-flight ran.

    Everything here comes from SSM calls made in `snapshot_env2`. Fields are
    strings (not parsed dicts) because the LLM consumes them as prose — it
    reasons better from raw AWS CLI output than from re-serialized JSON.

    Capability probes vs IAM introspection:
      env2's assumed role can't call iam:ListAttachedRolePolicies on itself
      (least-privilege posture — good security, hostile to introspection).
      So we probe capabilities DIRECTLY instead: `aws kms list-keys` tells us
      whether KMS is reachable at all. AccessDenied on such a probe is a
      high-confidence signal the corresponding remediation shape will fail.
    """

    caller_identity: str = ""
    iam_summary: str = ""
    terraform_resources: list[str] = field(default_factory=list)
    target_resource_state: str = ""
    # Capability probes — each is either "OK: <preview>" or "DENIED: <reason>"
    # or "" (probe didn't run). Directly evidences what env2 CAN and CAN'T do,
    # independent of whether IAM introspection succeeded.
    capabilities: dict[str, str] = field(default_factory=dict)
    snapshot_errors: list[str] = field(default_factory=list)

    def to_llm_context(self) -> str:
        """Serialize into a compact prose block for the LLM prompt."""
        parts = ["==== env2 STATE SNAPSHOT ===="]
        if self.caller_identity:
            parts.append(f"IAM caller identity:\n{self.caller_identity}")
        if self.iam_summary:
            parts.append(f"\nIAM permissions summary:\n{self.iam_summary}")
        if self.capabilities:
            parts.append(
                "\nCapability probes (direct AccessDenied signal — trust these over IAM introspection):\n"
                + "\n".join(f"  - {k}: {v}" for k, v in self.capabilities.items())
            )
        if self.terraform_resources:
            parts.append(
                "\nTerraform state resources (HCL addresses already present — "
                "adding a resource with any of these addresses = 'Duplicate resource' error):\n"
                + "\n".join(f"  - {r}" for r in self.terraform_resources)
            )
        if self.target_resource_state:
            parts.append(f"\nTarget resource current state:\n{self.target_resource_state}")
        if self.snapshot_errors:
            parts.append(
                "\nSnapshot errors (info the reviewer could not fetch):\n"
                + "\n".join(f"  - {e}" for e in self.snapshot_errors)
            )
        return "\n".join(parts)


def snapshot_env2(executor: RemoteExecutor, ctx: FixContext, emit_fn: Any) -> EnvSnapshot:
    """Query env2 for its current state via SSM. Best-effort — individual
    failures append to `snapshot_errors` but never abort the snapshot.

    Four calls in sequence (each ~1s):
      1. `aws sts get-caller-identity`      → who is env2?
      2. `aws iam list-attached-role-policies` → what policies attached?
      3. `terraform state list`             → what resources exist?
      4. `terraform state show <resource>`  → target resource details
         (skipped when resource_name not in ctx)
    """
    snap = EnvSnapshot()

    # 1. AWS caller identity — quick, always works if AWS CLI is functional
    try:
        r = executor.run_command(
            "aws sts get-caller-identity --output json 2>&1",
            timeout_s=30,
        )
        if r.exit_code == 0:
            snap.caller_identity = r.stdout.strip()[:500]
        else:
            snap.snapshot_errors.append(f"aws sts failed: {(r.stderr or r.stdout)[:200]}")
    except Exception as e:  # noqa: BLE001
        snap.snapshot_errors.append(f"aws sts crashed: {type(e).__name__}: {str(e)[:200]}")

    # 2. IAM permissions summary — extract role name from caller-identity ARN,
    #    then list its attached managed policies. Coarse-grained (names, not
    #    JSON), but enough for the LLM to reason about KMS/S3/EC2 access.
    role_name = ""
    if "assumed-role/" in snap.caller_identity:
        after = snap.caller_identity.split("assumed-role/", 1)[1]
        role_name = after.split("/", 1)[0].split('"', 1)[0].strip()

    if role_name:
        try:
            r = executor.run_command(
                f"aws iam list-attached-role-policies --role-name '{role_name}' "
                "--query 'AttachedPolicies[].PolicyName' --output json 2>&1",
                timeout_s=30,
            )
            if r.exit_code == 0:
                snap.iam_summary = (
                    f"Role: {role_name}\nAttached managed policies: {r.stdout.strip()[:500]}"
                )
            else:
                snap.snapshot_errors.append(
                    f"iam list-attached-role-policies failed: {(r.stderr or r.stdout)[:200]}"
                )
        except Exception as e:  # noqa: BLE001
            snap.snapshot_errors.append(
                f"iam list-attached-role-policies crashed: {type(e).__name__}: {str(e)[:200]}"
            )
    else:
        snap.snapshot_errors.append(
            "Could not extract role name from caller identity — IAM lookup skipped"
        )

    # 3. Terraform state list — what resources exist in the target module
    wd = ctx.working_directory or "."
    try:
        r = executor.run_command(
            "terraform state list 2>&1",
            working_directory=wd,
            timeout_s=60,
        )
        if r.exit_code == 0:
            snap.terraform_resources = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()][
                :100
            ]
        else:
            snap.snapshot_errors.append(
                f"terraform state list failed: {(r.stderr or r.stdout)[:200]}"
            )
    except Exception as e:  # noqa: BLE001
        snap.snapshot_errors.append(
            f"terraform state list crashed: {type(e).__name__}: {str(e)[:200]}"
        )

    # 4. Capability probes — direct signal of what env2 CAN vs CAN'T do,
    # independent of whether IAM introspection succeeded. Each probe is a
    # cheap read-only call: success means the capability exists; AccessDenied
    # means the corresponding fix shape will fail at apply time.
    _CAPABILITY_PROBES: list[tuple[str, str]] = [
        # KMS — the specific case that killed CKV_AWS_145. If ListKeys is
        # denied, env2 has no KMS access at all, so any `sse_algorithm =
        # "aws:kms"` step is guaranteed to fail. AES256 needs nothing.
        ("kms_list", "aws kms list-keys --max-items 1 --output json 2>&1"),
    ]
    for probe_key, probe_cmd in _CAPABILITY_PROBES:
        try:
            r = executor.run_command(probe_cmd, timeout_s=30)
            if r.exit_code == 0:
                snap.capabilities[probe_key] = f"OK ({(r.stdout or '').strip()[:120]})"
            else:
                stderr_preview = (r.stderr or r.stdout or "").strip()[:200]
                snap.capabilities[probe_key] = f"DENIED ({stderr_preview})"
        except Exception as e:  # noqa: BLE001
            snap.capabilities[probe_key] = f"PROBE_CRASHED ({type(e).__name__}: {str(e)[:120]})"

    # 5. Target resource current state (if we know what it is)
    if ctx.resource_name:
        try:
            r = executor.run_command(
                f"terraform state show '{ctx.resource_name}' 2>&1",
                working_directory=wd,
                timeout_s=60,
            )
            if r.exit_code == 0:
                snap.target_resource_state = r.stdout.strip()[:3000]
            else:
                snap.snapshot_errors.append(
                    f"terraform state show {ctx.resource_name} failed: "
                    f"{(r.stderr or r.stdout)[:200]}"
                )
        except Exception as e:  # noqa: BLE001
            snap.snapshot_errors.append(
                f"terraform state show crashed: {type(e).__name__}: {str(e)[:200]}"
            )

    cap_summary = (
        ", ".join(
            f"{k}={'OK' if v.startswith('OK') else 'DENIED' if v.startswith('DENIED') else '?'}"
            for k, v in snap.capabilities.items()
        )
        or "none"
    )
    emit_fn(
        ctx.agent_run_id,
        "sub-agent-4",
        "MESSAGE",
        f"🔬 Snapshot complete: identity={'yes' if snap.caller_identity else 'no'}, "
        f"iam={'yes' if snap.iam_summary else 'no'}, "
        f"tf_resources={len(snap.terraform_resources)}, "
        f"target_state={'yes' if snap.target_resource_state else 'no'}, "
        f"capabilities=[{cap_summary}], "
        f"errors={len(snap.snapshot_errors)}",
    )
    return snap


# ============================================================================
# LLM output schema — Pydantic (used by invoke_structured_with_retry)
# ============================================================================
class PreflightRewrite(BaseModel):
    """One proposed rewrite to a single remediation_steps entry."""

    model_config = ConfigDict(extra="ignore")

    step_index: int = Field(..., ge=0, description="0-based index into remediation_steps")
    reason: str = Field(
        ...,
        min_length=10,
        max_length=1500,
        description=(
            "Concrete evidence-based explanation citing the env snapshot "
            "(e.g. 'attached policies list has no AmazonS3KMSAccess, and step "
            "uses sse_algorithm=aws:kms which requires kms:CreateKey')."
        ),
    )
    confidence: Literal["high", "medium", "low"] = Field(
        ...,
        description=(
            "high = snapshot has direct evidence the original step will fail. "
            "medium = strong suspicion but not certain. low = guessing. "
            "Only 'high' rewrites are applied to the executed package."
        ),
    )
    original_step_preview: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="First 200 chars of the step being rewritten, for audit trail",
    )
    new_step: str = Field(
        ...,
        min_length=10,
        max_length=8000,
        description=(
            "Full replacement value for remediation_steps[step_index].step. "
            "Must preserve the same Action + Command: + Why: sections. HCL "
            "edits must stay wrapped in `cat >> file << 'EOF' ... EOF` heredoc."
        ),
    )


class PreflightRewritePlan(BaseModel):
    """LLM output: the full set of rewrites + advisories for this package."""

    model_config = ConfigDict(extra="ignore")

    rewrites: list[PreflightRewrite] = Field(
        default_factory=list,
        max_length=10,
        description=(
            "Steps to modify. Empty list when the package is already "
            "env-appropriate (encouraged — do not invent rewrites)."
        ),
    )
    unfixable_concerns: list[str] = Field(
        default_factory=list,
        max_length=5,
        description=(
            "Issues you spotted but cannot fix by rewriting a single step "
            "(e.g. 'CKV2_AWS_5 requires the SG be attached to an EC2 instance, "
            "but no EC2 instance exists in terraform state to attach it to'). "
            "Concrete blockers only, not general commentary."
        ),
    )


# ============================================================================
# LLM prompt
# ============================================================================
_SYSTEM_PROMPT = """You are the pre-flight reviewer for Sub-Agent 4 (the Fixer).

You review remediation packages BEFORE they execute against real infrastructure.
Your job: catch steps that will fail given what we know about the target
environment, and rewrite them to shapes that will actually work.

You have three signals to work from:
  1. The finding being remediated
  2. The full remediation package (remediation_steps + their commands)
  3. An env-state snapshot: IAM identity + attached policies, terraform state
     resources, and current state of the target resource

Emit exactly one tool call to `PreflightRewritePlan`. Do not emit prose.

RULES for `rewrites`:
  * You can ONLY modify existing steps. You cannot add, delete, or reorder
    steps. This preserves the audit trail — the package still has N steps,
    each carrying its rewrite reason.
  * Only mark `confidence = "high"` when you have CONCRETE EVIDENCE from
    the snapshot. Speculation is "medium", guessing is "low".
  * The `new_step` MUST preserve the same shape as the original — same
    Action + Command: + Why: sections. Only change what needs changing.
  * HCL edits MUST stay in `cat >> file << 'EOF' ... EOF` heredoc form.
    Never emit bare HCL as Command block content.
  * Cite the SPECIFIC snapshot evidence in your `reason` field.

TWO HIGH-VALUE PATTERNS to always check for (both are HIGH-CONFIDENCE if
snapshot evidence is present):

  Pattern 1 — KMS lockdown (fires on CKV_AWS_145 and similar):
    IF `capabilities.kms_list` starts with "DENIED"
    AND any step contains `sse_algorithm = "aws:kms"` or references a KMS
        key / kms:CreateKey / kms:GenerateDataKey / `--kms-key-id`
    THEN rewrite the step to use `sse_algorithm = "AES256"` (needs zero
    permissions) and drop any KMS-key-discovery preludes. Cite the DENIED
    kms_list probe in your reason.

  Pattern 2 — Duplicate resource (fires when a prior fix already added the
                                  same resource):
    IF `terraform_resources` already contains the HCL address the step is
        trying to add (e.g. step does `cat >> main.tf << EOF resource
        "aws_s3_bucket_public_access_block" "vulnerable_bucket" {...} EOF`
        AND the resources list already has
        `aws_s3_bucket_public_access_block.vulnerable_bucket`)
    THEN rewrite to a no-op step in the FULL PROPER SHAPE (never bare echo).
    The `new_step` must still contain Action + Command: + Why: sections so
    the executor's parser accepts it. Correct no-op shape:

        Skip — resource already present in terraform state.

        Command:
            echo "aws_s3_bucket_public_access_block.vulnerable_bucket already in state — nothing to add"

        Why: Terraform state already contains
        aws_s3_bucket_public_access_block.vulnerable_bucket. Adding it again
        would fail with 'Duplicate resource'; the desired end-state is
        already declared, so this step is a no-op.

    Alternatively, add to `unfixable_concerns` if you can't determine a safe
    rewrite. Do NOT let a duplicate-resource step reach terraform plan — it
    hard-fails and rolls back the entire fix.

Do not invent rewrites when the package looks correct. Emit
`rewrites=[]` — that IS the right answer when the snapshot doesn't reveal a
problem.

RULES for `unfixable_concerns`:
  * Use for issues you SPOT but cannot fix by rewriting a single step.
  * Do NOT put general commentary here. Only concrete blockers with
    specific evidence.

If the package looks correct given the snapshot: emit rewrites=[] and
unfixable_concerns=[]. That is a valid, encouraged answer. Do not invent
rewrites to justify running.
"""


def _build_llm_messages(pathway: dict, snapshot: EnvSnapshot, issue: dict) -> list:
    """Assemble the LLM messages: system prompt + user context payload."""
    from langchain_core.messages import HumanMessage, SystemMessage

    steps = pathway.get("remediation_steps") or []
    steps_prose = "\n\n".join(
        f"[step_index={i}]\n{(s.get('step') or '')[:1500]}" for i, s in enumerate(steps)
    )

    finding_pairs = {
        "id": issue.get("id"),
        "source_vuln_id": issue.get("source_vuln_id"),
        "title": issue.get("title"),
        "severity": issue.get("severity"),
        "resource": (issue.get("asset_identity") or {}).get("resource"),
    }
    finding_summary = "\n".join(f"  - {k}: {str(v)[:200]}" for k, v in finding_pairs.items() if v)

    user_text = (
        f"FINDING:\n{finding_summary}\n\n"
        f"{snapshot.to_llm_context()}\n\n"
        f"REMEDIATION_STEPS (indexed 0..{max(len(steps) - 1, 0)}):\n\n{steps_prose}\n"
    )
    return [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=user_text)]


# ============================================================================
# Public entry point — orchestrator calls this between pre_flight and backup
# ============================================================================
def run_preflight_rewrite(
    ctx: FixContext,
    emit_fn: Any,
    *,
    config: FixerConfig | None = None,
) -> tuple[dict, list[str]]:
    """Snapshot env2, invoke the rewriter LLM, apply high-confidence rewrites
    to a copy of the pathway. Returns (rewritten_pathway, rewrite_log).

    Fail-open — on ANY error (snapshot crash, LLM error, safety-layer rejects
    every rewrite), returns the ORIGINAL pathway unchanged with an empty
    rewrite_log. Never raises. This is a review layer, not a critical path;
    a broken rewriter must not block fixes.

    Args:
        ctx: the FixContext for this run (holds pathway, issue, target info)
        emit_fn: trace emitter (real or demo) — orchestrator's choice
        config: FixerConfig for the RemoteExecutor; defaults if omitted

    Returns:
        (pathway_dict, log_lines) — pathway is either the mutated copy
        (if any rewrite was applied) or the exact original object.
    """
    original_pathway = ctx.pathway
    if not original_pathway or not original_pathway.get("remediation_steps"):
        return original_pathway, []

    non_iac_scanner_types = {"container_image", "os_pkg", "os", "image"}
    if ctx.scanner_type in non_iac_scanner_types:
        return original_pathway, []

    cfg = config or FixerConfig()
    executor = RemoteExecutor(
        instance_id=ctx.target_instance_id,
        region=ctx.aws_region,
        config=cfg,
        emit_fn=emit_fn,
        run_id=ctx.agent_run_id,
    )

    # 1. Snapshot env2 (best-effort, fail-open)
    try:
        snapshot = snapshot_env2(executor, ctx, emit_fn)
    except Exception as e:  # noqa: BLE001
        emit_fn(
            ctx.agent_run_id,
            "sub-agent-4",
            "MESSAGE",
            f"⚠ Pre-flight snapshot crashed ({type(e).__name__}: {str(e)[:200]}) — "
            "executing ORIGINAL package (fail-open).",
        )
        return original_pathway, []

    # 2. Invoke the rewriter LLM (single attempt, fail-open)
    try:
        messages = _build_llm_messages(original_pathway, snapshot, ctx.issue)
        plan: PreflightRewritePlan = invoke_structured_with_retry(
            run_id=ctx.agent_run_id,
            agent="sub-agent-4",
            schema=PreflightRewritePlan,
            messages=messages,
            attempts=[(0.1, _PREFLIGHT_MODEL_OVERRIDE[0] or "gpt-4o", 3000)],
            emit_fn=emit_fn,
        )
    except Exception as e:  # noqa: BLE001
        emit_fn(
            ctx.agent_run_id,
            "sub-agent-4",
            "MESSAGE",
            f"⚠ Pre-flight rewriter LLM failed ({type(e).__name__}: {str(e)[:200]}) — "
            "executing ORIGINAL package (fail-open).",
        )
        return original_pathway, []

    # 3. Report plan to the trace (before applying anything)
    high_conf = [r for r in plan.rewrites if r.confidence == "high"]
    advisory = [r for r in plan.rewrites if r.confidence != "high"]
    emit_fn(
        ctx.agent_run_id,
        "sub-agent-4",
        "MESSAGE",
        f"🧠 Rewriter proposed {len(plan.rewrites)} rewrite(s): "
        f"{len(high_conf)} high-confidence (will apply), "
        f"{len(advisory)} advisory (logged only)",
    )

    for _ in advisory:
        pass  # advisory rewrites not surfaced to client trace

    for concern in plan.unfixable_concerns:
        emit_fn(
            ctx.agent_run_id,
            "sub-agent-4",
            "MESSAGE",
            f"   ⚠ Unfixable concern: {concern[:400]}",
        )

    if not high_conf:
        return original_pathway, []

    # 4. Apply high-confidence rewrites (each still hits safety layer)
    new_pathway = _copy.deepcopy(original_pathway)
    steps = new_pathway.get("remediation_steps") or []
    log: list[str] = []
    applied = 0
    skipped = 0

    for r in sorted(high_conf, key=lambda x: x.step_index):
        if r.step_index < 0 or r.step_index >= len(steps):
            skipped += 1
            continue

        # Hallucination guard — reject "already in state" no-op rewrites when
        # the cited HCL address isn't actually in the snapshot's
        # terraform_resources list. Without this, the LLM occasionally
        # pattern-matches on the Pattern 2 example in its prompt and invents
        # duplicate-resource concerns that don't exist (observed at
        # 2026-07-15 15:53 after a state reset). Silent no-op'ing a real
        # remediation step is worse than skipping the rewrite — the step
        # never runs, the scanner re-scan still fails, and rollback fires.
        ok, diagnostic = _verify_no_op_claim(r.reason, r.new_step, snapshot.terraform_resources)
        if not ok:
            emit_fn(
                ctx.agent_run_id,
                "sub-agent-4",
                "MESSAGE",
                f"   🛑 Rewrite step_index={r.step_index} REJECTED — "
                f"hallucinated no-op ({diagnostic}). Keeping original step.",
            )
            skipped += 1
            continue

        safety = validate_command(r.new_step, ctx.working_directory)
        if not safety.allowed:
            emit_fn(
                ctx.agent_run_id,
                "sub-agent-4",
                "MESSAGE",
                f"   🛑 Rewrite step_index={r.step_index} REJECTED by safety "
                f"({safety.matched_pattern}: {(safety.reason or '')[:200]}) — "
                "keeping original.",
            )
            skipped += 1
            continue

        old_preview = (steps[r.step_index].get("step") or "")[:200]
        steps[r.step_index]["step"] = r.new_step
        steps[r.step_index]["_preflight_rewrite"] = {
            "reason": r.reason,
            "original_preview": old_preview,
        }
        emit_fn(
            ctx.agent_run_id,
            "sub-agent-4",
            "MESSAGE",
            f"   ✓ Rewrote step {r.step_index}: {r.reason[:250]}",
        )
        log.append(f"step_{r.step_index}: {r.reason}")
        applied += 1

    emit_fn(
        ctx.agent_run_id,
        "sub-agent-4",
        "MESSAGE",
        f"🧠 Pre-flight complete: {applied} applied, {skipped} skipped. Proceeding to execute.",
    )
    return new_pathway, log
