from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TriggerTargets(BaseModel):
    scanners: list[str] = Field(..., min_length=1)
    scope: list[str] = []
    priority: Literal["low", "normal", "critical"] = "normal"


class TriggerEvent(BaseModel):
    """Payload sent by the UI when a user clicks 'Fetch findings'."""

    event_id: str = Field(..., min_length=1, max_length=128)
    persona: str = "security-analyst"
    action: Literal["FETCH", "ENRICH", "FULL"] = "FETCH"
    targets: TriggerTargets
    knowledge_layer_ready: bool = True


class RunCreated(BaseModel):
    run_id: str
    event_id: str
    status: str


# =============================================================================
# Image Hardening (separate feature — not linked to the scanner pipeline)
# =============================================================================
class HardeningTriggerRequest(BaseModel):
    """Payload to start an image-hardening run.

    MVP: the auto_sign toggle is a request field (UI checkbox). A persisted
    server-side default may be added later.
    """

    model_config = ConfigDict(extra="forbid")

    # Image to harden (informational for the MVP sample; the build box builds
    # the curated Dockerfile).
    source_image_ref: str = Field(..., min_length=1, max_length=512)
    # ECR repository URL to publish to (no tag).
    target_registry: str = Field(..., min_length=1, max_length=512)
    # Tag to publish under (e.g. v0.1.0). IMMUTABLE repos need a fresh tag per run.
    published_tag: str = Field(..., min_length=1, max_length=128)
    # When true, auto-dispatch the signing workflow after a successful publish.
    auto_sign: bool = False


class HardeningRunCreated(BaseModel):
    hardening_run_id: int
    status: str


class LLMNormalizedIssue(BaseModel):
    """The fields Sub-Agent 1 (LLM) is responsible for producing.

    Used as the function-call input_schema for the LLM. The LLM's output is
    guaranteed by the API to match this schema — no JSON parsing required.

    Excluded from the LLM's responsibility (added by code):
      - source_raw       (the original raw row, attached verbatim by code)
      - agent_run_id     (set from the run context)
    """

    model_config = ConfigDict(extra="forbid")

    # Open string so user-registered scanners (via the Integrations page) work.
    # Sub-Agent 1 overrides this with the actual tool slug after the LLM call,
    # so the value the LLM returns here is advisory only.
    source: str
    source_vuln_id: str
    cve_id: str | None = None
    all_cves: list[str] = []
    # cwe_id is populated by Sub-Agent 1 when the raw row references one
    # directly (common for SAST scanners like Bandit/Semgrep/Snyk-Code that
    # produce code-level weakness findings without a CVE). When set, Sub-Agent 2
    # routes enrichment through MITRE directly, skipping the NVD-per-CVE lookup.
    cwe_id: str | None = None
    title: str
    description: str | None = None
    severity: Literal["Info", "Low", "Medium", "High", "Critical"]
    cvss_score: float | None = None
    cvss_version: Literal["2.0", "3.0", "3.1", "4.0"] | None = None
    # Raw CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:H/..."). When the LLM
    # spots one in the raw row, it lifts it here verbatim — Sub-Agent 1's
    # deterministic post-LLM step then parses it to fill cvss_score +
    # cvss_version. Lifts the LLM out of doing arithmetic it does poorly.
    cvss_vector: str | None = None
    solution: str | None = None
    asset_identity: dict[str, Any] = {}
    package: dict[str, Any] | None = None
    first_detected: datetime | None = None


class LLMEnrichmentDecision(BaseModel):
    """Sub-Agent 2's per-issue LLM output — prose only.

    Used as the input_schema for the emit_enrichment_decision tool call.

    As of prompt v1.4, the LLM no longer outputs the numeric score —
    a deterministic Python formula computes derived_risk, priority, and the
    factor breakdown (stored in `components_summary`). The LLM's job is now
    to write the narrative that explains WHY the formula produced that
    score, and to write a concrete remediation suggestion.
    """

    model_config = ConfigDict(extra="forbid")

    risk_explanation: str = Field(..., min_length=10, max_length=600)
    remediation_suggestion: str = Field(..., min_length=10, max_length=600)


class RemediationStep(BaseModel):
    """One step in a remediation or rollback plan, with its citation.

    The `step` field contains rich text — action + embedded command(s) +
    'Why' rationale. Length cap is generous (8000 chars) so a single step
    can carry a full HCL/Kubernetes-manifest/multi-line-CLI block plus
    2-3 sentences of context. Steps for enterprise IaC changes (IAM
    role + policy + replication config) legitimately hit 2500-4000 chars.

    extra="ignore" — any field the LLM emits that isn't declared here is
    silently dropped, so shape drift on unknown fields never hard-fails
    the whole package. Required fields still enforced. See docstring at
    LLMRemediationOutput for the design rationale.

    _normalize_shape (mode=before) — recovers `step` field when the LLM
    emitted its contents under separate `action`/`command`/`why` keys.
    Same recovery logic used to live in agent_v2's JSON repair; moved
    here so it applies wherever the schema is used (both remediation_steps
    and rollback_plan.steps).
    """

    model_config = ConfigDict(extra="ignore")

    step: str = Field(..., min_length=10, max_length=8000)
    source: str = Field(..., min_length=3, max_length=200)
    source_url: str = Field("", max_length=500)

    @model_validator(mode="before")
    @classmethod
    def _normalize_shape(cls, data: Any) -> Any:
        """If LLM emitted action/command/why as separate keys instead of one
        `step` string, merge them. This is DATA RECOVERY — dropping the
        misplaced fields would lose the actual instruction content.
        """
        if not isinstance(data, dict):
            return data
        if data.get("step"):
            return data  # Already has step — leave alone

        # Try to reconstruct step from whatever the LLM split it into
        action = data.pop("action", None) or data.pop("Action", None)
        command = data.pop("command", None) or data.pop("Command", None)
        why = data.pop("why", None) or data.pop("Why", None) or data.pop("rationale", None)
        if not (action or command or why):
            return data  # Nothing to reconstruct from

        parts: list[str] = []
        if action:
            parts.append(str(action).rstrip())
        if command:
            cmd_lines = str(command).splitlines() or [str(command)]
            indented = "\n".join("    " + ln if ln.strip() else ln for ln in cmd_lines)
            parts.append(f"Command:\n{indented}")
        if why:
            parts.append(f"Why: {str(why).rstrip()}")
        data["step"] = "\n\n".join(parts)
        return data


class ValidationTest(BaseModel):
    """One concrete test (validation or regression) the operator can run.

    _normalize_shape (mode=before) — recovers the `command` field when the
    LLM put its contents under a `step` key (confusing this shape with a
    RemediationStep). Also recovers `name` from the first line of the step
    text. Applies wherever ValidationTest is used (top-level validation_tests
    AND rollback_plan.validation) — same code path, no location tracking.
    """

    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., min_length=5, max_length=200)
    method: str = Field(..., min_length=2, max_length=50)
    # Cap at 4000 — some validation commands are multi-line pipelines with
    # jq filters, awk, etc. Legitimate enterprise CLI checks hit 1500+ chars.
    command: str = Field(..., min_length=5, max_length=4000)
    # Cap at 1500 — expected output can be a full JSON snippet from a
    # `describe-*` call the operator eyeballs against.
    # Floor at 1 because legitimate `expected` values include HTTP status codes
    # ("403", "200"), terraform detailed-exitcodes ("2", "0"), and exit-status
    # markers ("0", "ok"). An over-strict floor forced SA3's agentic path to
    # give up and fall back to the hybrid pattern planner on every fix where
    # the LLM chose a status-code check.
    expected: str = Field(..., min_length=1, max_length=1500)
    source: str = Field(..., min_length=3, max_length=200)

    @model_validator(mode="before")
    @classmethod
    def _normalize_shape(cls, data: Any) -> Any:
        """If LLM put command text in a `step` field (a RemediationStep
        misinterpretation), extract the command from it. DATA RECOVERY —
        without this, the command would be silently dropped by extra=ignore
        and Pydantic would then fail on missing required `command`.
        """
        if not isinstance(data, dict):
            return data

        # Auto-heal LLM's habit of emitting empty strings for these
        # always-required fields. Without this, an empty `expected: ""`
        # fails Pydantic min_length=1 and drops the whole package into
        # the hybrid fallback path. Observed live 2026-07-17 on CKV_AWS_24.
        # Only rewrites empty strings — non-empty values are LEFT ALONE.
        if data.get("expected") == "":
            data["expected"] = "command exits 0"
        if data.get("source") == "":
            data["source"] = "recovered — LLM emitted empty source"
        if data.get("method") == "":
            data["method"] = "cli"

        if data.get("command"):
            return data  # Already has command — leave alone

        step_text = data.pop("step", None) or data.pop("Step", None)
        if not step_text:
            return data  # Nothing to recover from — will fail on missing command

        step_str = str(step_text)
        # Try to pull a runnable command out of the step text
        try:
            from .agents.remediation.verifier import (  # noqa: PLC0415
                _extract_commands,
            )

            commands = _extract_commands(step_str)
            command = "\n".join(commands) if commands else ""
        except Exception:  # noqa: BLE001
            command = ""

        if not command:
            # Fallback: strip common headers + take a reasonable slice
            command = step_str.replace("Command:", "").strip()

        data["command"] = command[:4000]  # respect the cap
        # If name is also missing, derive from first line of step text
        if not data.get("name"):
            first_line = step_str.split("\n", 1)[0].strip()
            data["name"] = (first_line[:200] or "validation")[:200]
        # Sensible defaults for other required fields the LLM may have
        # legitimately omitted (schema still enforces min_length below)
        data.setdefault("method", "cli")
        data.setdefault("expected", "command exits 0")
        data.setdefault("source", data.get("source_url", "recovered from step field"))
        return data


class TestScript(BaseModel):
    """A runnable script that automates one or more validation tests."""

    model_config = ConfigDict(extra="ignore")

    language: Literal["bash", "python", "powershell", "yaml", "hcl"]
    description: str = Field(..., min_length=10, max_length=300)
    # Cap at 10000 — a complete Terraform module or a boto3 smoke test
    # with error handling easily hits 4000-6000 chars.
    code: str = Field(..., min_length=20, max_length=10000)


class RollbackPlan(BaseModel):
    """Explainable rollback plan per Phase-1 doc §7.2.

    Same rigor as remediation: every rollback should justify whether it's
    technically possible, what preconditions apply, what limitations exist,
    and the reasoning behind the recommendation (not "just revert to X").
    """

    model_config = ConfigDict(extra="ignore")

    supported: bool = Field(
        ..., description="True if rollback is technically possible for this finding"
    )
    objective: str = Field(..., min_length=10, max_length=400)
    preconditions: list[str] = Field(default_factory=list, max_length=15)
    # Caps raised to match remediation_steps ceiling — rollback complexity
    # scales with remediation complexity.
    steps: list[RemediationStep] = Field(default_factory=list, max_length=20)
    validation: list[ValidationTest] = Field(default_factory=list, max_length=10)
    limitations: list[str] = Field(default_factory=list, max_length=15)
    explanation: str = Field(
        ...,
        min_length=20,
        max_length=600,
        description="WHY rollback is or isn't recommended for this specific finding",
    )
    recommended_recovery: str | None = Field(
        None,
        max_length=400,
        description=(
            "If supported=false, the alternative path (e.g. 'Restore from backup'). "
            "Accepts None because the LLM correctly omits it when supported=true; "
            "downstream code treats None/empty identically."
        ),
    )


class ValidationMetadata(BaseModel):
    """Audit trail for §7.1 — confirms the remediation was checked against
    authoritative sources, and at what tier.
    """

    model_config = ConfigDict(extra="forbid")

    status: Literal["validated", "partial", "unvalidated"]
    sources: list[str] = Field(
        default_factory=list,
        description="Citation names — e.g. ['AWS Documentation', 'NVD', 'CIS AWS 2.1.5']",
    )
    timestamp: str = Field(..., description="ISO 8601 timestamp when validation was performed")
    confidence: Literal["high", "medium", "low"]


class RemediationPathway(BaseModel):
    """One way to remediate the finding (per Phase-1 doc §7.3).

    For Phase-1, every package has exactly 1 pathway. Schema supports
    multiple pathways for the Phase-2 multi-pathway flow without further
    architectural change.
    """

    model_config = ConfigDict(extra="ignore")

    # LLM-generated
    objective: str = Field(..., min_length=10, max_length=300)
    security_coverage: Literal["complete", "partial", "interim"]
    # Caps raised (was 10/10/5) to let the agent produce as many steps as the
    # remediation actually needs — simple config fixes stay small (3-5 steps),
    # complex remediations (Log4Shell, staged rollout, multi-region) can now
    # go up to ~20. Cap remains as a hallucination guard, not a design target.
    remediation_steps: list[RemediationStep] = Field(..., min_length=1, max_length=20)
    rollback_plan: RollbackPlan
    validation_tests: list[ValidationTest] = Field(..., min_length=1, max_length=12)
    test_scripts: list[TestScript] = Field(default_factory=list, max_length=8)
    execution_strategy: str = Field(..., min_length=50, max_length=600)
    advantages: list[str] = Field(default_factory=list, max_length=8)
    # Bumped from 6 to 15 so the verifier can emit its full report (depth flags,
    # placeholder flags, low-authority flags, destructive flags, cross-source
    # summary) alongside any LLM-generated considerations.
    considerations: list[str] = Field(default_factory=list, max_length=15)

    # Code-attached (deterministic — filled by planner/confidence engine)
    validation_metadata: ValidationMetadata | None = None
    confidence_score: int | None = None
    confidence_components: dict[str, Any] | None = None


class LLMRemediationOutput(BaseModel):
    """Sub-Agent 3's LLM output. Caller attaches issue_id, family,
    validation_metadata, confidence, approval_required, recommended_pathway_index
    AFTER the call.

    ─── Design: why LLM-facing sub-schemas use extra="ignore" ───
    Every sub-schema below (RemediationStep, ValidationTest, TestScript,
    RollbackPlan, RemediationPathway, LLMRemediationOutput itself) uses
    extra="ignore" instead of extra="forbid".

    Reason: LLMs periodically emit fields the schema doesn't declare —
    the wrong-shape drift is unavoidable at scale. With extra="forbid",
    any single unexpected field hard-fails the entire package parse and
    the pipeline falls back to the hybrid CLI-only planner (bad). With
    extra="ignore", the offending field is silently dropped and the rest
    of the (well-formed) package parses cleanly.

    Required fields still enforced — if the LLM drops something we
    actually need, the parse still fails visibly. But it fails on missing
    REQUIRED data, not on gratuitous extras. Genuine data errors surface;
    LLM whims don't.

    This is deliberately more permissive than the pattern for
    LLMNormalizedIssue / LLMEnrichmentDecision (which stay extra="forbid"
    — they operate on smaller, tighter, less-ambiguous schemas where
    strict-mode drift is rare and revealing).
    """

    model_config = ConfigDict(extra="ignore")

    finding: str = Field(..., min_length=20, max_length=400)
    root_cause: str = Field(..., min_length=20, max_length=400)
    impact: str = Field(..., min_length=20, max_length=400)
    pathways: list[RemediationPathway] = Field(..., min_length=1, max_length=3)


class RemediationPackage(BaseModel):
    """The full persisted artifact — Phase-1 Working Model §5 (v1.1 shape).

    Top-level header (Finding / Root Cause / Impact) is shared across
    pathways. Each pathway holds its own remediation/rollback/tests/confidence.
    `recommended_pathway_index` points at the pathway the planner suggests.
    Approval is package-level (one decision covers the chosen pathway).
    """

    model_config = ConfigDict(extra="forbid")

    # Caller-attached (deterministic)
    issue_id: int
    family: str

    # LLM-generated header (shared across pathways)
    finding: str
    root_cause: str
    impact: str

    # 1+ remediation pathways (Phase-1 always = 1)
    pathways: list[RemediationPathway]

    # Code-attached
    recommended_pathway_index: int = 0
    approval_required: Literal["auto", "single_approver", "multi_stage"] | None = None


class MasterPlanStep(BaseModel):
    """One step in the Master Agent's plan."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["FETCH", "ENRICH"]
    tool: str | None = None  # required when kind == "FETCH"
    notes: str | None = None  # 1-line reasoning


class MasterPlan(BaseModel):
    """Master Agent's LLM-produced plan: ordered steps for the run."""

    model_config = ConfigDict(extra="forbid")

    plan_summary: str = Field(..., min_length=10, max_length=500)
    steps: list[MasterPlanStep] = Field(..., min_length=1)


# =============================================================================
# Ticketing models
# =============================================================================


class CreateTicketRequest(BaseModel):
    """Request body for POST /admin/tickets/create."""

    model_config = ConfigDict(extra="forbid")

    remediation_package_id: int
    # Optional: specify which connection_registry tool to use. Defaults to 'servicenow-ticket'.
    connection_tool: str | None = None
    # Override auto-generated title/description if desired
    title_override: str | None = Field(None, max_length=160)
    description_override: str | None = Field(None, max_length=8000)
    # Additional ServiceNow fields (e.g. assignment_group, cmdb_ci, u_*)
    extra_fields: dict[str, Any] = Field(default_factory=dict)


class TicketResponse(BaseModel):
    """Response shape for a single ticket."""

    model_config = ConfigDict(extra="ignore")

    id: int
    remediation_package_id: int
    connection_tool: str
    provider: str
    external_ticket_id: str | None = None
    external_ticket_url: str | None = None
    status: str
    error_message: str | None = None
    title: str
    priority: str | None = None
    labels: list[str] = []
    created_at: str | None = None
    updated_at: str | None = None
    synced_at: str | None = None


class TicketingConnectionCreate(BaseModel):
    """Request body for registering a new ticketing connection."""

    model_config = ConfigDict(extra="forbid")

    provider: Literal["servicenow", "jira", "azure_devops", "monday", "slack", "teams", "webhook"]
    display_name: str = Field(..., min_length=1, max_length=200)
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class TicketingConnectionResponse(BaseModel):
    """Response shape for a ticketing connection."""

    model_config = ConfigDict(extra="ignore")

    id: int
    provider: str
    display_name: str
    enabled: bool
    created_at: str | None = None
    updated_at: str | None = None


class TicketingConnectionUpdate(BaseModel):
    """PATCH body for updating a ticketing connection."""

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = None
    enabled: bool | None = None
    config: dict[str, Any] | None = None
