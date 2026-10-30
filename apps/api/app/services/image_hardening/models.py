"""Image Hardening typed models.

Reuses the fixer's family-agnostic result models (StepResult, ValidationResult,
RollbackResult, PreFlightResult, BackupResult) by IMPORT — not by copy — so the
execution-result shapes stay identical to the proven engine. Only the
hardening-specific context + aggregate outcome are defined here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Reuse the fixer engine's result models as a library (isolation guarantee #2:
# imported read-only, never edited).
from app.agents.fixer.models import (  # noqa: F401  (re-exported for convenience)
    BackupResult,
    PreFlightResult,
    RollbackResult,
    StepResult,
    ValidationResult,
)


def utcnow() -> datetime:
    """UTC-aware now(). Mirrors fixer.models.utcnow for consistent timestamps."""
    return datetime.now(UTC)


# Lifecycle status values — MUST match the CHECK constraint in
# supabase/migrations/0044_hardening_runs.sql.
HardeningStatus = Literal[
    "pending",
    "preflight",
    "building",
    "scanning",
    "publishing",
    "signing",
    "success",
    "failed",
    "rolled_back",
]


class HardenContext(BaseModel):
    """Everything a hardening run needs to execute. The analog of the fixer's
    FixContext, but with NO scanner-finding fields (no issue, no package, no
    pathway) — hardening is not a response to a finding.
    """

    model_config = ConfigDict(extra="forbid")

    # Persistence handle
    hardening_run_id: int

    # What to harden and where to publish
    source_image_ref: str  # e.g. "golang:1.25-alpine" or a client base ref
    target_registry: str  # ECR repo URL (push target, no tag)
    published_tag: str  # e.g. "v0.1.0"

    # Where it runs
    build_instance_id: str  # the dedicated build EC2 (NOT the fixer's env2)
    aws_region: str = "us-east-1"

    # Build inputs
    dockerfile_path: str | None = None  # path on the build box; None = use default
    build_directory: str | None = None  # docker build context dir
    sbom_bucket: str | None = None  # S3 bucket for the SBOM artifact

    # Signing toggle (the UI-configurable auto-sign option)
    auto_sign: bool = False

    # Populated by the orchestrator between phases (e.g. the pushed digest,
    # so later phases + the signing dispatch can reference the exact artifact).
    published_digest: str | None = None
    backup_reference: str | None = None

    # Emitter — orchestrator injects a trace emitter. Signature mirrors the
    # fixer's: emit_fn(run_id, label, event_type, message). The label is the
    # hardening-specific identity, NOT "sub-agent-4".


class HardeningOutcome(BaseModel):
    """Final aggregate outcome of a hardening run's lifecycle.

    Analogous to the fixer's StrategyOutcome but with hardening-specific
    publish/sign fields.
    """

    model_config = ConfigDict(extra="forbid")

    status: Literal["success", "failed", "rolled_back"]
    step_results: list[StepResult] = Field(default_factory=list)
    validation_results: list[ValidationResult] = Field(default_factory=list)
    rollback_results: list[RollbackResult] = Field(default_factory=list)

    # What got published
    published_digest: str | None = None
    published_tag: str | None = None
    sbom_s3_key: str | None = None
    scan_summary: dict = Field(default_factory=dict)

    # Signing
    sign_dispatched: bool = False

    backup_reference: str | None = None
    error_message: str | None = None
