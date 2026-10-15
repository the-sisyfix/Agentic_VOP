"""Image Hardening configuration — all values config-driven, nothing hardcoded.

Pulled from app.config.settings (env-backed) with sane MVP defaults. Mirrors
the fixer's FixerConfig style.

EPHEMERAL-READY: this config carries a `build_instance_id`, but the STRATEGY
never reads it — the orchestrator resolves an instance (via `resolve_build_instance`)
and injects it into the HardenContext. For the MVP that resolver returns the
fixed long-lived box id from settings. For the future ephemeral-box-per-build
model, ONLY the resolver changes (provision → return new id → terminate after),
with no change to the strategy, context, executor calls, or persistence.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import settings


@dataclass(frozen=True)
class HardeningConfig:
    """Immutable hardening configuration snapshot for one run."""

    # AWS region for SSM + ECR + S3.
    aws_region: str = "us-east-1"

    # The build EC2 the MVP dispatches to (long-lived box). In the ephemeral
    # future this is ignored in favor of a per-run provisioned instance — see
    # resolve_build_instance().
    build_instance_id: str = ""

    # ECR repository URL the hardened image is pushed to (no tag).
    ecr_repository_url: str = ""

    # S3 bucket the SBOM is uploaded to (keyed by digest under sboms/).
    sbom_bucket: str = ""

    # Default build context on the build box (where the repo is cloned).
    # Must live under an allowed working directory (see fixer safety allowlist).
    default_build_directory: str = "/opt/image-forge-src/image-forge/base-images/static-hello"
    default_dockerfile_path: str = (
        "/opt/image-forge-src/image-forge/base-images/static-hello/Dockerfile"
    )

    # Scan gate severities that FAIL the run.
    scan_gate_severities: str = "CRITICAL,HIGH"

    # --- Copa (in-place patch) path ---
    # BuildKit endpoint copa connects to. Copa needs a running buildkitd; the
    # strategy starts a moby/buildkit container on the box and talks to it over
    # this TCP address. Honest note: copa patches OS packages only — app/lang
    # deps (pip/npm/go) need the rebuild path.
    buildkit_addr: str = "tcp://0.0.0.0:8888"
    buildkit_image: str = "moby/buildkit:v0.12.5"
    # Max remediation loop iterations before giving up (scan→patch→re-scan).
    max_remediation_iterations: int = 3
    # Scratch dir on the box for trivy JSON reports. Kept under the already
    # allowed /opt/image-forge-src/ prefix so safety's working-directory
    # allowlist permits commands here without any further change.
    copa_scratch_dir: str = "/opt/image-forge-src/.copa-scratch"

    # Whole-run timeout (seconds). Image builds + scans are slower than a
    # typical fix, so this is generous.
    run_timeout_s: int = 1800

    # --- Auto-sign (GitHub Actions dispatch) ---
    # When a run has auto_sign=True, the orchestrator dispatches the signing
    # workflow. These identify the workflow to trigger. Token comes from
    # settings.github_pat (reused; needs actions:write).
    github_repo: str = ""  # "owner/repo"
    github_sign_workflow: str = "image-sign.yml"
    github_sign_ref: str = "main"


def load_hardening_config() -> HardeningConfig:
    """Build a HardeningConfig from env-backed settings, with MVP defaults.

    All values are config-driven. New settings fields are read defensively via
    getattr so this does not require touching the shared Settings schema before
    those fields exist (they can be added to app/config.py when wired to the UI).
    """
    return HardeningConfig(
        aws_region=getattr(settings, "aws_region", "us-east-1"),
        build_instance_id=getattr(settings, "hardening_build_instance_id", "")
        or getattr(settings, "fixer_env2_instance_id", ""),
        ecr_repository_url=getattr(settings, "hardening_ecr_repository_url", ""),
        sbom_bucket=getattr(settings, "hardening_sbom_bucket", ""),
        github_repo=getattr(settings, "github_repo", "")
        or getattr(settings, "github_repository", ""),
    )


def resolve_build_instance(config: HardeningConfig) -> str:
    """Return the build-EC2 instance id to run this hardening build on.

    THE EPHEMERAL SEAM. For the MVP this returns the fixed long-lived box id
    from config. For the future ephemeral model, replace the body with:
    provision a fresh instance, wait for SSM online, return its id (and pair
    with a teardown in the orchestrator's finally block). Nothing else in the
    pipeline needs to change — the strategy only ever sees the returned id.
    """
    if not config.build_instance_id:
        raise RuntimeError(
            "No build instance configured. Set HARDENING_BUILD_INSTANCE_ID "
            "(or FIXER_ENV2_INSTANCE_ID) in env."
        )
    return config.build_instance_id
