# ==============================================================================
# image-forge — dedicated build environment for the SLSA base-image supply chain
# ==============================================================================
# First end-to-end slice: a dedicated build EC2 + a test ECR repository used to
# prove the build -> scan -> SBOM -> sign/attest -> push -> verify pipeline for
# hardened, minimal base images.
#
# SLSA target (this slice): Build L2 (dedicated build infrastructure + signed
# provenance). Full L3 (per-run isolation + signing-key isolation from build
# steps) is a deferred next milestone — see docs for the gap analysis.
#
# Conventions mirror infra/app-hosting:
#   - S3 backend configured via -backend-config=backend/<env>.hcl
#   - sisyfix-${var.env}-* naming, Project/Environment/ManagedBy default tags
#   - SSM Session Manager for access (no SSH ingress by default)
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Backend configuration is provided via -backend-config flag
    # using environment-specific .hcl files in backend/
    # Example: terraform init -backend-config=backend/dev.hcl
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "sisyfix"
      Environment = var.env
      ManagedBy   = "terraform"
      Component   = "image-forge"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  name       = "sisyfix-${var.env}-image-forge"

  # The one test ECR repository the build box is allowed to push to.
  ecr_repository_arn = "arn:aws:ecr:${var.aws_region}:${local.account_id}:repository/${var.ecr_repository_name}"

  # SBOM artifacts bucket name (defined in s3.tf) — referenced by IAM policies.
  sbom_bucket_name = "${local.name}-sbom-${local.account_id}"
  sbom_bucket_arn  = "arn:aws:s3:::${local.name}-sbom-${local.account_id}"

  # Shared GitHub Actions OIDC provider (created in the top-level infra/ state —
  # referenced by ARN here, same pattern app-hosting uses for shared resources).
  github_oidc_provider_arn = "arn:aws:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"
}
