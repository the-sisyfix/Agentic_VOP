# ------------------------------------------------------------------------------
# IAM for the build EC2 instance — least privilege
# ------------------------------------------------------------------------------
# The build box gets exactly two capabilities:
#   1. SSM core (so we can reach it via Session Manager, no SSH).
#   2. Push/pull to the ONE test ECR repository (scoped by ARN) + the
#      account-wide GetAuthorizationToken (which cannot be resource-scoped).
#
# Deliberately NO signing-key access on this role. For the v1 slice keyless
# signing is intended to run off-box (GitHub Actions OIDC) so the build host
# never holds signing material — a step toward the L3 "signing secret not
# accessible to build steps" requirement. If signing is later moved on-box
# with KMS, add a tightly-scoped kms:Sign statement here and revisit the L3
# gap analysis.

resource "aws_iam_role" "build" {
  name                 = "${local.name}-ec2"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Role = "build-ec2"
  }
}

# SSM Session Manager access (no SSH needed)
resource "aws_iam_role_policy_attachment" "build_ssm_core" {
  role       = aws_iam_role.build.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ECR: auth token is account-wide (not resource-scopable); push/pull actions
# are scoped to the single test repository ARN.
resource "aws_iam_role_policy" "build_ecr_push" {
  name = "${local.name}-ecr-push-policy"
  role = aws_iam_role.build.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRAuthToken"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRPushPullTestRepoOnly"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:DescribeImages",
          "ecr:DescribeImageScanFindings"
        ]
        Resource = local.ecr_repository_arn
      }
    ]
  })
}

# S3: the build box uploads the SBOM it generates to the SBOM bucket under the
# sboms/ prefix (keyed by image digest). Write-only + list; no read needed.
resource "aws_iam_role_policy" "build_sbom_put" {
  name = "${local.name}-sbom-put-policy"
  role = aws_iam_role.build.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SBOMPutObject"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${local.sbom_bucket_arn}/sboms/*"
      },
      {
        Sid      = "SBOMListBucketPrefix"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = local.sbom_bucket_arn
        Condition = {
          StringLike = {
            "s3:prefix" = "sboms/*"
          }
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "build" {
  name = "${local.name}-ec2"
  role = aws_iam_role.build.name

  tags = {
    Role = "build-ec2"
  }
}

# =============================================================================
# CI SIGNING ROLE (GitHub Actions OIDC, main branch only)
# =============================================================================
# Option A keyless-signing identity. GitHub Actions assumes this role to:
#   1. Pull the already-built image FROM the test ECR repo BY DIGEST
#      (the build box pushes the unsigned image; CI signs that exact digest).
#   2. Attach cosign signatures + SBOM + SLSA provenance attestations, which
#      cosign stores as additional OCI artifacts IN THE SAME repo (the
#      sha256-<digest>.sig / .att tags) — so the identity needs repo WRITE
#      even though it never "builds" anything.
#
# Why this role lives in the module (not the central infra/iam.tf): it is
# workload-scoped — its sole purpose is to act on THIS module's ECR repo, and
# its permissions are meaningless without that repo. This mirrors the existing
# app-hosting module, which likewise keeps its workload-scoped CI role
# (app_deploy) in infra/app-hosting/iam.tf rather than the central file.
#
# Keyless signing note: the signing KEY is never stored here. Fulcio issues a
# short-lived cert bound to this role's GitHub OIDC identity at sign time.
# This role grants only ECR access, not any kms:Sign — which is what keeps the
# signing material off the build host and advances the SLSA L3 "signing secret
# not accessible to build steps" requirement.
#
# Repo migration: the trust is built from var.github_repository. When the repo
# moves to a new owner, change that one variable + re-apply; verifiers must
# then expect the new --certificate-identity (documented in the signing design).

resource "aws_iam_role" "ci_image_sign" {
  name                 = "sisyfix-github-image-sign-${var.env}"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGitHubOIDCSignMainOnly"
        Effect = "Allow"
        Principal = {
          Federated = local.github_oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          # Genuinely gated to main (ref:refs/heads/main) + GitHub Environments.
          # Stricter than most existing roles here, which use repo:...:* (any ref).
          StringLike = {
            "token.actions.githubusercontent.com:sub" = [
              "${var.github_subject_prefix}:ref:refs/heads/main",
              "${var.github_subject_prefix}:environment:*"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Component = "ci-cd"
    Role      = "image-sign"
  }
}

resource "aws_iam_role_policy" "ci_image_sign" {
  name = "sisyfix-image-sign-${var.env}-policy"
  role = aws_iam_role.ci_image_sign.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRAuthToken"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRPullAndAttachSignaturesTestRepoOnly"
        Effect = "Allow"
        Action = [
          # Pull the image to sign, by digest
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:DescribeImages",
          "ecr:DescribeImageScanFindings",
          # Write signatures / SBOM / provenance attestations back as OCI
          # artifacts in the same repo (cosign attach semantics)
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = local.ecr_repository_arn
      },
      {
        # Download the build-box-generated SBOM (by digest) to attach as an
        # attestation. Read-only, scoped to the sboms/ prefix.
        Sid      = "SBOMGetObject"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${local.sbom_bucket_arn}/sboms/*"
      }
    ]
  })
}

# Dev guardrail: a dev-env signing role must not touch prod ECR, mirroring the
# deny-prod pattern used across the existing modules (app-hosting, infra/iam.tf).
resource "aws_iam_role_policy" "ci_image_sign_deny_prod" {
  count = var.env == "dev" ? 1 : 0

  name = "sisyfix-deny-prod-access"
  role = aws_iam_role.ci_image_sign.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyProdEcr"
        Effect   = "Deny"
        Action   = "ecr:*"
        Resource = "arn:aws:ecr:${var.aws_region}:${local.account_id}:repository/sisyfix-prod-*"
      }
    ]
  })
}
