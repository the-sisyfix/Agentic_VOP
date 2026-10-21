# ------------------------------------------------------------------------------
# SBOM artifacts bucket — transport between the build box and the CI signer
# ------------------------------------------------------------------------------
# The build box generates the SBOM (syft, from the exact image) and uploads it
# here keyed by image digest: sboms/<digest>.spdx.json. The GitHub Actions
# signing workflow downloads it BY DIGEST and runs `cosign attest`, which binds
# the SBOM to the image digest and signs it keylessly.
#
# Why S3 and not regenerate-in-CI: the image is arm64 and the CI runner is
# amd64, so CI can't pull the image to re-scan it with syft. Generating the
# SBOM on the (arm64) build box and shipping the file sidesteps that entirely.
# cosign attaches attestations BY DIGEST without pulling the image, so the
# attest step is arch-independent.
#
# NOTE (see research task): S3 is an L3-NEUTRAL transport (not signing material,
# not in the build-isolation boundary). The trust anchor is the cosign
# attestation binding SBOM->digest, not the bucket. In-transit SBOM integrity
# is a documented production refinement.

resource "aws_s3_bucket" "sbom" {
  bucket = "${local.name}-sbom-${local.account_id}"

  # Test bucket — allow `terraform destroy` to remove it even with objects.
  force_destroy = true

  tags = {
    Name = "${local.name}-sbom"
    Role = "sbom-artifacts"
  }
}

# Block all public access — SBOMs are internal artifacts.
resource "aws_s3_bucket_public_access_block" "sbom" {
  bucket = aws_s3_bucket.sbom.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Server-side encryption at rest (SSE-S3 / AES256), matching the ECR repo.
resource "aws_s3_bucket_server_side_encryption_configuration" "sbom" {
  bucket = aws_s3_bucket.sbom.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versioning — keep a history of SBOMs per key (cheap, aids auditability).
resource "aws_s3_bucket_versioning" "sbom" {
  bucket = aws_s3_bucket.sbom.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Expire throwaway SBOM artifacts (and old versions) after N days so the test
# bucket doesn't accumulate cost. Mirrors the ECR untagged-expiry approach.
resource "aws_s3_bucket_lifecycle_configuration" "sbom" {
  bucket = aws_s3_bucket.sbom.id

  rule {
    id     = "expire-sbom-artifacts"
    status = "Enabled"

    filter {
      prefix = "sboms/"
    }

    expiration {
      days = var.sbom_expire_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.sbom_expire_days
    }
  }
}
