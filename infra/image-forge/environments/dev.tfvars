env        = "dev"
aws_region = "us-east-1"

# GitHub repo whose Actions OIDC identity is trusted to sign images (gated to
# main). Change this single value if/when the repo migrates to a new owner,
# then re-apply — and update the verification identity in the signing design.
github_repository = "the-sisyfix/Agentic_VOP"

# VPC CIDR reuses 10.1.0.0/16 — freed by deleting the manual VOP-vpc-adhoc VPC.
vpc_cidr           = "10.1.0.0/16"
public_subnet_cidr = "10.1.1.0/24"

# Build box sizing — ARM64 Graviton, with EBS headroom for image layers.
instance_type = "t4g.medium"
volume_size   = 40

# Test publish target. MUTABLE because cosign stores signatures/attestations
# as derived OCI tags (sha256-<digest>.sig / .att) and must be able to write
# (and re-write on re-sign) them — IMMUTABLE blocks that with TAG_INVALID.
# Integrity still comes from signing the immutable DIGEST + the Rekor log, not
# from ECR tag immutability. Production milestone: immutable image tags + a
# mutability EXCLUSION for the *.sig/*.att cosign tags.
ecr_repository_name      = "sisyfix-hardened-base-test"
ecr_image_tag_mutability = "MUTABLE"
ecr_untagged_expire_days = 7
