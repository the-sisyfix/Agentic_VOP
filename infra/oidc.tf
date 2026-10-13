# -----------------------------------------------------------------------------
# GitHub OIDC Provider and Trust Policies
# Requirements: 16.1–16.5
# -----------------------------------------------------------------------------

# GitHub Actions OIDC Identity Provider
resource "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  # AWS no longer requires thumbprint verification for GitHub Actions OIDC.
  # An empty list or any value is accepted — AWS validates the token directly.
  # See: https://github.blog/changelog/2023-06-27-github-actions-update-on-oidc-integration-with-aws/
  thumbprint_list = ["ffffffffffffffffffffffffffffffffffffffff"]

  tags = {
    Name = "sisyfix-github-actions-oidc"
  }
}

# -----------------------------------------------------------------------------
# NOTE: The GitHub Actions CI roles (infra-plan, infra-apply, lambda-deploy,
# backfill) are defined in iam.tf — that is the single authoritative source,
# because iam.tf also attaches their permission policies and deny rules.
# This file previously duplicated those four roles (plus two trust-policy data
# sources) as aws_iam_role.github_*, which aliased the same physical roles and
# conflicted on apply. Those duplicates were removed; only the OIDC provider
# (above) lives here now. The immutable OIDC subject condition is applied in
# iam.tf via local.github_subject_prefix.
# -----------------------------------------------------------------------------
