variable "env" {
  description = "Deployment environment (dev or prod)"
  type        = string

  validation {
    condition     = contains(["dev", "prod"], var.env)
    error_message = "Environment must be one of: dev, prod."
  }
}

variable "alert_email" {
  description = "Email address for CloudWatch alarm notifications via SNS"
  type        = string
}

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "github_repository" {
  description = "GitHub repository in 'owner/repo' format. Used for non-OIDC references (e.g. metadata). OIDC trust uses github_subject_prefix."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be in 'owner/repo' format."
  }
}

variable "github_subject_prefix" {
  description = <<-EOT
    Immutable OIDC subject-claim prefix for the GitHub Actions trust policies, in the form
    'repo:<owner>@<owner_id>/<repo>@<repo_id>'. Copy the value from the repo's
    Settings > Actions > OIDC "Default subject claim prefix". Repositories created, renamed,
    or transferred after 2026-07-15 emit this immutable format; trust conditions append the
    usual suffixes (:* , :ref:refs/heads/main, :environment:*) to this prefix.
  EOT
  type        = string

  validation {
    condition     = can(regex("^repo:[a-zA-Z0-9_.-]+@[0-9]+/[a-zA-Z0-9_.-]+@[0-9]+$", var.github_subject_prefix))
    error_message = "github_subject_prefix must look like 'repo:<owner>@<owner_id>/<repo>@<repo_id>'."
  }
}
