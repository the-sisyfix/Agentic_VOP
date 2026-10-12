variable "env" {
  description = "Deployment environment (dev or prod)"
  type        = string

  validation {
    condition     = contains(["dev", "prod"], var.env)
    error_message = "Environment must be one of: dev, prod."
  }
}

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "github_repository" {
  description = "GitHub repository in 'owner/repo' format. Used for the EC2 git clone source. OIDC trust uses github_subject_prefix."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be in 'owner/repo' format."
  }
}

variable "github_subject_prefix" {
  description = <<-EOT
    Immutable OIDC subject-claim prefix for the GitHub Actions trust policy, in the form
    'repo:<owner>@<owner_id>/<repo>@<repo_id>'. Copy from the repo's Settings > Actions > OIDC
    "Default subject claim prefix". Trust conditions append the usual suffixes.
  EOT
  type        = string

  validation {
    condition     = can(regex("^repo:[a-zA-Z0-9_.-]+@[0-9]+/[a-zA-Z0-9_.-]+@[0-9]+$", var.github_subject_prefix))
    error_message = "github_subject_prefix must look like 'repo:<owner>@<owner_id>/<repo>@<repo_id>'."
  }
}

variable "instance_type" {
  description = "EC2 instance type for the application server"
  type        = string
  default     = "t4g.small"
}

variable "volume_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 20
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH into the EC2 instance (e.g., GitHub Actions runner IPs)"
  type        = list(string)
  default     = []
}
