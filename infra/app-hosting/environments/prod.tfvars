env               = "prod"
aws_region        = "us-east-1"
github_repository = "the-sisyfix/Agentic_VOP"
instance_type     = "t4g.small"
volume_size       = 20

# Immutable OIDC subject prefix (owner-id + repo-id embedded). Source of truth:
# repo Settings > Actions > OIDC "Default subject claim prefix".
github_subject_prefix = "repo:the-sisyfix@339457570/Agentic_VOP@1223959649"

# GitHub Actions runner CIDR blocks for SSH access
# Retrieve current ranges from https://api.github.com/meta (actions key)
# Using 0.0.0.0/0 temporarily — tighten with actual GH Actions IPs after first deploy
ssh_allowed_cidrs = ["0.0.0.0/0"]
