# --- IAM Roles and Policies ---
# Requirements 9.1–9.6, 1.5: Least-privilege IAM design for EC2 app hosting

# --- Data Sources ---

data "aws_caller_identity" "current" {}

# --- Locals ---

locals {
  account_id = data.aws_caller_identity.current.account_id

  # GitHub OIDC provider ARN (existing provider)
  github_oidc_provider_arn = "arn:aws:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"

  # Resource ARNs used across multiple policies
  intelligence_table_arn = "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/sisyfix-${var.env}-vulnerability-intelligence"
}

# =============================================================================
# 1. EC2 INSTANCE ROLE (per-environment, assumed by EC2 service)
# =============================================================================

resource "aws_iam_role" "ec2_instance" {
  name                 = "sisyfix-${var.env}-ec2-instance"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Component = "app-hosting"
    Role      = "ec2-instance"
  }
}

# Attach AmazonSSMManagedInstanceCore for SSM Session Manager access
resource "aws_iam_role_policy_attachment" "ec2_ssm_core" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Inline policy: SSM Parameter Store read access for app secrets
resource "aws_iam_role_policy" "ec2_ssm_read" {
  name = "sisyfix-ec2-ssm-read-${var.env}-policy"
  role = aws_iam_role.ec2_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMReadAppSecrets"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/sisyfix/${var.env}/app/*"
      }
    ]
  })
}

# Inline policy: DynamoDB read access for vulnerability intelligence table
resource "aws_iam_role_policy" "ec2_dynamodb_read" {
  name = "sisyfix-ec2-dynamodb-read-${var.env}-policy"
  role = aws_iam_role.ec2_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBReadVulnIntelligence"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:BatchGetItem"
        ]
        Resource = local.intelligence_table_arn
      }
    ]
  })
}

# Inline policy: SSM SendCommand to vuln-labs instances (for SA4 remediation)
resource "aws_iam_role_policy" "ec2_ssm_send_command" {
  name = "sisyfix-ec2-ssm-send-command-${var.env}-policy"
  role = aws_iam_role.ec2_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMSendCommandToVulnLabs"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:ListCommandInvocations",
          "ssm:DescribeInstanceInformation"
        ]
        Resource = "*"
      }
    ]
  })
}

# Instance Profile for EC2 attachment
resource "aws_iam_instance_profile" "ec2_instance" {
  name = "sisyfix-${var.env}-ec2-instance"
  role = aws_iam_role.ec2_instance.name

  tags = {
    Component = "app-hosting"
  }
}

# =============================================================================
# 2. APP DEPLOY ROLE (per-environment, main branch only via GitHub OIDC)
# =============================================================================

resource "aws_iam_role" "app_deploy" {
  name                 = "sisyfix-github-app-deploy-${var.env}"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGitHubOIDCDeploy"
        Effect = "Allow"
        Principal = {
          Federated = local.github_oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
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
    Role      = "app-deploy"
  }
}

# Inline policy: SSM read for SSH key and EC2 public IP
resource "aws_iam_role_policy" "app_deploy_ssm" {
  name = "sisyfix-app-deploy-${var.env}-policy"
  role = aws_iam_role.app_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMReadDeploySecrets"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = [
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/sisyfix/${var.env}/ec2/ssh-private-key",
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/sisyfix/${var.env}/ec2/public-ip"
        ]
      }
    ]
  })
}

# =============================================================================
# 3. (Removed — EC2 infra provisioning uses shared sisyfix-github-ec2-infra-apply role
#     defined in infra/iam.tf, not a per-module role)
# =============================================================================

# =============================================================================
# 4. EXPLICIT DENY: Dev roles cannot access prod resources (Req 9.6)
# =============================================================================

resource "aws_iam_role_policy" "ec2_instance_deny_prod" {
  count = var.env == "dev" ? 1 : 0

  name = "sisyfix-deny-prod-access"
  role = aws_iam_role.ec2_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyProdResources"
        Effect = "Deny"
        Action = "*"
        Resource = [
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/sisyfix/prod/*",
          "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/sisyfix-prod-*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "app_deploy_deny_prod" {
  count = var.env == "dev" ? 1 : 0

  name = "sisyfix-deny-prod-access"
  role = aws_iam_role.app_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyProdResources"
        Effect = "Deny"
        Action = "*"
        Resource = [
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/sisyfix/prod/*"
        ]
      }
    ]
  })
}
