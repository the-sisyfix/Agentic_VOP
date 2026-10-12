# --- IAM Roles and Policies ---
# Requirements 15.1–15.8: Least-privilege IAM design with environment isolation

# --- Data Sources ---

data "aws_caller_identity" "current" {}

# --- Locals ---

locals {
  account_id = data.aws_caller_identity.current.account_id

  # GitHub OIDC provider ARN (created in oidc.tf)
  github_oidc_provider_arn = "arn:aws:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"

  # Resource ARNs used across multiple policies
  intelligence_table_arn = aws_dynamodb_table.intelligence.arn
  dlq_arn                = aws_sqs_queue.nvd_sync_dlq.arn
  ssm_nvd_api_key_arn    = aws_ssm_parameter.nvd_api_key.arn
  lambda_log_group_arn   = "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/aws/lambda/sisyfix-${var.env}-nvd-sync:*"

  # GitHub repository for OIDC conditions
  github_repository = var.github_repository

  # Immutable OIDC subject prefix: repo:<owner>@<owner_id>/<repo>@<repo_id>
  github_subject_prefix = var.github_subject_prefix
}

# =============================================================================
# 1. INFRA-PLAN ROLE (read-only, any branch)
# =============================================================================

resource "aws_iam_role" "infra_plan" {
  name                 = "sisyfix-github-infra-plan"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = local.github_oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "${local.github_subject_prefix}:*"
          }
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Component = "ci-cd"
    Role      = "infra-plan"
  }
}

resource "aws_iam_role_policy" "infra_plan" {
  name = "sisyfix-infra-plan-policy"
  role = aws_iam_role.infra_plan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformPlanReadDynamoDB"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeTable",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:DescribeTimeToLive",
          "dynamodb:ListTagsOfResource"
        ]
        Resource = local.intelligence_table_arn
      },
      {
        Sid    = "TerraformPlanReadLambda"
        Effect = "Allow"
        Action = [
          "lambda:Get*",
          "lambda:List*"
        ]
        Resource = "arn:aws:lambda:${var.aws_region}:${local.account_id}:function:sisyfix-${var.env}-nvd-sync"
      },
      {
        Sid    = "TerraformPlanReadSQS"
        Effect = "Allow"
        Action = [
          "sqs:GetQueueAttributes",
          "sqs:ListQueueTags"
        ]
        Resource = local.dlq_arn
      },
      {
        Sid    = "TerraformPlanReadSSM"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:DescribeParameters",
          "ssm:ListTagsForResource"
        ]
        Resource = [
          local.ssm_nvd_api_key_arn,
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:*"
        ]
      },
      {
        Sid    = "TerraformPlanReadIAM"
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:GetOpenIDConnectProvider",
          "iam:ListOpenIDConnectProviders"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:role/sisyfix-*",
          "arn:aws:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"
        ]
      },
      {
        Sid    = "TerraformPlanReadEvents"
        Effect = "Allow"
        Action = [
          "events:DescribeRule",
          "events:ListTargetsByRule",
          "events:ListTagsForResource"
        ]
        Resource = "arn:aws:events:${var.aws_region}:${local.account_id}:rule/sisyfix-${var.env}-nvd-sync-schedule"
      },
      {
        Sid    = "TerraformPlanReadS3"
        Effect = "Allow"
        Action = [
          "s3:Get*",
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::sisyfix-lambda-artifacts-486655355038"
      },
      {
        Sid    = "TerraformPlanReadCloudWatch"
        Effect = "Allow"
        Action = [
          "cloudwatch:DescribeAlarms",
          "cloudwatch:ListTagsForResource"
        ]
        Resource = "arn:aws:cloudwatch:${var.aws_region}:${local.account_id}:alarm:sisyfix-${var.env}-*"
      },
      {
        Sid    = "TerraformPlanReadSNS"
        Effect = "Allow"
        Action = [
          "sns:GetTopicAttributes",
          "sns:GetSubscriptionAttributes",
          "sns:ListSubscriptionsByTopic",
          "sns:ListTagsForResource"
        ]
        Resource = [
          "arn:aws:sns:${var.aws_region}:${local.account_id}:sisyfix-${var.env}-alerts",
          "arn:aws:sns:${var.aws_region}:${local.account_id}:sisyfix-${var.env}-alerts:*"
        ]
      },
      {
        Sid    = "TerraformStateAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::sisyfix-terraform-state-486655355038",
          "arn:aws:s3:::sisyfix-terraform-state-486655355038/*"
        ]
      },
      {
        Sid    = "TerraformStateLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/sisyfix-terraform-locks"
      }
    ]
  })
}

# =============================================================================
# 2. INFRA-APPLY ROLE (per-environment, main branch only)
# =============================================================================

resource "aws_iam_role" "infra_apply" {
  name                 = "sisyfix-github-infra-apply-${var.env}"
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
            "token.actions.githubusercontent.com:sub" = "${local.github_subject_prefix}:*"
          }
        }
      }
    ]
  })

  tags = {
    Component = "ci-cd"
    Role      = "infra-apply"
  }
}

resource "aws_iam_role_policy" "infra_apply" {
  name = "sisyfix-infra-apply-${var.env}-policy"
  role = aws_iam_role.infra_apply.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformApplyDynamoDB"
        Effect = "Allow"
        Action = [
          "dynamodb:CreateTable",
          "dynamodb:UpdateTable",
          "dynamodb:DeleteTable",
          "dynamodb:DescribeTable",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:UpdateContinuousBackups",
          "dynamodb:DescribeTimeToLive",
          "dynamodb:UpdateTimeToLive",
          "dynamodb:TagResource",
          "dynamodb:UntagResource",
          "dynamodb:ListTagsOfResource"
        ]
        Resource = local.intelligence_table_arn
      },
      {
        Sid    = "TerraformApplyLambda"
        Effect = "Allow"
        Action = [
          "lambda:*"
        ]
        Resource = "arn:aws:lambda:${var.aws_region}:${local.account_id}:function:sisyfix-${var.env}-nvd-sync"
      },
      {
        Sid    = "TerraformApplySQS"
        Effect = "Allow"
        Action = [
          "sqs:CreateQueue",
          "sqs:DeleteQueue",
          "sqs:SetQueueAttributes",
          "sqs:GetQueueAttributes",
          "sqs:TagQueue",
          "sqs:UntagQueue",
          "sqs:ListQueueTags"
        ]
        Resource = local.dlq_arn
      },
      {
        Sid    = "TerraformApplySSM"
        Effect = "Allow"
        Action = [
          "ssm:*"
        ]
        Resource = [
          local.ssm_nvd_api_key_arn,
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:*"
        ]
      },
      {
        Sid    = "TerraformApplyIAM"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:UpdateRole",
          "iam:UpdateRoleDescription",
          "iam:UpdateAssumeRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:PassRole",
          "iam:CreateOpenIDConnectProvider",
          "iam:DeleteOpenIDConnectProvider",
          "iam:GetOpenIDConnectProvider",
          "iam:UpdateOpenIDConnectProviderThumbprint",
          "iam:TagOpenIDConnectProvider",
          "iam:ListOpenIDConnectProviders"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:role/sisyfix-*",
          "arn:aws:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"
        ]
      },
      {
        Sid    = "TerraformApplyEvents"
        Effect = "Allow"
        Action = [
          "events:PutRule",
          "events:DeleteRule",
          "events:PutTargets",
          "events:RemoveTargets",
          "events:DescribeRule",
          "events:ListTargetsByRule",
          "events:TagResource",
          "events:UntagResource",
          "events:ListTagsForResource"
        ]
        Resource = "arn:aws:events:${var.aws_region}:${local.account_id}:rule/sisyfix-${var.env}-nvd-sync-schedule"
      },
      {
        Sid    = "TerraformApplyS3"
        Effect = "Allow"
        Action = [
          "s3:*"
        ]
        Resource = [
          "arn:aws:s3:::sisyfix-lambda-artifacts-486655355038",
          "arn:aws:s3:::sisyfix-lambda-artifacts-486655355038/*"
        ]
      },
      {
        Sid    = "TerraformApplyCloudWatch"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:TagResource",
          "cloudwatch:UntagResource",
          "cloudwatch:ListTagsForResource"
        ]
        Resource = "arn:aws:cloudwatch:${var.aws_region}:${local.account_id}:alarm:sisyfix-${var.env}-*"
      },
      {
        Sid    = "TerraformApplySNS"
        Effect = "Allow"
        Action = [
          "sns:*"
        ]
        Resource = [
          "arn:aws:sns:${var.aws_region}:${local.account_id}:sisyfix-${var.env}-alerts",
          "arn:aws:sns:${var.aws_region}:${local.account_id}:sisyfix-${var.env}-alerts:*"
        ]
      },
      {
        Sid    = "TerraformStateAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::sisyfix-terraform-state-486655355038",
          "arn:aws:s3:::sisyfix-terraform-state-486655355038/*"
        ]
      },
      {
        Sid    = "TerraformStateLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/sisyfix-terraform-locks"
      }
    ]
  })
}

# =============================================================================
# 3. LAMBDA-DEPLOY ROLE (per-environment, main branch only)
# =============================================================================

resource "aws_iam_role" "lambda_deploy" {
  name                 = "sisyfix-github-lambda-deploy-${var.env}"
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
            "token.actions.githubusercontent.com:sub" = "${local.github_subject_prefix}:*"
          }
        }
      }
    ]
  })

  tags = {
    Component = "ci-cd"
    Role      = "lambda-deploy"
  }
}

resource "aws_iam_role_policy" "lambda_deploy" {
  name = "sisyfix-lambda-deploy-${var.env}-policy"
  role = aws_iam_role.lambda_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaUpdate"
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:GetFunction",
          "lambda:GetFunctionConfiguration"
        ]
        Resource = "arn:aws:lambda:${var.aws_region}:${local.account_id}:function:sisyfix-${var.env}-nvd-sync"
      },
      {
        Sid    = "S3ArtifactAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::sisyfix-lambda-artifacts-486655355038/nvd-sync/*"
      }
    ]
  })
}

# =============================================================================
# 4. BACKFILL ROLE (per-environment, main branch only)
# =============================================================================

resource "aws_iam_role" "backfill" {
  name                 = "sisyfix-github-backfill-${var.env}"
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
            "token.actions.githubusercontent.com:sub" = "${local.github_subject_prefix}:*"
          }
        }
      }
    ]
  })

  tags = {
    Component = "ci-cd"
    Role      = "backfill"
  }
}

resource "aws_iam_role_policy" "backfill" {
  name = "sisyfix-backfill-${var.env}-policy"
  role = aws_iam_role.backfill.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBBackfillWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:BatchWriteItem",
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem"
        ]
        Resource = local.intelligence_table_arn
      },
      {
        Sid    = "SSMReadApiKey"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = local.ssm_nvd_api_key_arn
      }
    ]
  })
}

# =============================================================================
# 5. LAMBDA EXECUTION ROLE (per-environment, assumed by Lambda service)
# =============================================================================

resource "aws_iam_role" "lambda_execution" {
  name                 = "sisyfix-${var.env}-lambda-execution"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Component = "nvd-sync"
    Role      = "lambda-execution"
  }
}

resource "aws_iam_role_policy" "lambda_execution" {
  name = "sisyfix-${var.env}-lambda-execution-policy"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBReadWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:BatchWriteItem"
        ]
        Resource = local.intelligence_table_arn
      },
      {
        Sid    = "SSMReadApiKey"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = local.ssm_nvd_api_key_arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = local.lambda_log_group_arn
      },
      {
        Sid    = "SQSSendToDLQ"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = local.dlq_arn
      }
    ]
  })
}

# =============================================================================
# 6. API APPLICATION ROLE (per-environment, read-only)
# =============================================================================

resource "aws_iam_role" "api_application" {
  name                 = "sisyfix-${var.env}-api-application"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Component = "api"
    Role      = "api-application"
  }
}

resource "aws_iam_role_policy" "api_application" {
  name = "sisyfix-${var.env}-api-application-policy"
  role = aws_iam_role.api_application.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBReadOnly"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:BatchGetItem"
        ]
        Resource = local.intelligence_table_arn
      },
      {
        Sid    = "SSMReadApiKey"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = local.ssm_nvd_api_key_arn
      }
    ]
  })
}

# =============================================================================
# 7. BREAK-GLASS OPERATOR ROLE (MFA required, 1-hour session, PITR only)
# =============================================================================

resource "aws_iam_role" "break_glass_operator" {
  name                 = "sisyfix-break-glass-operator"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = {
    Component = "emergency"
    Role      = "break-glass-operator"
  }
}

resource "aws_iam_role_policy" "break_glass_operator" {
  name = "sisyfix-break-glass-operator-policy"
  role = aws_iam_role.break_glass_operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PITRRestoreOnly"
        Effect = "Allow"
        Action = [
          "dynamodb:RestoreTableToPointInTime",
          "dynamodb:DescribeTable",
          "dynamodb:DescribeContinuousBackups"
        ]
        Resource = local.intelligence_table_arn
      }
    ]
  })
}

# =============================================================================
# 8. EC2 INFRA APPLY ROLE (single role for all EC2-based provisioning)
# Used by: app-hosting, vuln-labs, and future EC2 workloads.
# =============================================================================

import {
  to = aws_iam_role.ec2_infra_apply
  id = "sisyfix-github-ec2-infra-apply"
}

resource "aws_iam_role" "ec2_infra_apply" {
  name                 = "sisyfix-github-ec2-infra-apply"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGitHubOIDC"
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
            "token.actions.githubusercontent.com:sub" = "${local.github_subject_prefix}:*"
          }
        }
      }
    ]
  })

  tags = {
    Component = "ci-cd"
    Role      = "ec2-infra-apply"
  }
}

resource "aws_iam_role_policy" "ec2_infra_apply" {
  name = "sisyfix-ec2-infra-apply-policy"
  role = aws_iam_role.ec2_infra_apply.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Management"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:ModifyInstanceAttribute",
          "ec2:Describe*",
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "VPCManagement"
        Effect = "Allow"
        Action = [
          "ec2:CreateVpc",
          "ec2:DeleteVpc",
          "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:ModifySubnetAttribute",
          "ec2:CreateInternetGateway",
          "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway",
          "ec2:CreateRouteTable",
          "ec2:DeleteRouteTable",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:AssociateRouteTable",
          "ec2:DisassociateRouteTable",
          "ec2:DeleteNetworkInterface",
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "SecurityGroupManagement"
        Effect = "Allow"
        Action = [
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "KeyPairManagement"
        Effect = "Allow"
        Action = [
          "ec2:CreateKeyPair",
          "ec2:DeleteKeyPair",
          "ec2:ImportKeyPair"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "IAMForEC2"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:UpdateRole",
          "iam:UpdateRoleDescription",
          "iam:UpdateAssumeRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:PassRole",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:GetInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:ListInstanceProfilesForRole",
          "iam:TagInstanceProfile",
          "iam:UntagInstanceProfile",
          "iam:GetOpenIDConnectProvider",
          "iam:ListOpenIDConnectProviders"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:role/sisyfix-*",
          "arn:aws:iam::${local.account_id}:instance-profile/sisyfix-*",
          "arn:aws:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"
        ]
      },
      {
        Sid    = "SSMManagement"
        Effect = "Allow"
        Action = [
          "ssm:PutParameter",
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
          "ssm:DeleteParameter",
          "ssm:DescribeParameters",
          "ssm:ListTagsForResource",
          "ssm:AddTagsToResource",
          "ssm:RemoveTagsFromResource"
        ]
        Resource = [
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/sisyfix/*",
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:*"
        ]
      },
      {
        Sid    = "TerraformStateAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::sisyfix-terraform-state-486655355038",
          "arn:aws:s3:::sisyfix-terraform-state-486655355038/*"
        ]
      },
      {
        Sid    = "TerraformStateLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/sisyfix-terraform-locks"
      }
    ]
  })
}

# =============================================================================
# 8b. VULN-LABS DEPLOY ROLE (CI role for the vuln-labs GitHub Actions workflow)
# Previously created out-of-band (not in Terraform). Imported here so its OIDC
# trust tracks the repo like every other CI role. Global name (no env suffix),
# same deploy-style trust as app-deploy/image-sign.
# =============================================================================

import {
  to = aws_iam_role.vuln_labs_deploy
  id = "sisyfix-github-vuln-labs-deploy"
}

resource "aws_iam_role" "vuln_labs_deploy" {
  name                 = "sisyfix-github-vuln-labs-deploy"
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
              "${local.github_subject_prefix}:ref:refs/heads/main",
              "${local.github_subject_prefix}:environment:*"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Component = "ci-cd"
    Role      = "vuln-labs-deploy"
  }
}

resource "aws_iam_role_policy" "vuln_labs_deploy" {
  name = "sisyfix-github-vuln-labs-deployPolicy"
  role = aws_iam_role.vuln_labs_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Management"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:ImportKeyPair",
          "ec2:CreateKeyPair",
          "ec2:DeleteKeyPair",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:ModifyInstanceAttribute",
          "ec2:AssociateIamInstanceProfile",
          "ec2:DisassociateIamInstanceProfile"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMForVulnLabs"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListInstanceProfilesForRole",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:GetRolePolicy",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:GetInstanceProfile",
          "iam:TagInstanceProfile",
          "iam:UntagInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:PassRole"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:role/vop-vuln-lab-*",
          "arn:aws:iam::${local.account_id}:instance-profile/vop-vuln-lab-*"
        ]
      },
      {
        Sid    = "TerraformState"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          "arn:aws:s3:::sisyfix-terraform-state-${local.account_id}",
          "arn:aws:s3:::sisyfix-terraform-state-${local.account_id}/vuln-labs/*"
        ]
      },
      {
        Sid    = "TerraformLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/sisyfix-terraform-locks"
      },
      {
        Sid    = "STSIdentity"
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# 9. EXPLICIT DENY: Dev roles cannot access prod resources (Req 15.3)
# =============================================================================

resource "aws_iam_role_policy" "infra_apply_deny_prod" {
  count = var.env == "dev" ? 1 : 0

  name = "sisyfix-deny-prod-access"
  role = aws_iam_role.infra_apply.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyProdResources"
        Effect = "Deny"
        Action = "*"
        Resource = [
          "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/sisyfix-prod-*",
          "arn:aws:lambda:${var.aws_region}:${local.account_id}:function:sisyfix-prod-*",
          "arn:aws:sqs:${var.aws_region}:${local.account_id}:sisyfix-prod-*",
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/sisyfix/prod/*",
          "arn:aws:events:${var.aws_region}:${local.account_id}:rule/sisyfix-prod-*",
          "arn:aws:s3:::sisyfix-prod-*",
          "arn:aws:cloudwatch:${var.aws_region}:${local.account_id}:alarm:sisyfix-prod-*",
          "arn:aws:sns:${var.aws_region}:${local.account_id}:sisyfix-prod-*",
          "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/aws/lambda/sisyfix-prod-*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_deploy_deny_prod" {
  count = var.env == "dev" ? 1 : 0

  name = "sisyfix-deny-prod-access"
  role = aws_iam_role.lambda_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyProdResources"
        Effect = "Deny"
        Action = "*"
        Resource = [
          "arn:aws:lambda:${var.aws_region}:${local.account_id}:function:sisyfix-prod-*",
          "arn:aws:s3:::sisyfix-lambda-artifacts-486655355038/nvd-sync/sisyfix-prod-*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "backfill_deny_prod" {
  count = var.env == "dev" ? 1 : 0

  name = "sisyfix-deny-prod-access"
  role = aws_iam_role.backfill.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyProdResources"
        Effect = "Deny"
        Action = "*"
        Resource = [
          "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/sisyfix-prod-*",
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/sisyfix/prod/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_execution_deny_prod" {
  count = var.env == "dev" ? 1 : 0

  name = "sisyfix-deny-prod-access"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyProdResources"
        Effect = "Deny"
        Action = "*"
        Resource = [
          "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/sisyfix-prod-*",
          "arn:aws:sqs:${var.aws_region}:${local.account_id}:sisyfix-prod-*",
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/sisyfix/prod/*",
          "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/aws/lambda/sisyfix-prod-*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "api_application_deny_prod" {
  count = var.env == "dev" ? 1 : 0

  name = "sisyfix-deny-prod-access"
  role = aws_iam_role.api_application.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyProdResources"
        Effect = "Deny"
        Action = "*"
        Resource = [
          "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/sisyfix-prod-*",
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/sisyfix/prod/*"
        ]
      }
    ]
  })
}
