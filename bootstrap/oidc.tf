# ---------------------------------------------------------------------------
# GitHub Actions OIDC. Two roles with different trust:
#   plan   : pull requests and main, read only, cannot change anything
#   deploy : only jobs that run in the protected GitHub environment (required reviewers)
# A pull request can therefore never obtain write access to the account.
# ---------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_oidc_provider ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

locals {
  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
  repo_ref          = "${var.github_org}/${var.github_repo}"
}

data "aws_iam_policy_document" "plan_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${local.repo_ref}:pull_request",
        "repo:${local.repo_ref}:ref:refs/heads/main",
      ]
    }
  }
}

data "aws_iam_policy_document" "deploy_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.repo_ref}:environment:${var.github_environment}"]
    }
  }
}

# ---- plan role -------------------------------------------------------------

resource "aws_iam_role" "plan" {
  name                 = "${var.ci_role_prefix}-plan"
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "state_read" {
  statement {
    sid       = "ReadState"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
  }
  statement {
    sid       = "DecryptState"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.state.arn]
  }
}

resource "aws_iam_role_policy" "plan_state_read" {
  name   = "state-read"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.state_read.json
}

# ---- deploy role -----------------------------------------------------------

resource "aws_iam_role" "deploy" {
  name                 = "${var.ci_role_prefix}-deploy"
  assume_role_policy   = data.aws_iam_policy_document.deploy_trust.json
  max_session_duration = 3600
}

# Reads for refresh and plan. The write permissions below are scoped to this project.
resource "aws_iam_role_policy_attachment" "deploy_readonly" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "deploy" {
  statement {
    sid       = "StateReadWrite"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
  }

  statement {
    sid       = "StateKey"
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.state.arn]
  }

  statement {
    sid = "ManageProjectRolesAndPolicies"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:UpdateRole", "iam:UpdateAssumeRolePolicy",
      "iam:TagRole", "iam:UntagRole", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
      "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:CreatePolicy", "iam:DeletePolicy",
      "iam:CreatePolicyVersion", "iam:DeletePolicyVersion", "iam:TagPolicy", "iam:UntagPolicy",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:role/${var.name_prefix}-*",
      "arn:aws:iam::${local.account_id}:role/${var.extra_aether_role_prefix}-*",
      "arn:aws:iam::${local.account_id}:policy/${var.name_prefix}-*",
    ]
  }

  statement {
    sid       = "PassProjectRolesToLambda"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.account_id}:role/${var.name_prefix}-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }

  statement {
    sid       = "NeverGrantAdministratorAccess"
    effect    = "Deny"
    actions   = ["iam:AttachRolePolicy"]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values   = ["arn:aws:iam::aws:policy/AdministratorAccess"]
    }
  }

  statement {
    sid       = "Lambda"
    actions   = ["lambda:*"]
    resources = ["arn:aws:lambda:${var.region}:${local.account_id}:function:${var.name_prefix}-*"]
  }

  statement {
    sid       = "EventBridge"
    actions   = ["events:PutRule", "events:DeleteRule", "events:PutTargets", "events:RemoveTargets", "events:TagResource", "events:UntagResource"]
    resources = ["arn:aws:events:${var.region}:${local.account_id}:rule/${var.name_prefix}-*"]
  }

  statement {
    sid       = "LogGroups"
    actions   = ["logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:AssociateKmsKey", "logs:DisassociateKmsKey", "logs:TagResource", "logs:UntagResource", "logs:TagLogGroup"]
    resources = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${var.name_prefix}-*", "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${var.name_prefix}-*:*"]
  }

  statement {
    sid       = "SnsAndSqs"
    actions   = ["sns:*", "sqs:*"]
    resources = ["arn:aws:sns:${var.region}:${local.account_id}:${var.name_prefix}-*", "arn:aws:sqs:${var.region}:${local.account_id}:${var.name_prefix}-*"]
  }

  statement {
    sid       = "Secrets"
    actions   = ["secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:UpdateSecret", "secretsmanager:TagResource", "secretsmanager:UntagResource", "secretsmanager:PutResourcePolicy", "secretsmanager:DeleteResourcePolicy"]
    resources = ["arn:aws:secretsmanager:${var.region}:${local.account_id}:secret:${var.name_prefix}/*"]
  }

  # Write actions for the bucket sub resources Terraform manages. Reads come from ReadOnlyAccess.
  # Deleting a sub resource (BPA, lifecycle, encryption) uses the matching Put permission.
  # Object deletes are only for force_destroy on the dev buckets.
  statement {
    sid = "ProjectBuckets"
    actions = [
      "s3:CreateBucket", "s3:DeleteBucket", "s3:PutBucketTagging",
      "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration", "s3:PutLifecycleConfiguration",
      "s3:PutBucketOwnershipControls", "s3:DeleteObject", "s3:DeleteObjectVersion",
    ]
    resources = ["arn:aws:s3:::${var.name_prefix}-*", "arn:aws:s3:::${var.name_prefix}-*/*", "arn:aws:s3:::${var.extra_aether_role_prefix}-*", "arn:aws:s3:::${var.extra_aether_role_prefix}-*/*"]
  }

  statement {
    sid       = "CloudWatchAlarmsAndDashboards"
    actions   = ["cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms", "cloudwatch:PutDashboard", "cloudwatch:DeleteDashboards", "cloudwatch:TagResource", "cloudwatch:UntagResource"]
    resources = ["arn:aws:cloudwatch:${var.region}:${local.account_id}:alarm:${var.name_prefix}-*", "arn:aws:cloudwatch::${local.account_id}:dashboard/${var.name_prefix}-*"]
  }

  statement {
    sid       = "CloudTrail"
    actions   = ["cloudtrail:CreateTrail", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:StartLogging", "cloudtrail:StopLogging", "cloudtrail:PutEventSelectors", "cloudtrail:AddTags", "cloudtrail:RemoveTags"]
    resources = ["arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${var.name_prefix}-*"]
  }

  # kms:CreateKey has no resource ARN to scope (the key does not exist yet), so the wildcard is
  # unavoidable. It is constrained to requests that tag the new key with this project's tag,
  # which the provider default_tags in envs/dev always send.
  statement {
    sid       = "CreateProjectKeys"
    actions   = ["kms:CreateKey", "kms:TagResource"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = [local.project_tag]
    }
  }

  # Key level management only on keys that already carry the project tag. Wildcard resource
  # because key IDs are random, the tag condition does the scoping.
  statement {
    sid = "ManageProjectKeys"
    actions = [
      "kms:CreateAlias", "kms:DeleteAlias", "kms:ScheduleKeyDeletion", "kms:PutKeyPolicy",
      "kms:EnableKeyRotation", "kms:TagResource", "kms:UntagResource", "kms:CreateGrant",
      "kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [local.project_tag]
    }
  }

  # Aliases are separate resources with no tags. CreateAlias needs both the alias and the key.
  statement {
    sid       = "ManageProjectAliases"
    actions   = ["kms:CreateAlias", "kms:DeleteAlias"]
    resources = ["arn:aws:kms:${var.region}:${local.account_id}:alias/${var.name_prefix}-*"]
  }

  # The state key carries the same project tag. The pipeline must never be able to change its
  # policy or delete it, or a bad deploy could lock everyone out of state.
  statement {
    sid    = "ProtectStateKey"
    effect = "Deny"
    actions = [
      "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:CreateGrant",
      "kms:UntagResource", "kms:TagResource",
    ]
    resources = [aws_kms_key.state.arn]
  }

  statement {
    sid       = "ProtectStateKeyAlias"
    effect    = "Deny"
    actions   = ["kms:DeleteAlias", "kms:UpdateAlias", "kms:CreateAlias"]
    resources = [aws_kms_alias.state.arn]
  }

  statement {
    sid       = "XRayConfig"
    actions   = ["xray:GetTraceSummaries"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "deploy-project-resources"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}
