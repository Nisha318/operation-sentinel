data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  name       = "${var.name_prefix}-iam-quarantine"

  # Must match the role name the responder module derives from var.name ("<name>-role").
  own_role_arn = "arn:aws:iam::${local.account_id}:role/${local.name}-role"

  # IAM is a global service. Its CloudTrail events only reach EventBridge in us-east-1.
  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        # CreateRole: a role can be born protected and already violating (open trust).
        # TagRole: tagging an existing violator sentinel:protected=true brings it into scope.
        "CreateRole",
        "TagRole",
        "PutRolePolicy",
        "AttachRolePolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
        "UpdateAssumeRolePolicy",
        "DeleteRolePermissionsBoundary",
        "DeleteRolePolicy",
        "UntagRole",
      ]
      errorCode = [{ exists = false }]
    }
  })
}

data "aws_iam_policy_document" "control" {
  statement {
    sid = "ReadRolesAndPolicies"
    actions = [
      "iam:GetRole",
      "iam:ListRolePolicies",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
    ]
    resources = ["arn:aws:iam::${local.account_id}:role/*"]
  }

  statement {
    sid = "ReadManagedPolicies"
    actions = [
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListEntitiesForPolicy",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:policy/*",
      "arn:aws:iam::aws:policy/*",
    ]
  }

  # AWS enforces the scope. Sentinel can only write to roles carrying the protected tag.
  statement {
    sid       = "QuarantineProtectedRolesOnly"
    actions   = ["iam:PutRolePolicy"]
    resources = ["arn:aws:iam::${local.account_id}:role/*"]
    condition {
      test     = "StringEquals"
      variable = "iam:ResourceTag/sentinel:protected"
      values   = ["true"]
    }
  }

  statement {
    sid       = "TagQuarantineStateOnly"
    actions   = ["iam:TagRole"]
    resources = ["arn:aws:iam::${local.account_id}:role/*"]
    condition {
      test     = "StringEquals"
      variable = "iam:ResourceTag/sentinel:protected"
      values   = ["true"]
    }
    condition {
      test     = "ForAllValues:StringLike"
      variable = "aws:TagKeys"
      values   = ["sentinel:quarantine*"]
    }
  }

  # A compromised Sentinel must not be able to rewrite itself.
  statement {
    sid       = "NeverModifySelf"
    effect    = "Deny"
    actions   = ["iam:*"]
    resources = [local.own_role_arn]
  }
}

module "responder" {
  source = "../../responder"

  name              = local.name
  description       = "Quarantines protected IAM roles that gain wildcard permissions or open trust."
  handler           = "iam_quarantine.handler.lambda_handler"
  source_dir        = var.source_dir
  event_pattern     = local.event_pattern
  extra_policy_json = data.aws_iam_policy_document.control.json

  environment_variables = {
    AUTHORIZED_ACTOR_ARNS  = join(",", var.authorized_actor_arns)
    RELEASE_PRINCIPAL_ARNS = join(",", var.release_principal_arns)
    TRUSTED_ACCOUNT_IDS    = join(",", var.trusted_account_ids)
  }

  sns_topic_arn      = var.sns_topic_arn
  slack_secret_arn   = var.slack_secret_arn
  kms_key_arn        = var.kms_key_arn
  log_retention_days = var.log_retention_days
}
