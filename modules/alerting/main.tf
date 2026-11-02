data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = var.kms_key_arn
}

data "aws_iam_policy_document" "topic" {
  statement {
    sid       = "AccountOwnerFullAccess"
    actions   = ["sns:*"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowAlarmsAndEventsToPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sns:Publish", "sns:Subscribe"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.topic.json
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# The secret is created EMPTY on purpose. Terraform never sees the webhook value, so it can
# never land in state or in a plan. Populate it once, out of band:
#
#   aws secretsmanager put-secret-value --secret-id <secret name> \
#     --secret-string '{"webhook_url":"https://hooks.slack.com/services/..."}'
resource "aws_secretsmanager_secret" "slack_webhook" {
  name                    = "${var.name_prefix}/slack-webhook"
  description             = "Slack incoming webhook used by Sentinel responders. JSON: {\"webhook_url\": \"...\"}"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = 7
}
