data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  role_name  = "${var.name}-role"
  log_group  = "/aws/lambda/${var.name}"
}

# The package is the whole src/ tree: shared helpers plus every handler package.
# Each function selects its own handler, so the zip is identical across functions.
data "archive_file" "package" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.module}/.build/${var.name}.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

resource "aws_cloudwatch_log_group" "this" {
  name              = local.log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

# One DLQ catches both failure modes: events EventBridge could not deliver to the function,
# and invocations that failed every Lambda retry. Encrypted with the platform CMK, whose key
# policy already lets events.amazonaws.com use it. The Lambda role gets kms:GenerateDataKey below.
resource "aws_sqs_queue" "dlq" {
  name                              = "${var.name}-dlq"
  message_retention_seconds         = 1209600
  kms_master_key_id                 = var.kms_key_arn
  kms_data_key_reuse_period_seconds = 300
}

data "aws_iam_policy_document" "dlq" {
  statement {
    sid       = "AllowDetectionRuleDeadLetters"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.this.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy    = data.aws_iam_policy_document.dlq.json
}

# ---- execution role: base permissions plus the control's own statements ----

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

data "aws_iam_policy_document" "base" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.this.arn}:*"]
  }

  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }

  statement {
    sid       = "ReadSlackWebhookSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.slack_secret_arn]
  }

  statement {
    sid       = "UsePlatformKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }

  statement {
    sid       = "SendFailedEventsToDlq"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }

  # X-Ray does not support resource level permissions.
  statement {
    sid       = "XRayTracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "combined" {
  source_policy_documents = [
    data.aws_iam_policy_document.base.json,
    var.extra_policy_json,
  ]
}

resource "aws_iam_role" "this" {
  name               = local.role_name
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "this" {
  name   = "responder"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.combined.json
}

# ---- function ---------------------------------------------------------------

resource "aws_lambda_function" "this" {
  function_name    = var.name
  description      = var.description
  role             = aws_iam_role.this.arn
  handler          = var.handler
  runtime          = var.runtime
  architectures    = ["arm64"]
  filename         = data.archive_file.package.output_path
  source_code_hash = data.archive_file.package.output_base64sha256
  timeout          = var.timeout
  memory_size      = var.memory_size
  kms_key_arn      = var.kms_key_arn

  environment {
    variables = merge(var.environment_variables, {
      SNS_TOPIC_ARN    = var.sns_topic_arn
      SLACK_SECRET_ARN = var.slack_secret_arn
      OWN_ROLE_ARN     = aws_iam_role.this.arn
    })
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  # Text format keeps our one-JSON-object-per-line logs (and EMF metrics) untouched.
  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.this.name
  }

  depends_on = [aws_iam_role_policy.this, aws_cloudwatch_log_group.this]
}

resource "aws_lambda_function_event_invoke_config" "this" {
  function_name                = aws_lambda_function.this.function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600
}

# ---- detection wiring -------------------------------------------------------

resource "aws_cloudwatch_event_rule" "this" {
  name          = var.name
  description   = "Detection rule for ${var.name}"
  event_pattern = var.event_pattern
}

resource "aws_cloudwatch_event_target" "this" {
  rule = aws_cloudwatch_event_rule.this.name
  arn  = aws_lambda_function.this.arn

  retry_policy {
    maximum_retry_attempts       = 2
    maximum_event_age_in_seconds = 3600
  }

  # Without this, an event EventBridge cannot deliver (throttling, a broken permission)
  # is dropped silently. With it, the event lands in the DLQ and the DLQ alarm fires.
  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this.arn
}
