data "aws_region" "current" {}

locals {
  region   = data.aws_region.current.name
  controls = var.controls
  ns       = "Sentinel"

  # One metric line per control, per metric. EMF emits these from the Lambda log lines.
  detected  = [for c in local.controls : [local.ns, "ViolationDetected", "Control", c, { label = "${c} detected" }]]
  succeeded = [for c in local.controls : [local.ns, "RemediationSucceeded", "Control", c, { label = "${c} remediated" }]]
  failed    = [for c in local.controls : [local.ns, "RemediationFailed", "Control", c, { label = "${c} failed" }]]
  critical  = [for c in local.controls : [local.ns, "CriticalViolation", "Control", c, { label = c }]]
  ttr_avg   = [for c in local.controls : [local.ns, "TimeToRemediateSeconds", "Control", c, { label = "${c} avg", stat = "Average" }]]
  ttr_max   = [for c in local.controls : [local.ns, "TimeToRemediateSeconds", "Control", c, { label = "${c} max", stat = "Maximum" }]]
  exempt    = [for c in local.controls : [local.ns, "ExemptViolation", "Control", c, { label = "${c} exempt" }]]
  alert_bad = [for c in local.controls : [local.ns, "AlertFailed", "Control", c, { label = "${c} alert failed" }]]

  # Only iam-quarantine emits these. Listing them for every control would draw empty lines.
  iam_signals = contains(local.controls, "iam-quarantine") ? [
    for m in ["TamperDetected", "ProtectionRemoved", "QuarantineReleased", "BoundaryRemoved"] :
    [local.ns, m, "Control", "iam-quarantine", { label = m }]
  ] : []

  invocations = [for c in local.controls : ["AWS/Lambda", "Invocations", "FunctionName", var.function_names[c], { label = c }]]
  errors      = [for c in local.controls : ["AWS/Lambda", "Errors", "FunctionName", var.function_names[c], { label = c }]]

  log_sources = join(" | ", [for c in local.controls : "SOURCE '${var.log_group_names[c]}'"])
}

# ---- alarms -----------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "critical_violation" {
  for_each = toset(local.controls)

  alarm_name          = "${var.name_prefix}-${each.key}-critical-violation"
  alarm_description   = "A critical violation was detected by ${each.key}. Second alert path, independent of the Lambda."
  namespace           = local.ns
  metric_name         = "CriticalViolation"
  dimensions          = { Control = each.key }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "remediation_failed" {
  for_each = toset(local.controls)

  alarm_name          = "${var.name_prefix}-${each.key}-remediation-failed"
  alarm_description   = "${each.key} detected a violation and could not fix it. Human action needed."
  namespace           = local.ns
  metric_name         = "RemediationFailed"
  dimensions          = { Control = each.key }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "alert_failed" {
  for_each = toset(local.controls)

  alarm_name          = "${var.name_prefix}-${each.key}-alert-delivery-failed"
  alarm_description   = "${each.key} could not deliver an alert to SNS or Slack. The remediation still ran. Check the function log."
  namespace           = local.ns
  metric_name         = "AlertFailed"
  dimensions          = { Control = each.key }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = toset(local.controls)

  alarm_name          = "${var.name_prefix}-${each.key}-lambda-errors"
  alarm_description   = "The ${each.key} function raised an error."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = var.function_names[each.key] }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  for_each = toset(local.controls)

  alarm_name          = "${var.name_prefix}-${each.key}-dlq-not-empty"
  alarm_description   = "An event for ${each.key} failed all retries and is sitting in the dead letter queue."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = var.dlq_names[each.key] }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_topic_arn]
}

# ---- dashboard --------------------------------------------------------------

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = "${var.name_prefix}-overview"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "text", x = 0, y = 0, width = 24, height = 2
        properties = {
          markdown = "# Sentinel shield\nDetections, automated responses, and time from violation to remediation. Time to remediate is measured from the CloudTrail event time, so it includes event delivery."
        }
      },
      {
        type = "metric", x = 0, y = 2, width = 8, height = 6
        properties = {
          title   = "Time to remediate (seconds)"
          view    = "timeSeries"
          region  = local.region
          stat    = "Average"
          period  = 300
          metrics = concat(local.ttr_avg, local.ttr_max)
        }
      },
      {
        type = "metric", x = 8, y = 2, width = 8, height = 6
        properties = {
          title   = "Violations detected vs remediated"
          view    = "timeSeries"
          region  = local.region
          stat    = "Sum"
          period  = 300
          metrics = concat(local.detected, local.succeeded)
        }
      },
      {
        type = "metric", x = 16, y = 2, width = 8, height = 6
        properties = {
          title   = "Critical violations (24h)"
          view    = "singleValue"
          region  = local.region
          stat    = "Sum"
          period  = 86400
          metrics = local.critical
        }
      },
      {
        type = "metric", x = 0, y = 8, width = 8, height = 6
        properties = {
          title   = "Remediation failures"
          view    = "timeSeries"
          region  = local.region
          stat    = "Sum"
          period  = 300
          metrics = local.failed
        }
      },
      {
        type = "metric", x = 8, y = 8, width = 8, height = 6
        properties = {
          title   = "Lambda invocations"
          view    = "timeSeries"
          region  = local.region
          stat    = "Sum"
          period  = 300
          metrics = local.invocations
        }
      },
      {
        type = "metric", x = 16, y = 8, width = 8, height = 6
        properties = {
          title   = "Lambda errors"
          view    = "timeSeries"
          region  = local.region
          stat    = "Sum"
          period  = 300
          metrics = local.errors
        }
      },
      {
        type = "metric", x = 0, y = 14, width = 8, height = 6
        properties = {
          title   = "Exempt violations (allowed by design)"
          view    = "timeSeries"
          region  = local.region
          stat    = "Sum"
          period  = 300
          metrics = local.exempt
        }
      },
      {
        type = "metric", x = 8, y = 14, width = 8, height = 6
        properties = {
          title   = "Quarantine tamper, protection and release events"
          view    = "timeSeries"
          region  = local.region
          stat    = "Sum"
          period  = 300
          metrics = length(local.iam_signals) > 0 ? local.iam_signals : local.exempt
        }
      },
      {
        type = "metric", x = 16, y = 14, width = 8, height = 6
        properties = {
          title   = "Alert delivery failures"
          view    = "timeSeries"
          region  = local.region
          stat    = "Sum"
          period  = 300
          metrics = local.alert_bad
        }
      },
      {
        type = "log", x = 0, y = 20, width = 24, height = 8
        properties = {
          title  = "Recent Sentinel actions"
          region = local.region
          view   = "table"
          query  = "${local.log_sources} | fields @timestamp, control, message, role, bucket, tier, actor, source_ip, seconds_to_remediate | filter ispresent(control) and level != 'info' | sort @timestamp desc | limit 50"
        }
      },
    ]
  })
}
