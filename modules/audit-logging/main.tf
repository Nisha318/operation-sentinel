data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  trail_name = "${var.name_prefix}-audit-trail"
  trail_arn  = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
  # Known at plan time, so the tamper rule's event pattern shows up in the reviewed plan.
  log_bucket_name = "${var.name_prefix}-audit-logs-${local.account_id}-${local.region}"
}

# ---- locked down log bucket ------------------------------------------------

resource "aws_s3_bucket" "logs" {
  bucket        = local.log_bucket_name
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "retain-then-expire"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
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

resource "aws_s3_bucket_policy" "logs" {
  bucket     = aws_s3_bucket.logs.id
  policy     = data.aws_iam_policy_document.logs.json
  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# ---- trail -----------------------------------------------------------------

resource "aws_cloudtrail" "this" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = var.kms_key_arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    # Object level (data) events for the monitored buckets, so every read and write is recorded.
    dynamic "data_resource" {
      for_each = length(var.monitored_bucket_arns) > 0 ? [1] : []
      content {
        type   = "AWS::S3::Object"
        values = [for arn in var.monitored_bucket_arns : "${arn}/"]
      }
    }
  }

  depends_on = [aws_s3_bucket_policy.logs]
}

# ---- audit trail tamper detection ---------------------------------------------
# Alert only, no remediation. Anyone who can blind the trail can blind every control, so this
# goes straight to the alert topic with no Lambda in the path. The deploy role also triggers it
# when Terraform updates the trail, which is intended: trail changes should always be seen.

locals {
  tamper_rule_name = "${var.name_prefix}-audit-trail-tamper"
}

resource "aws_cloudwatch_event_rule" "trail_tamper" {
  name        = local.tamper_rule_name
  description = "Alerts when the Sentinel audit trail or its log bucket is weakened"

  event_pattern = jsonencode({
    source        = ["aws.cloudtrail", "aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      errorCode = [{ exists = false }]
      "$or" = [
        {
          eventSource = ["cloudtrail.amazonaws.com"]
          eventName   = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
        },
        {
          eventSource       = ["s3.amazonaws.com"]
          eventName         = ["PutBucketPolicy", "DeleteBucketPolicy", "PutBucketLifecycle", "DeleteBucketLifecycle"]
          requestParameters = { bucketName = [local.log_bucket_name] }
        },
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "trail_tamper" {
  rule = aws_cloudwatch_event_rule.trail_tamper.name
  arn  = var.alert_topic_arn

  retry_policy {
    maximum_retry_attempts       = 10
    maximum_event_age_in_seconds = 3600
  }

  input_transformer {
    input_paths = {
      event  = "$.detail.eventName"
      actor  = "$.detail.userIdentity.arn"
      ip     = "$.detail.sourceIPAddress"
      time   = "$.detail.eventTime"
      region = "$.detail.awsRegion"
      id     = "$.detail.eventID"
    }
    input_template = <<-EOT
      {"control": "audit-trail", "severity": "critical", "title": "Audit trail changed: <event>", "actor": "<actor>", "source_ip": "<ip>", "event_time": "<time>", "region": "<region>", "event_id": "<id>", "action_taken": "alert only, verify the trail is logging"}
    EOT
  }
}
