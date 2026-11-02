data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# ---- protected role: the "app reporting" workload from the Aether scenario ----

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "reporting" {
  name               = "aether-app-reporting-role"
  assume_role_policy = data.aws_iam_policy_document.trust.json

  tags = {
    "sentinel:protected"   = "true"
    "sentinel:test-target" = "true"
  }
}

# Read only. Specific actions on all resources is fine. The attack scripts add the bad grants.
data "aws_iam_policy_document" "reporting" {
  statement {
    sid       = "DescribeDatabases"
    actions   = ["rds:DescribeDBInstances", "rds:DescribeDBClusters", "rds:DescribeDBSnapshots"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "reporting" {
  name   = "reporting-read-only"
  role   = aws_iam_role.reporting.id
  policy = data.aws_iam_policy_document.reporting.json
}

# ---- monitored bucket ----------------------------------------------------------

resource "aws_s3_bucket" "reports" {
  bucket        = "aether-reports-${local.account_id}"
  force_destroy = var.force_destroy

  tags = {
    "sentinel:test-target" = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
