data "aws_caller_identity" "current" {}

locals {
  # Must match the Project default tag in envs/dev/providers.tf. The deploy role's KMS
  # permissions are scoped by this tag.
  project_tag = "operation-sentinel"
  account_id  = data.aws_caller_identity.current.account_id
  bucket_name = "${var.name_prefix}-tfstate-${local.account_id}-${var.region}"
}

# ---------------------------------------------------------------------------
# Remote state. This stack is applied once with LOCAL state (the chicken and egg
# step), then its own state may optionally be migrated into the bucket it creates.
# ---------------------------------------------------------------------------

# Explicit key policy. It delegates to IAM in this account (the AWS default, written down), so
# access is decided by the plan and deploy role policies in oidc.tf. The deploy role carries an
# explicit deny on managing this key, so the platform pipeline cannot lock itself out of state.
data "aws_iam_policy_document" "state_key" {
  #checkov:skip=CKV_AWS_109:Key policy root statement is the AWS default delegation to account IAM. Restricting it risks a key lockout; the deploy role is denied key management in oidc.tf.
  statement {
    sid       = "EnableAccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"] # In a key policy, "*" means this key.
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "state" {
  description             = "Terraform state encryption for ${var.name_prefix}"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.state_key.json
}

resource "aws_kms_alias" "state" {
  name          = "alias/${var.name_prefix}-tfstate"
  target_key_id = aws_kms_key.state.key_id
}

resource "aws_s3_bucket" "state" {
  bucket = local.bucket_name
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "expire-old-state-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "state_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
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

resource "aws_s3_bucket_policy" "state" {
  bucket     = aws_s3_bucket.state.id
  policy     = data.aws_iam_policy_document.state_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.state]
}
