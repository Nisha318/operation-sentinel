locals {
  name = "${var.name_prefix}-s3-public-access"

  # Bucket level API calls are management events. They reach EventBridge in the bucket's
  # region, so this rule covers us-east-1 only. See docs/design-decisions.md for extending it.
  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "CreateBucket",
        "PutBucketPolicy",
        "PutBucketAcl",
        "PutBucketPublicAccessBlock",
        # CloudTrail logs the DeletePublicAccessBlock API as DeleteBucketPublicAccessBlock.
        # The API name is kept as well so the rule survives either spelling.
        "DeleteBucketPublicAccessBlock",
        "DeletePublicAccessBlock",
      ]
      errorCode = [{ exists = false }]
    }
  })
}

data "aws_iam_policy_document" "control" {
  # Unavoidable wildcard: a bucket can be made public by anyone, so the responder has to
  # reach every bucket in the account. The actions are read only here and limited to
  # Block Public Access and tagging below. No object access, no policy or ACL writes.
  statement {
    sid = "InspectBuckets"
    actions = [
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketAcl",
      "s3:GetBucketTagging",
    ]
    resources = ["arn:aws:s3:::*"]
  }

  # Same wildcard reasoning. PutBucketPublicAccessBlock can only make a bucket safer in
  # practice, and PutBucketTagging is needed for the sentinel:quarantined evidence tag.
  statement {
    sid = "SecureBuckets"
    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketTagging",
    ]
    resources = ["arn:aws:s3:::*"]
  }
}

module "responder" {
  source = "../../responder"

  name              = local.name
  description       = "Re-enables Block Public Access on buckets that become public or lose protection."
  handler           = "s3_public_access.handler.lambda_handler"
  source_dir        = var.source_dir
  event_pattern     = local.event_pattern
  extra_policy_json = data.aws_iam_policy_document.control.json

  sns_topic_arn      = var.sns_topic_arn
  slack_secret_arn   = var.slack_secret_arn
  kms_key_arn        = var.kms_key_arn
  log_retention_days = var.log_retention_days
}
