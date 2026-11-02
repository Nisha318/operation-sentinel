#!/usr/bin/env bash
# Break glass: resolve attacks and lift quarantines on the TEST role and bucket.
# Run with credentials for a principal listed in release_principal_arns, otherwise
# Sentinel treats the removal as tampering and re-applies the quarantine.
#
# Order matters. Remove the offending grant FIRST, then the quarantine.
source "$(dirname "$0")/common.sh"
load_role
load_bucket

for policy in AttackAdminStar AttackRdsStar; do
  aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$policy" 2>/dev/null && echo "removed $policy" || true
done

# Restore the Lambda only trust policy.
aws iam update-assume-role-policy --role-name "$ROLE_NAME" --policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

for policy in SentinelQuarantineDenyAll SentinelQuarantineTargeted; do
  aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$policy" 2>/dev/null && echo "lifted $policy" || true
done
aws iam untag-role --role-name "$ROLE_NAME" --tag-keys \
  sentinel:quarantined sentinel:quarantine-response sentinel:quarantine-tier \
  sentinel:quarantine-time sentinel:quarantine-event

aws s3api delete-bucket-policy --bucket "$BUCKET" 2>/dev/null && echo "removed bucket policy" || true
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
# Drop only Sentinel's quarantine tags. Keeping Project, Environment and ManagedBy avoids
# drift on the next terraform apply, and keeping sentinel:test-target keeps the scripts safe.
kept_tags="$(aws s3api get-bucket-tagging --bucket "$BUCKET" \
  --query "TagSet[?!starts_with(Key, 'sentinel:quarantine')]" --output json)"
aws s3api put-bucket-tagging --bucket "$BUCKET" --tagging "{\"TagSet\": ${kept_tags}}"

echo "Reset complete"
