#!/usr/bin/env bash
# Attack: remove Block Public Access from the test bucket and try to publish it.
# Only ever runs against the bucket tagged sentinel:test-target=true. It holds no real data.
#
# The delete is recorded by CloudTrail as DeleteBucketPublicAccessBlock and triggers
# Sentinel on its own. The policy write follows within a second, so two outcomes are a pass:
#   * Sentinel re-enables Block Public Access before the policy is written (policy is rejected)
#   * the policy lands first and Sentinel then neutralizes it
source "$(dirname "$0")/common.sh"
load_bucket

echo "Removing Block Public Access from $BUCKET"
aws s3api delete-public-access-block --bucket "$BUCKET"

echo "Attempting to publish the bucket"
aws s3api put-bucket-policy --bucket "$BUCKET" --policy "{
  \"Version\":\"2012-10-17\",
  \"Statement\":[{\"Sid\":\"AttackPublicRead\",\"Effect\":\"Allow\",\"Principal\":\"*\",
  \"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::${BUCKET}/*\"}]}" \
  || echo "Policy rejected: Sentinel already re-enabled Block Public Access"

wait_for "Block Public Access fully enabled" bucket_fully_blocked
aws s3api get-bucket-tagging --bucket "$BUCKET" --output table
