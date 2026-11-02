#!/usr/bin/env bash
# Attack: touch the audit trail configuration.
#
# This is a deliberately harmless trigger. It calls UpdateTrail with the value the trail
# already has (log file validation on), so nothing about logging changes, but CloudTrail
# still records an UpdateTrail event. Sentinel's tamper rule should publish a critical
# "Audit trail changed: UpdateTrail" alert to the SNS topic (and so to your email) within
# about a minute. Never use StopLogging for this test, that would really blind the trail.
source "$(dirname "$0")/common.sh"

TRAIL_ARN="${TRAIL_ARN:-$("$TF_BIN" -chdir="$TF_DIR" output -raw trail_arn)}"

echo "Calling UpdateTrail on $TRAIL_ARN with its current settings"
start="$(now)"
aws cloudtrail update-trail --name "$TRAIL_ARN" --enable-log-file-validation \
  --query '{name:Name,validation:LogFileValidationEnabled}' --output table

echo "Confirming the trail is still logging"
aws cloudtrail get-trail-status --name "$TRAIL_ARN" --query '{logging:IsLogging}' --output table

echo "Done at +$(( $(now) - start ))s. Expect an alert titled 'Audit trail changed: UpdateTrail'."
echo "Delivery is visible in the AWS/Events MatchedEvents and Invocations metrics for the"
echo "sentinel-audit-trail-tamper rule."
