#!/usr/bin/env bash
# Attack: grant the reporting role full admin. Expect SentinelQuarantineDenyAll within seconds.
source "$(dirname "$0")/common.sh"
load_role

echo "Attacking $ROLE_NAME with Action * on Resource *"
aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name AttackAdminStar \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

wait_for "SentinelQuarantineDenyAll attached" role_has_policy SentinelQuarantineDenyAll
show_role_state
echo "Check Slack and the SNS email, then the dashboard for the time to remediate."
