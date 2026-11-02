#!/usr/bin/env bash
# Attack: grant rds:* on all resources (snapshot exfiltration). Expect the TARGETED deny,
# which blocks snapshot creation and sharing but leaves rds:Describe* working.
source "$(dirname "$0")/common.sh"
load_role

echo "Attacking $ROLE_NAME with rds:* on Resource *"
aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name AttackRdsStar \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["rds:*"],"Resource":"*"}]}'

wait_for "SentinelQuarantineTargeted attached" role_has_policy SentinelQuarantineTargeted
aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name SentinelQuarantineTargeted \
  --query PolicyDocument --output json
show_role_state
