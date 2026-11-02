#!/usr/bin/env bash
# Attack: open the role trust policy to any AWS principal. Expect deny all.
source "$(dirname "$0")/common.sh"
load_role

echo "Opening the trust policy of $ROLE_NAME to any AWS principal"
aws iam update-assume-role-policy --role-name "$ROLE_NAME" --policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'

wait_for "SentinelQuarantineDenyAll attached" role_has_policy SentinelQuarantineDenyAll
show_role_state
