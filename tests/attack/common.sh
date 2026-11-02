#!/usr/bin/env bash
# Shared helpers for the attack scripts. Source this file, do not run it.
#
# Safety: every script refuses to touch a role or bucket that does not carry the tag
# sentinel:test-target=true, which only the monitored-resources module sets.
set -euo pipefail

export AWS_DEFAULT_REGION="${AWS_REGION:-us-east-1}"
TF_BIN="${TF_BIN:-terraform}"
TF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../envs/dev" && pwd)"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-180}"

load_role() {
  ROLE_NAME="${ROLE_NAME:-$("$TF_BIN" -chdir="$TF_DIR" output -raw test_role_name)}"
  local flag
  flag="$(aws iam list-role-tags --role-name "$ROLE_NAME" \
    --query "Tags[?Key=='sentinel:test-target'].Value | [0]" --output text)"
  if [[ "$flag" != "true" ]]; then
    echo "Refusing to run: role $ROLE_NAME is not tagged sentinel:test-target=true" >&2
    exit 1
  fi
}

load_bucket() {
  BUCKET="${BUCKET:-$("$TF_BIN" -chdir="$TF_DIR" output -raw test_bucket_name)}"
  local flag
  flag="$(aws s3api get-bucket-tagging --bucket "$BUCKET" \
    --query "TagSet[?Key=='sentinel:test-target'].Value | [0]" --output text)"
  if [[ "$flag" != "true" ]]; then
    echo "Refusing to run: bucket $BUCKET is not tagged sentinel:test-target=true" >&2
    exit 1
  fi
}

now() { date +%s; }

# wait_for <description> <command...>  : polls once per second until the command succeeds.
wait_for() {
  local description="$1"; shift
  local start deadline
  start="$(now)"; deadline=$(( start + TIMEOUT_SECONDS ))
  until "$@" >/dev/null 2>&1; do
    if (( $(now) > deadline )); then
      echo "TIMEOUT after ${TIMEOUT_SECONDS}s waiting for: $description" >&2
      return 1
    fi
    sleep 1
  done
  echo "OBSERVED: $description after $(( $(now) - start ))s"
}

role_has_policy() {
  aws iam list-role-policies --role-name "$ROLE_NAME" --query "PolicyNames[?@=='$1'] | [0]" --output text | grep -qv None
}

bucket_fully_blocked() {
  local result
  result="$(aws s3api get-public-access-block --bucket "$BUCKET" \
    --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' \
    --output text)"
  [[ "$result" == "True	True	True	True" ]]
}

show_role_state() {
  echo "--- inline policies"
  aws iam list-role-policies --role-name "$ROLE_NAME" --output table
  echo "--- tags"
  aws iam list-role-tags --role-name "$ROLE_NAME" --output table
}
