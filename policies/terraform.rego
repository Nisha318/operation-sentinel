# Policy as code gate for the Sentinel platform. Evaluated against `terraform show -json` output.
#
#   conftest test plan.json --policy policies --namespace sentinel.terraform
#
# deny blocks the pipeline. warn is reported but does not fail it.
package sentinel.terraform

import rego.v1

# Resources that exist after the change (anything not being deleted).
live contains rc if {
	some rc in input.resource_changes
	rc.change.after != null
}

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

# An attribute is "set" when it has a value now, or when Terraform will compute it at apply
# time. On a first deploy, KMS key ARNs are unknown and appear only in after_unknown. Treating
# those as missing would block every fresh deploy.
attr_set(rc, attr) if rc.change.after[attr]

attr_set(rc, attr) if rc.change.after_unknown[attr] == true

attr_unknown(rc, attr) if {
	not rc.change.after[attr]
	rc.change.after_unknown[attr] == true
}

# ---- IAM policies written by this repo must not be broad ---------------------

policy_types := {"aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

# A policy built from ARNs that do not exist yet is unknown at plan time and cannot be checked
# here. Say so loudly instead of passing silently. The next plan, once the ARNs exist, is checked.
warn contains msg if {
	some rc in live
	rc.type in policy_types
	attr_unknown(rc, "policy")
	msg := sprintf("%s: policy is unknown until apply and was not evaluated by the gate", [rc.address])
}

allow_statements(rc) := [st |
	doc := json.unmarshal(rc.change.after.policy)
	some st in as_array(doc.Statement)
	st.Effect == "Allow"
]

wild_resource(st) if "*" in as_array(st.Resource)

deny contains msg if {
	some rc in live
	rc.type in policy_types
	some st in allow_statements(rc)
	wild_resource(st)
	some action in as_array(st.Action)
	action in {"*", "*:*"}
	msg := sprintf("%s: Allow * on * is not permitted", [rc.address])
}

warn contains msg if {
	some rc in live
	rc.type in policy_types
	some st in allow_statements(rc)
	wild_resource(st)
	some action in as_array(st.Action)
	endswith(action, ":*")
	action != "*:*"
	msg := sprintf("%s: service wide wildcard %s on all resources", [rc.address, action])
}

# ---- IAM trust policies must not be open to everyone -------------------------

open_principal(p) if p == "*"

open_principal(p) if "*" in as_array(p.AWS)

deny contains msg if {
	some rc in live
	rc.type == "aws_iam_role"
	doc := json.unmarshal(rc.change.after.assume_role_policy)
	some st in as_array(doc.Statement)
	st.Effect == "Allow"
	open_principal(st.Principal)
	msg := sprintf("%s: trust policy allows any principal to assume the role", [rc.address])
}

# ---- S3 -----------------------------------------------------------------------

bpa_flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

deny contains msg if {
	some rc in live
	rc.type == "aws_s3_bucket_public_access_block"
	some flag in bpa_flags
	rc.change.after[flag] != true
	msg := sprintf("%s: %s must be true", [rc.address, flag])
}

# ---- encryption and retention ------------------------------------------------------

deny contains msg if {
	some rc in live
	rc.type == "aws_sns_topic"
	not attr_set(rc, "kms_master_key_id")
	msg := sprintf("%s: SNS topic must be encrypted with a KMS key", [rc.address])
}

deny contains msg if {
	some rc in live
	rc.type == "aws_cloudwatch_log_group"
	not rc.change.after.retention_in_days
	msg := sprintf("%s: log group must set retention_in_days", [rc.address])
}

deny contains msg if {
	some rc in live
	rc.type == "aws_cloudwatch_log_group"
	not attr_set(rc, "kms_key_id")
	msg := sprintf("%s: log group must be encrypted with a KMS key", [rc.address])
}

deny contains msg if {
	some rc in live
	rc.type == "aws_sqs_queue"
	not attr_set(rc, "kms_master_key_id")
	msg := sprintf("%s: SQS queue must be encrypted with the platform KMS key", [rc.address])
}

# ---- audit trail ---------------------------------------------------------------------

deny contains msg if {
	some rc in live
	rc.type == "aws_cloudtrail"
	rc.change.after.enable_log_file_validation != true
	msg := sprintf("%s: CloudTrail log file validation must be enabled", [rc.address])
}

deny contains msg if {
	some rc in live
	rc.type == "aws_cloudtrail"
	rc.change.after.is_multi_region_trail != true
	msg := sprintf("%s: CloudTrail must be multi region", [rc.address])
}

# ---- Lambda --------------------------------------------------------------------------

deny contains msg if {
	some rc in live
	rc.type == "aws_lambda_function"
	count(object.get(rc.change.after, "dead_letter_config", [])) == 0
	msg := sprintf("%s: Lambda must have a dead letter queue", [rc.address])
}

lambda_traced(rc) if {
	some tc in object.get(rc.change.after, "tracing_config", [])
	tc.mode == "Active"
}

deny contains msg if {
	some rc in live
	rc.type == "aws_lambda_function"
	not lambda_traced(rc)
	msg := sprintf("%s: Lambda must use active X-Ray tracing", [rc.address])
}

secret_looking := `(hooks\.slack\.com|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY)`

deny contains msg if {
	some rc in live
	rc.type == "aws_lambda_function"
	some env in object.get(rc.change.after, "environment", [])
	some name, value in object.get(env, "variables", {})
	is_string(value)
	regex.match(secret_looking, value)
	msg := sprintf("%s: environment variable %s looks like a plaintext secret", [rc.address, name])
}

# ---- secrets never pass through Terraform ----------------------------------------------

deny contains msg if {
	some rc in live
	rc.type == "aws_secretsmanager_secret_version"
	msg := sprintf("%s: secret values must not be managed by Terraform (they would land in state)", [rc.address])
}
