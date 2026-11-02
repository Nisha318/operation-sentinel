package sentinel.terraform_test

import rego.v1

import data.sentinel.terraform

plan(resource) := {"resource_changes": [resource]}

admin_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
})

scoped_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{"Effect": "Allow", "Action": ["rds:DescribeDBInstances"], "Resource": "*"}],
})

service_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{"Effect": "Allow", "Action": "rds:*", "Resource": "*"}],
})

test_admin_policy_is_denied if {
	r := {"address": "aws_iam_role_policy.x", "type": "aws_iam_role_policy", "change": {"after": {"policy": admin_policy}}}
	count(terraform.deny) == 1 with input as plan(r)
}

test_scoped_policy_is_allowed if {
	r := {"address": "aws_iam_role_policy.x", "type": "aws_iam_role_policy", "change": {"after": {"policy": scoped_policy}}}
	count(terraform.deny) == 0 with input as plan(r)
}

test_service_wildcard_warns_but_does_not_deny if {
	r := {"address": "aws_iam_role_policy.x", "type": "aws_iam_role_policy", "change": {"after": {"policy": service_policy}}}
	count(terraform.deny) == 0 with input as plan(r)
	count(terraform.warn) == 1 with input as plan(r)
}

test_deleted_resources_are_ignored if {
	r := {"address": "aws_iam_role_policy.x", "type": "aws_iam_role_policy", "change": {"after": null}}
	count(terraform.deny) == 0 with input as plan(r)
}

test_incomplete_public_access_block_is_denied if {
	r := {"address": "aws_s3_bucket_public_access_block.b", "type": "aws_s3_bucket_public_access_block", "change": {"after": {
		"block_public_acls": true,
		"block_public_policy": false,
		"ignore_public_acls": true,
		"restrict_public_buckets": true,
	}}}
	count(terraform.deny) == 1 with input as plan(r)
}

test_unencrypted_sns_topic_is_denied if {
	r := {"address": "aws_sns_topic.t", "type": "aws_sns_topic", "change": {"after": {"name": "t"}}}
	count(terraform.deny) == 1 with input as plan(r)
}

test_log_group_without_retention_or_kms_is_denied if {
	r := {"address": "aws_cloudwatch_log_group.g", "type": "aws_cloudwatch_log_group", "change": {"after": {"name": "g"}}}
	count(terraform.deny) == 2 with input as plan(r)
}

test_trail_without_validation_is_denied if {
	r := {"address": "aws_cloudtrail.t", "type": "aws_cloudtrail", "change": {"after": {
		"enable_log_file_validation": false,
		"is_multi_region_trail": true,
	}}}
	count(terraform.deny) == 1 with input as plan(r)
}

traced := [{"mode": "Active"}]

dlq := [{"target_arn": "arn:aws:sqs:us-east-1:111122223333:q"}]

test_lambda_without_dlq_is_denied if {
	r := {"address": "aws_lambda_function.f", "type": "aws_lambda_function", "change": {"after": {"dead_letter_config": [], "tracing_config": traced}}}
	count(terraform.deny) == 1 with input as plan(r)
}

test_lambda_without_active_tracing_is_denied if {
	r := {"address": "aws_lambda_function.f", "type": "aws_lambda_function", "change": {"after": {
		"dead_letter_config": dlq,
		"tracing_config": [{"mode": "PassThrough"}],
	}}}
	count(terraform.deny) == 1 with input as plan(r)
}

test_compliant_lambda_is_allowed if {
	r := {"address": "aws_lambda_function.f", "type": "aws_lambda_function", "change": {"after": {"dead_letter_config": dlq, "tracing_config": traced}}}
	count(terraform.deny) == 0 with input as plan(r)
}

test_plaintext_webhook_in_lambda_env_is_denied if {
	r := {"address": "aws_lambda_function.f", "type": "aws_lambda_function", "change": {"after": {
		"dead_letter_config": dlq,
		"tracing_config": traced,
		"environment": [{"variables": {"HOOK": "https://hooks.slack.com/services/T000/B000/XXXX"}}],
	}}}
	count(terraform.deny) == 1 with input as plan(r)
}

test_single_region_trail_is_denied if {
	r := {"address": "aws_cloudtrail.t", "type": "aws_cloudtrail", "change": {"after": {
		"enable_log_file_validation": true,
		"is_multi_region_trail": false,
	}}}
	count(terraform.deny) == 1 with input as plan(r)
}

test_full_wildcard_does_not_also_warn if {
	r := {"address": "aws_iam_role_policy.x", "type": "aws_iam_role_policy", "change": {"after": {"policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": "*:*", "Resource": "*"}],
	})}}}
	count(terraform.deny) == 1 with input as plan(r)
	count(terraform.warn) == 0 with input as plan(r)
}

# ---- values that are unknown until apply (first deploy) ------------------------

test_kms_key_known_after_apply_passes if {
	sns := {"address": "aws_sns_topic.t", "type": "aws_sns_topic", "change": {
		"after": {"name": "t"},
		"after_unknown": {"kms_master_key_id": true},
	}}
	logs := {"address": "aws_cloudwatch_log_group.g", "type": "aws_cloudwatch_log_group", "change": {
		"after": {"name": "g", "retention_in_days": 90},
		"after_unknown": {"kms_key_id": true},
	}}
	count(terraform.deny) == 0 with input as {"resource_changes": [sns, logs]}
}

test_unknown_policy_warns_instead_of_passing_silently if {
	r := {"address": "aws_iam_role_policy.x", "type": "aws_iam_role_policy", "change": {
		"after": {"name": "x"},
		"after_unknown": {"policy": true},
	}}
	count(terraform.deny) == 0 with input as plan(r)
	count(terraform.warn) == 1 with input as plan(r)
}

# ---- trust policies and queues ---------------------------------------------------

test_open_trust_policy_is_denied if {
	r := {"address": "aws_iam_role.r", "type": "aws_iam_role", "change": {"after": {"assume_role_policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
	})}}}
	count(terraform.deny) == 1 with input as plan(r)
}

test_service_trust_policy_is_allowed if {
	r := {"address": "aws_iam_role.r", "type": "aws_iam_role", "change": {"after": {"assume_role_policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
	})}}}
	count(terraform.deny) == 0 with input as plan(r)
}

test_unencrypted_queue_is_denied if {
	r := {"address": "aws_sqs_queue.q", "type": "aws_sqs_queue", "change": {"after": {"name": "q", "sqs_managed_sse_enabled": true}}}
	count(terraform.deny) == 1 with input as plan(r)
}

test_cmk_encrypted_queue_is_allowed if {
	r := {"address": "aws_sqs_queue.q", "type": "aws_sqs_queue", "change": {"after": {"name": "q", "kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc"}}}
	count(terraform.deny) == 0 with input as plan(r)
}

test_secret_version_in_terraform_is_denied if {
	r := {"address": "aws_secretsmanager_secret_version.s", "type": "aws_secretsmanager_secret_version", "change": {"after": {"secret_string": "x"}}}
	count(terraform.deny) == 1 with input as plan(r)
}
