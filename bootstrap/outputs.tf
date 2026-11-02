output "state_bucket" {
  value = aws_s3_bucket.state.id
}

output "state_kms_key_arn" {
  value = aws_kms_key.state.arn
}

output "plan_role_arn" {
  description = "Set as the AWS_PLAN_ROLE_ARN repository variable."
  value       = aws_iam_role.plan.arn
}

output "deploy_role_arn" {
  description = "Set as the AWS_DEPLOY_ROLE_ARN repository variable, and list in authorized_actor_arns for envs/dev."
  value       = aws_iam_role.deploy.arn
}

output "backend_hcl" {
  description = "Contents for envs/dev/backend.hcl"
  value       = <<-EOT
    bucket       = "${aws_s3_bucket.state.id}"
    key          = "operation-sentinel/dev/terraform.tfstate"
    region       = "${var.region}"
    encrypt      = true
    kms_key_id   = "${aws_kms_key.state.arn}"
    use_lockfile = true
  EOT
}
