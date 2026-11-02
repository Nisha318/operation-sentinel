output "function_name" {
  value = aws_lambda_function.this.function_name
}

output "function_arn" {
  value = aws_lambda_function.this.arn
}

output "role_arn" {
  value = aws_iam_role.this.arn
}

output "role_name" {
  value = aws_iam_role.this.name
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.this.name
}

output "dlq_name" {
  value = aws_sqs_queue.dlq.name
}

output "rule_arn" {
  value = aws_cloudwatch_event_rule.this.arn
}
