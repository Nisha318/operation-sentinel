output "trail_arn" {
  value = aws_cloudtrail.this.arn
}

output "log_bucket" {
  value = aws_s3_bucket.logs.id
}

output "tamper_rule_name" {
  value = aws_cloudwatch_event_rule.trail_tamper.name
}
