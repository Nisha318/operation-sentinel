output "topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "slack_secret_arn" {
  value = aws_secretsmanager_secret.slack_webhook.arn
}

output "slack_secret_name" {
  value = aws_secretsmanager_secret.slack_webhook.name
}
