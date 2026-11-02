output "alert_topic_arn" {
  value = module.alerting.topic_arn
}

output "slack_secret_name" {
  description = "Populate with: aws secretsmanager put-secret-value --secret-id <this> --secret-string '{\"webhook_url\":\"...\"}'"
  value       = module.alerting.slack_secret_name
}

output "dashboard_name" {
  value = module.observability.dashboard_name
}

output "trail_arn" {
  value = module.audit_logging.trail_arn
}

output "test_role_name" {
  value = var.deploy_monitored_resources ? module.monitored[0].role_name : null
}

output "test_bucket_name" {
  value = var.deploy_monitored_resources ? module.monitored[0].bucket_name : null
}
