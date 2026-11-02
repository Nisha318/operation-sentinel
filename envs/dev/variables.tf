variable "region" {
  description = "Home region. Must be us-east-1: IAM is global and its CloudTrail events are only delivered there."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.region == "us-east-1"
    error_message = "Operation Sentinel must run in us-east-1 so the IAM detection rule can receive IAM events."
  }
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "name_prefix" {
  description = "Prefix for every resource. The bootstrap deploy role is scoped to this prefix."
  type        = string
  default     = "sentinel"
}

variable "alert_email" {
  description = "Email for the SNS alert topic. Leave empty to skip."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch log retention for Lambda logs."
  type        = number
  default     = 90
}

variable "trail_retention_days" {
  description = "Days CloudTrail log files stay in S3."
  type        = number
  default     = 365
}

variable "authorized_actor_arns" {
  description = "Role ARNs whose IAM changes are alerted on but not quarantined. Put the CI deploy role here."
  type        = list(string)
  default     = []
}

variable "release_principal_arns" {
  description = "Break glass role ARNs allowed to lift a quarantine."
  type        = list(string)
  default     = []
}

variable "trusted_account_ids" {
  description = "Extra account IDs allowed in role trust policies."
  type        = list(string)
  default     = []
}

variable "deploy_monitored_resources" {
  description = "Create the aether-app-reporting-role and aether-reports bucket used by the attack scripts."
  type        = bool
  default     = true
}

variable "force_destroy" {
  description = "Allow destroy to delete non empty buckets. Dev only."
  type        = bool
  default     = true
}
