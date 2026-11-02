variable "name_prefix" {
  type = string
}

variable "source_dir" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

variable "slack_secret_arn" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "authorized_actor_arns" {
  description = "Role ARNs whose IAM changes are alerted on but not quarantined (for example the CI deploy role)."
  type        = list(string)
  default     = []
}

variable "release_principal_arns" {
  description = "Role ARNs allowed to lift a quarantine (break glass). Their changes are recorded, not reverted."
  type        = list(string)
  default     = []
}

variable "trusted_account_ids" {
  description = "Extra AWS account IDs that may appear in role trust policies."
  type        = list(string)
  default     = []
}
