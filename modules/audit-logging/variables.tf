variable "name_prefix" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "log_retention_days" {
  description = "Days to keep CloudTrail log files in S3."
  type        = number
  default     = 365
}

variable "monitored_bucket_arns" {
  description = "Buckets that get object level (data event) logging."
  type        = list(string)
  default     = []
}

variable "force_destroy" {
  description = "Allow terraform destroy to remove a non empty log bucket. Dev only."
  type        = bool
  default     = false
}

variable "alert_topic_arn" {
  description = "SNS topic that receives audit trail tamper alerts."
  type        = string
}
