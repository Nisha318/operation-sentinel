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
