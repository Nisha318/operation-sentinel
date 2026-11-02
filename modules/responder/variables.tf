variable "name" {
  description = "Full function name, for example sentinel-iam-quarantine."
  type        = string
}

variable "description" {
  type = string
}

variable "handler" {
  description = "Python handler, for example iam_quarantine.handler.lambda_handler."
  type        = string
}

variable "source_dir" {
  description = "Directory zipped into the function package (the repo src/ directory)."
  type        = string
}

variable "event_pattern" {
  description = "EventBridge event pattern as a JSON string."
  type        = string
}

variable "extra_policy_json" {
  description = "Control specific IAM policy document (JSON), merged with the base permissions."
  type        = string
}

variable "environment_variables" {
  description = "Extra environment variables for the function."
  type        = map(string)
  default     = {}
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

variable "timeout" {
  type    = number
  default = 30
}

variable "memory_size" {
  type    = number
  default = 256
}

variable "runtime" {
  type    = string
  default = "python3.13"
}
