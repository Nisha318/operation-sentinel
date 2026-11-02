variable "name_prefix" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "alert_email" {
  description = "Email address for the alert topic. Leave empty to skip the subscription."
  type        = string
  default     = ""
}
