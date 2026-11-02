variable "name_prefix" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

variable "controls" {
  description = "Control names, matching the Control dimension emitted by the Lambdas."
  type        = list(string)
}

variable "function_names" {
  description = "Map of control name to Lambda function name."
  type        = map(string)
}

variable "log_group_names" {
  description = "Map of control name to Lambda log group name."
  type        = map(string)
}

variable "dlq_names" {
  description = "Map of control name to dead letter queue name."
  type        = map(string)
}
