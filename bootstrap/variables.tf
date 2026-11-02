variable "region" {
  description = "Home region. IAM events are only delivered to us-east-1, so keep the platform there."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for resources the Sentinel platform creates (used to scope the deploy role)."
  type        = string
  default     = "sentinel"
}

variable "ci_role_prefix" {
  description = "Prefix for the CI roles. Must NOT match name_prefix, so the deploy role cannot edit itself."
  type        = string
  default     = "gha-operation-sentinel"
}

variable "github_org" {
  description = "GitHub user or organization that owns the repository."
  type        = string
  default     = "Nisha318"
}

variable "github_repo" {
  description = "Repository name."
  type        = string
  default     = "operation-sentinel"
}

variable "github_environment" {
  description = "GitHub environment whose protection rules gate deployments. Its name appears in the OIDC sub claim."
  type        = string
  default     = "dev"
}

variable "create_oidc_provider" {
  description = "Set false if this account already has the GitHub OIDC provider (only one per URL is allowed)."
  type        = bool
  default     = true
}

variable "extra_aether_role_prefix" {
  description = "Prefix of the monitored test roles the deploy role may create."
  type        = string
  default     = "aether"
}
