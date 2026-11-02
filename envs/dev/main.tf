locals {
  src_dir = "${path.root}/../../src"
}

# ---- Phase 1: foundation ---------------------------------------------------------

module "kms" {
  source      = "../../modules/kms"
  name_prefix = var.name_prefix
}

module "monitored" {
  count  = var.deploy_monitored_resources ? 1 : 0
  source = "../../modules/monitored-resources"

  kms_key_arn   = module.kms.key_arn
  force_destroy = var.force_destroy
}

module "audit_logging" {
  source = "../../modules/audit-logging"

  name_prefix           = var.name_prefix
  kms_key_arn           = module.kms.key_arn
  log_retention_days    = var.trail_retention_days
  monitored_bucket_arns = var.deploy_monitored_resources ? [module.monitored[0].bucket_arn] : []
  force_destroy         = var.force_destroy
  alert_topic_arn       = module.alerting.topic_arn
}

module "alerting" {
  source = "../../modules/alerting"

  name_prefix = var.name_prefix
  kms_key_arn = module.kms.key_arn
  alert_email = var.alert_email
}

# ---- Phases 2 and 3: detection and remediation ----------------------------------

module "iam_quarantine" {
  source = "../../modules/controls/iam-quarantine"

  name_prefix            = var.name_prefix
  source_dir             = local.src_dir
  sns_topic_arn          = module.alerting.topic_arn
  slack_secret_arn       = module.alerting.slack_secret_arn
  kms_key_arn            = module.kms.key_arn
  log_retention_days     = var.log_retention_days
  authorized_actor_arns  = var.authorized_actor_arns
  release_principal_arns = var.release_principal_arns
  trusted_account_ids    = var.trusted_account_ids
}

module "s3_public_access" {
  source = "../../modules/controls/s3-public-access"

  name_prefix        = var.name_prefix
  source_dir         = local.src_dir
  sns_topic_arn      = module.alerting.topic_arn
  slack_secret_arn   = module.alerting.slack_secret_arn
  kms_key_arn        = module.kms.key_arn
  log_retention_days = var.log_retention_days
}

# ---- Phase 4: observability -------------------------------------------------------

module "observability" {
  source = "../../modules/observability"

  name_prefix   = var.name_prefix
  sns_topic_arn = module.alerting.topic_arn
  controls      = ["iam-quarantine", "s3-public-access"]

  function_names = {
    "iam-quarantine"   = module.iam_quarantine.function_name
    "s3-public-access" = module.s3_public_access.function_name
  }
  log_group_names = {
    "iam-quarantine"   = module.iam_quarantine.log_group_name
    "s3-public-access" = module.s3_public_access.log_group_name
  }
  dlq_names = {
    "iam-quarantine"   = module.iam_quarantine.dlq_name
    "s3-public-access" = module.s3_public_access.dlq_name
  }
}
