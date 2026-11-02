provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "operation-sentinel"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }

  # Sentinel writes quarantine tags at runtime. Terraform must not treat them as drift
  # and strip them on the next apply.
  ignore_tags {
    key_prefixes = ["sentinel:quarantine"]
  }
}
