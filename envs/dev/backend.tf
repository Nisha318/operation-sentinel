# Partial configuration. Values come from backend.hcl (see backend.hcl.example) locally
# and from -backend-config flags in GitHub Actions.
terraform {
  backend "s3" {}
}
