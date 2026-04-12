terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment to use S3 remote state (recommended for teams).
  # NOTE: Terraform backend blocks do not support variable interpolation.
  # Hardcode the region and bucket name here, or pass them via -backend-config flags:
  #   terraform init -backend-config="region=us-east-1" -backend-config="bucket=my-tfstate"
  # backend "s3" {
  #   bucket         = "backendtesis-tfstate"
  #   key            = "infra/aws/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "backendtesis-tflock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "backendTesis"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# ── Data sources ──────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ── Secrets Manager ───────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "app_secrets" {
  name                    = "${var.project_name}-${var.environment}-secrets"
  description             = "BackendTesis application secrets"
  recovery_window_in_days = var.environment == "production" ? 7 : 0
}

resource "aws_secretsmanager_secret_version" "app_secrets" {
  secret_id = aws_secretsmanager_secret.app_secrets.id
  secret_string = jsonencode({
    SECRET_KEY                   = var.secret_key
    VIRUSTOTAL_API_KEY           = var.virustotal_api_key
    URLSCAN_API_KEY              = var.urlscan_api_key
    GOOGLE_SAFE_BROWSING_API_KEY = var.google_safe_browsing_api_key
    WHOISXML_API_KEY             = var.whoisxml_api_key
    DB_PASSWORD                  = var.db_password
  })

  # Prevent Terraform from showing secret values in plan/apply output
  lifecycle {
    ignore_changes = [secret_string]
  }
}
