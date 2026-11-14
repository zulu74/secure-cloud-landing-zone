# providers.tf
# Provider configuration targets LocalStack by default so the entire
# landing zone can be built and tested for $0 before ever touching a
# real AWS account. Flip `use_localstack = false` (or unset the env
# var) to point this at real AWS with the same code.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "use_localstack" {
  description = "Route all AWS API calls through LocalStack (localhost:4566) instead of real AWS."
  type        = bool
  default     = true
}

locals {
  localstack_endpoint = "http://localhost:4566"
}

provider "aws" {
  region                      = var.aws_region
  access_key                  = var.use_localstack ? "test" : null
  secret_key                  = var.use_localstack ? "test" : null
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack
  s3_use_path_style           = var.use_localstack

  # Setting an endpoint to null (when use_localstack = false) tells the
  # provider to fall back to the real AWS endpoint for that service.
  endpoints {
    s3     = var.use_localstack ? local.localstack_endpoint : null
    iam    = var.use_localstack ? local.localstack_endpoint : null
    lambda = var.use_localstack ? local.localstack_endpoint : null
    ec2    = var.use_localstack ? local.localstack_endpoint : null
    sts    = var.use_localstack ? local.localstack_endpoint : null
    logs   = var.use_localstack ? local.localstack_endpoint : null
  }
}
