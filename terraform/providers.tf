terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    ec = {
      source  = "elastic/ec"
      version = "~> 0.10"
    }
  }
}

# AWS Provider - uses AWS_PROFILE or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY from environment
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "cribl-elastic-demo"
      Environment = "test"
    }
  }
}

# Elastic Cloud Provider - uses EC_API_KEY from environment
provider "ec" {}
