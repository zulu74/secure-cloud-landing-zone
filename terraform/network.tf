# network.tf
# Minimal landing-zone network: one VPC, one private subnet, no
# default route to the internet, and an explicit "default security
# group locks everything down" guardrail — a common CIS/AWS
# foundational benchmark finding when left open.

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "${var.project_name}-vpc"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  map_public_ip_on_launch = false

  tags = {
    Name        = "${var.project_name}-private-subnet"
    Environment = var.environment
  }
}

# CIS AWS Foundations 5.3 — ensure the default security group of every
# VPC restricts all traffic. Terraform manages it explicitly instead of
# leaving the AWS-created default (which allows all traffic) in place.
resource "aws_default_security_group" "locked_down" {
  vpc_id = aws_vpc.main.id

  # No ingress or egress rules = deny everything by default.
  tags = {
    Name = "${var.project_name}-default-sg-locked"
  }
}
