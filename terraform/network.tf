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

# --- VPC Flow Logs (CKV2_AWS_11) -----------------------------------------
# Without flow logs, nobody can answer "what talked to what" after an
# incident — this is the network-layer equivalent of the posture check:
# it doesn't prevent anything, it gives you the evidence to investigate
# when something does happen.

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/${var.project_name}/vpc-flow-logs"
  retention_in_days = 90

  tags = {
    Name = "${var.project_name}-vpc-flow-logs"
  }
}

data "aws_iam_policy_document" "flow_logs_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.project_name}-vpc-flow-logs-role"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume_role.json
}

data "aws_iam_policy_document" "flow_logs_publish" {
  statement {
    sid    = "PublishFlowLogsOnly"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow_logs_publish" {
  name   = "${var.project_name}-vpc-flow-logs-publish"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_publish.json
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.main.id
  traffic_type              = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination           = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn

  tags = {
    Name = "${var.project_name}-vpc-flow-log"
  }
}
