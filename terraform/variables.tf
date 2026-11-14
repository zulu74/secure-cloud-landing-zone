# variables.tf

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Short name used as a prefix for all resources, for tagging and naming."
  type        = string
  default     = "secure-landing-zone"
}

variable "environment" {
  description = "Deployment environment name (dev/staging/prod)."
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for the landing zone VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "allowed_log_bucket_force_destroy" {
  description = "Allow Terraform to destroy the log bucket even if it has objects in it. Keep false outside of local/dev testing."
  type        = bool
  default     = true
}
