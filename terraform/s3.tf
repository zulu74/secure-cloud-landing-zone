# s3.tf
# A bucket configured the way every "S3 bucket left open to the
# internet" headline wishes it had been: encrypted at rest, versioned,
# fully blocked from public access, and shipping its own access logs.
#
# The logs bucket gets the SAME hardening as the data bucket — a log
# bucket left open/unencrypted is its own finding, and checkov (rightly)
# flags it if you harden only the "primary" bucket and forget the one
# collecting its access history.

resource "aws_s3_bucket" "logs" {
  bucket        = "${var.project_name}-access-logs"
  force_destroy = var.allowed_log_bucket_force_destroy

  tags = {
    Name    = "${var.project_name}-access-logs"
    Purpose = "server-access-logging"
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "${var.project_name}-data"

  tags = {
    Name        = "${var.project_name}-data"
    Environment = var.environment
  }
}

# --- versioning (CKV_AWS_21) --------------------------------------------

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# --- encryption (CKV_AWS_145) --------------------------------------------

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# --- public access block (CKV2_AWS_6) ------------------------------------

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- lifecycle management (CKV2_AWS_61) -----------------------------------
# Expire old object versions rather than let a versioned bucket grow
# forever — a real cost/ops control, not just a security checkbox.

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# --- access logging ---------------------------------------------------

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "data-bucket-access-logs/"
}

# --- deliberately accepted findings ---------------------------------------
# checkov also flags CKV_AWS_144 (cross-region replication) and
# CKV2_AWS_62 (event notifications) for both buckets. Both are real
# best practices for production — but out of scope for a single-region
# dev/demo landing zone with no downstream consumer for event
# notifications to call. Documenting *why* a finding is accepted,
# instead of silently suppressing it, is the actual governance practice;
# see .checkov.yaml for the scoped skip with justification.
