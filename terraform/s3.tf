# s3.tf
# A bucket configured the way every "S3 bucket left open to the
# internet" headline wishes it had been: encrypted at rest, versioned,
# fully blocked from public access, and shipping its own access logs.

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

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "data-bucket-access-logs/"
}
