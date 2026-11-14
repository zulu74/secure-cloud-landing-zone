# iam.tf
# Least-privilege IAM: an application role that can only read/write
# objects in the one bucket it owns, with no wildcard actions and no
# wildcard resources — the opposite of the "AdministratorAccess
# attached to everything" pattern that shows up in most breach
# post-mortems.

data "aws_iam_policy_document" "app_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app_role" {
  name               = "${var.project_name}-app-role"
  assume_role_policy = data.aws_iam_policy_document.app_assume_role.json

  tags = {
    Name = "${var.project_name}-app-role"
  }
}

data "aws_iam_policy_document" "app_s3_access" {
  statement {
    sid    = "ReadWriteOwnBucketOnly"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.data.arn,
      "${aws_s3_bucket.data.arn}/*",
    ]
  }

  statement {
    sid    = "WriteLogsOnly"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:*:log-group:/${var.project_name}/*"]
  }
}

resource "aws_iam_policy" "app_s3_access" {
  name   = "${var.project_name}-app-s3-access"
  policy = data.aws_iam_policy_document.app_s3_access.json
}

resource "aws_iam_role_policy_attachment" "app_s3_access" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.app_s3_access.arn
}
