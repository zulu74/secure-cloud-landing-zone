# outputs.tf

output "vpc_id" {
  value = aws_vpc.main.id
}

output "data_bucket_name" {
  value = aws_s3_bucket.data.bucket
}

output "app_role_arn" {
  value = aws_iam_role.app_role.arn
}
