output "role_name" {
  value = aws_iam_role.reporting.name
}

output "role_arn" {
  value = aws_iam_role.reporting.arn
}

output "bucket_name" {
  value = aws_s3_bucket.reports.id
}

output "bucket_arn" {
  value = aws_s3_bucket.reports.arn
}
