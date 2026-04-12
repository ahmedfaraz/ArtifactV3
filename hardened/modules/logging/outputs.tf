output "app_log_group_name" {
  description = "CloudWatch log group name for ECS application logs"
  value       = aws_cloudwatch_log_group.app_logs.name
}

output "app_log_group_arn" {
  description = "CloudWatch log group ARN for ECS application logs"
  value       = aws_cloudwatch_log_group.app_logs.arn
}

output "flow_log_group_arn" {
  description = "CloudWatch log group ARN for VPC Flow Logs — passed to vpc module"
  value       = aws_cloudwatch_log_group.flow_logs.arn
}

output "flow_log_group_name" {
  description = "CloudWatch log group name for VPC Flow Logs"
  value       = aws_cloudwatch_log_group.flow_logs.name
}

output "flow_log_delivery_role_arn" {
  description = "IAM role ARN for VPC Flow Log delivery to CloudWatch — passed to vpc module"
  value       = aws_iam_role.flow_log_delivery.arn
}

output "cloudtrail_bucket_name" {
  description = "S3 bucket name for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail.bucket
}

output "cloudtrail_bucket_arn" {
  description = "S3 bucket ARN for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail.arn
}

output "sns_topic_arn" {
  description = "SNS topic ARN for security alerts"
  value       = aws_sns_topic.alerts.arn
}
