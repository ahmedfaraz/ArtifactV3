output "task_execution_role_arn" {
  description = "ARN of the ECS Task Execution Role (ECR pull + CloudWatch logs)"
  value       = aws_iam_role.task_execution.arn
}

output "task_role_arn" {
  description = "ARN of the ECS Task Role (over-permissive — baseline only)"
  value       = aws_iam_role.task.arn
}
