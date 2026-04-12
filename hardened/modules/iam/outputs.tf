output "task_execution_role_arn" {
  value = aws_iam_role.task_execution.arn
}

output "task_role_arn" {
  value = aws_iam_role.task.arn
}

output "task_role_name" {
  description = "Task role name — used when checking resource policies in the secrets module"
  value       = aws_iam_role.task.name
}
