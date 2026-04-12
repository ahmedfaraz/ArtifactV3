output "efs_id" {
  value = aws_efs_file_system.mcp.id
}

output "efs_access_point_arn" {
  description = "EFS access point ARN — referenced in the ECS task definition volume config"
  value       = aws_efs_access_point.customers.arn
}

output "efs_access_point_id" {
  value = aws_efs_access_point.customers.id
}
