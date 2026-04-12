output "rds_endpoint" {
  description = "RDS instance endpoint hostname (private — not publicly accessible)"
  value       = aws_db_instance.mcp.address
}

output "rds_port" {
  value = aws_db_instance.mcp.port
}

output "rds_resource_arn" {
  description = "ARN for rds-db:connect IAM policy — scoped to this instance's resource ID and db username"
  value       = "arn:aws:rds-db:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.mcp.resource_id}/${var.db_username}"
}
