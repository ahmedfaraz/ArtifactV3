output "rds_endpoint" {
  description = "RDS instance endpoint hostname (without port)"
  value       = aws_db_instance.mcp.address
}

output "rds_port" {
  description = "RDS instance port"
  value       = aws_db_instance.mcp.port
}
