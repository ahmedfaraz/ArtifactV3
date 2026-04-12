output "efs_id" {
  description = "EFS filesystem ID. DNS name: <efs_id>.efs.<region>.amazonaws.com"
  value       = aws_efs_file_system.mcp.id
}
