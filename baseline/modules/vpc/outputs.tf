output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "subnet_id" {
  description = "Primary public subnet ID (used by ECS and RDS)"
  value       = aws_subnet.public.id
}

output "secondary_subnet_id" {
  description = "Secondary public subnet ID (used only for RDS DB subnet group AZ requirement)"
  value       = aws_subnet.public_secondary.id
}

output "security_group_id" {
  description = "ECS task security group ID"
  value       = aws_security_group.ecs.id
}
