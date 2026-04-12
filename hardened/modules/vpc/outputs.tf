output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_id" {
  description = "Primary private subnet ID (ECS and primary RDS AZ)"
  value       = aws_subnet.private.id
}

output "secondary_private_subnet_id" {
  description = "Secondary private subnet ID (RDS DB subnet group AZ requirement)"
  value       = aws_subnet.private_secondary.id
}

output "public_subnet_id" {
  description = "Public subnet ID (NAT Gateway only — no ECS tasks here)"
  value       = aws_subnet.public_nat.id
}

output "ecs_sg_id" {
  description = "Hardened ECS task security group ID"
  value       = aws_security_group.ecs.id
}

output "rds_sg_id" {
  description = "RDS security group ID"
  value       = aws_security_group.rds.id
}

output "endpoint_sg_id" {
  description = "VPC Endpoint security group ID"
  value       = aws_security_group.endpoints.id
}

output "private_route_table_id" {
  description = "Private route table ID (associated with private subnets)"
  value       = aws_route_table.private.id
}
