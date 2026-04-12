output "ecs_cluster_name" {
  value = aws_ecs_cluster.mcp.name
}

output "ecs_service_name" {
  value = aws_ecs_service.mcp.name
}

output "task_private_ip" {
  description = "Private IP of the running ECS task — used by attacker EC2 in run_all.sh"
  value       = data.external.task_ip.result.private_ip
}

output "ecr_repository_url" {
  description = "ECR repository URL. Push mcp_server_hardened image here."
  value       = aws_ecr_repository.mcp.repository_url
}
