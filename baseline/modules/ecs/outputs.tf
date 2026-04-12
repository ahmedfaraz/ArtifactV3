output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.mcp.name
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.mcp.name
}

output "task_public_ip" {
  description = <<-EOT
    Public IP of the running ECS task.
    Returns "unavailable-push-image-and-reapply" if the task is not yet running.
    Cause: Docker image not yet pushed to ECR. Resolution:
      docker build -t <ecr_url>:latest mcp_server/
      aws ecr get-login-password | docker login --username AWS --password-stdin <ecr_url>
      docker push <ecr_url>:latest
      terraform apply
  EOT
  value       = data.external.task_ip.result.public_ip
}

output "ecr_repository_url" {
  description = "ECR repository URL for the mcp-server image"
  value       = aws_ecr_repository.mcp.repository_url
}
