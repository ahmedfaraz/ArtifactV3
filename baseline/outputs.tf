output "vpc_id" {
  description = "ID of the baseline VPC"
  value       = module.vpc.vpc_id
}

output "subnet_id" {
  description = "ID of the primary public subnet"
  value       = module.vpc.subnet_id
}

output "security_group_id" {
  description = "ID of the ECS task security group"
  value       = module.vpc.security_group_id
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = module.ecs.ecs_cluster_name
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = module.ecs.ecs_service_name
}

output "task_public_ip" {
  description = <<-EOT
    Public IP of the running ECS task.
    If this returns "unavailable", the task is not yet running.
    Ensure the Docker image has been built and pushed to ECR, then
    re-run: terraform apply
    Manual retrieval: aws ecs list-tasks --cluster <cluster> --region <region>
  EOT
  value       = module.ecs.task_public_ip
}

output "ecr_repository_url" {
  description = "ECR repository URL. Push the mcp_server image here before starting the ECS task."
  value       = module.ecs.ecr_repository_url
}

output "rds_endpoint" {
  description = "RDS instance endpoint hostname"
  value       = module.rds.rds_endpoint
}

output "rds_port" {
  description = "RDS instance port"
  value       = module.rds.rds_port
}

output "efs_id" {
  description = "EFS filesystem ID"
  value       = module.efs.efs_id
}

output "efs_dns_name" {
  description = "EFS mount DNS name. Export as EFS_DNS_NAME before running seed_secrets.sh"
  value       = "${module.efs.efs_id}.efs.${var.aws_region}.amazonaws.com"
}
