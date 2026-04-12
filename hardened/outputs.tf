output "vpc_id" {
  description = "Hardened VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnet_id" {
  description = "Private subnet ID (ECS tasks and RDS)"
  value       = module.vpc.private_subnet_id
}

output "ecs_cluster_name" {
  description = "Hardened ECS cluster name"
  value       = module.ecs.ecs_cluster_name
}

output "ecs_service_name" {
  description = "Hardened ECS service name"
  value       = module.ecs.ecs_service_name
}

output "task_private_ip" {
  description = <<-EOT
    Private IP of the running ECS task (used by attacker EC2 in run_all.sh).
    Returns "unavailable-push-image-and-reapply" if task not yet running.
  EOT
  value       = module.ecs.task_private_ip
}

output "ecr_repository_url" {
  description = "ECR repository URL. Push mcp_server_hardened image here before running attacks."
  value       = module.ecs.ecr_repository_url
}

output "rds_endpoint" {
  description = "RDS instance endpoint (private — not publicly accessible)"
  value       = module.rds.rds_endpoint
}

output "efs_id" {
  description = "Encrypted EFS filesystem ID"
  value       = module.efs.efs_id
}

output "efs_dns_name" {
  description = "EFS mount DNS name. Export as EFS_DNS_NAME before running seed_secrets_hardened.sh"
  value       = "${module.efs.efs_id}.efs.${var.aws_region}.amazonaws.com"
}

output "cloudtrail_bucket" {
  description = "S3 bucket name for CloudTrail logs"
  value       = module.logging.cloudtrail_bucket_name
}

output "sns_topic_arn" {
  description = "SNS topic ARN for secret-access alarms"
  value       = module.logging.sns_topic_arn
}
