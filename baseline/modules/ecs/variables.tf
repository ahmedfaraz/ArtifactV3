variable "architecture" {
  description = "Architecture label used in resource Name tags (baseline)"
  type        = string
}

variable "aws_region" {
  description = "AWS region — used in CloudWatch log configuration"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_id" {
  description = "Public subnet ID for the ECS task"
  type        = string
}

variable "security_group_id" {
  description = "Security group ID attached to the ECS task"
  type        = string
}

variable "task_execution_role_arn" {
  description = "ARN of the ECS task execution role (ECR pull + CloudWatch)"
  type        = string
}

variable "task_role_arn" {
  description = "ARN of the ECS task role (over-permissive — baseline only)"
  type        = string
}

variable "efs_id" {
  description = "EFS filesystem ID to mount at /mnt/data"
  type        = string
}

variable "db_connection_string" {
  description = "PostgreSQL connection string injected as plaintext env var (mock value)"
  type        = string
  sensitive   = true
}
