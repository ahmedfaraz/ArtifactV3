variable "architecture" { type = string }
variable "aws_region"   { type = string }

variable "task_role_arn" {
  description = "ECS task role ARN - permitted to call GetSecretValue at runtime"
  type        = string
}

variable "task_execution_role_arn" {
  description = "ECS task execution role ARN - permitted to call GetSecretValue at task startup for secret injection"
  type        = string
}
