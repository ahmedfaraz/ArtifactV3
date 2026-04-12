variable "architecture" { type = string }
variable "aws_region"   { type = string }

variable "task_role_arn" {
  description = "ECS task role ARN — the ONLY principal permitted to call GetSecretValue"
  type        = string
}
