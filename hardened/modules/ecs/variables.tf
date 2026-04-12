variable "architecture"  { type = string }
variable "aws_region"    { type = string }
variable "vpc_id"        { type = string }

variable "private_subnet_id" { type = string }
variable "ecs_sg_id"         { type = string }

variable "task_execution_role_arn" { type = string }
variable "task_role_arn"           { type = string }

variable "efs_id"               { type = string }
variable "efs_access_point_arn" { type = string }
variable "efs_access_point_id" {
  description = "EFS access point ID — used in efs_volume_configuration authorization_config"
  type        = string
  default     = ""
}

variable "secret_aws_key_id_arn"     { type = string }
variable "secret_aws_secret_key_arn" { type = string }
variable "secret_db_conn_arn"        { type = string }
variable "secret_api_token_arn"      { type = string }

variable "app_log_group_name" {
  description = "CloudWatch log group name for application logs (from logging module)"
  type        = string
}
