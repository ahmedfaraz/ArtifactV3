variable "architecture" { type = string }
variable "aws_region"   { type = string }
variable "vpc_id"       { type = string }

variable "subnet_ids" {
  description = "List of private subnet IDs for the DB subnet group (≥ 2 AZs required)"
  type        = list(string)
}

variable "ecs_sg_id" {
  description = "ECS task security group ID"
  type        = string
}

variable "rds_sg_id" {
  description = "RDS security group ID (created in vpc module)"
  type        = string
  default     = ""
}

variable "db_name" {
  type    = string
  default = "mockdb"
}

variable "db_username" {
  type    = string
  default = "mcpuser"
}

variable "db_password" {
  type      = string
  sensitive = true
}
