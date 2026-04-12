variable "architecture" {
  description = "Architecture label used in resource Name tags (baseline)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the DB subnet group (requires ≥ 2 different AZs)"
  type        = list(string)
}

variable "ecs_sg_id" {
  description = "ECS task security group ID — granted PostgreSQL access"
  type        = string
}

# MOCK VALUE — intentionally weak for baseline demonstration only.
variable "db_name" {
  description = "RDS database name (mock)"
  type        = string
  default     = "mockdb"
}

# MOCK VALUE — intentionally weak for baseline demonstration only.
variable "db_username" {
  description = "RDS master username (mock)"
  type        = string
  default     = "mcpuser"
}

# MOCK VALUE — appears in credentials.env and as plaintext ECS env var.
# Pattern-matched by attack scripts. Do NOT use in hardened/.
variable "db_password" {
  description = "RDS master password (mock — baseline only)"
  type        = string
  default     = "FAKEPASSWORD123"
  sensitive   = true
}
