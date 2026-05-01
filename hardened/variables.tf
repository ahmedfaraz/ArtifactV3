variable "aws_region" {
  description = "AWS region for all hardened resources"
  type        = string
  default     = "eu-west-1"
}

variable "alert_email" {
  description = "Email address for SNS CloudWatch alarm notifications (leave empty to skip subscription)"
  type        = string
  default     = ""
}

variable "db_name" {
  description = "RDS PostgreSQL database name"
  type        = string
  default     = "mockdb"
}

variable "db_username" {
  description = "RDS PostgreSQL master username"
  type        = string
  default     = "mcpuser"
}

# No default value — must be supplied via tfvars or environment variable.
# No mock plaintext values in hardened/. Use AWS Secrets Manager at runtime.
variable "db_password" {
  description = "RDS PostgreSQL master password (supply via TF_VAR_db_password or terraform.tfvars)"
  type        = string
  sensitive   = true
}

variable "key_name" {
  description = "AWS EC2 key pair name for SSH access to the attacker EC2"
  type        = string
  default     = "mcp-lab-key"
}
