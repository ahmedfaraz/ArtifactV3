variable "aws_region" {
  description = "AWS region for all baseline resources"
  type        = string
  default     = "eu-west-1"
}

variable "db_name" {
  description = "RDS PostgreSQL database name (mock)"
  type        = string
  default     = "mockdb"
}

variable "db_username" {
  description = "RDS PostgreSQL master username (mock)"
  type        = string
  default     = "mcpuser"
}

# MOCK VALUE — intentionally weak for baseline demonstration.
# Per global constraints, mock credential values are permitted only in
# baseline/ and baseline/mock_data/. Do NOT copy to hardened/.
variable "db_password" {
  description = "RDS PostgreSQL master password (mock — baseline only)"
  type        = string
  default     = "FAKEPASSWORD123"
  sensitive   = true
}
