variable "architecture" {
  type = string
}

variable "aws_region" {
  description = "AWS region — used in scoped ARN patterns"
  type        = string
}

variable "s3_data_prefix_arn" {
  description = "S3 ARN for the permitted prefix (e.g. arn:aws:s3:::mcp-hardened-data-XXXX/customers/*)"
  type        = string
}

variable "rds_resource_arn" {
  description = "RDS IAM auth ARN for rds-db:connect (arn:aws:rds-db:<region>:<acct>:dbuser:<id>/<user>)"
  type        = string
}
