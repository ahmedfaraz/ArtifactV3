variable "architecture" {
  description = "Architecture label (hardened)"
  type        = string
}

variable "aws_region" {
  description = "AWS region — used in VPC endpoint service names"
  type        = string
}

variable "flow_log_group_arn" {
  description = "ARN of the CloudWatch log group for VPC Flow Logs (from logging module)"
  type        = string
}

variable "flow_log_delivery_role_arn" {
  description = "ARN of the IAM role that delivers VPC Flow Logs to CloudWatch (from logging module)"
  type        = string
}
