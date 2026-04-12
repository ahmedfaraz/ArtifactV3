variable "architecture" {
  description = "Architecture label used in resource Name tags (hardened)"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "bucket_suffix" {
  description = "4-character hex suffix for the CloudTrail S3 bucket name (from random_id.bucket_suffix.hex)"
  type        = string
}

variable "alert_email" {
  description = "Email address for SNS alarm subscription. Empty string disables the subscription."
  type        = string
  default     = ""
}
