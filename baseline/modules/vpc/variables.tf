variable "architecture" {
  description = "Architecture label used in resource Name tags (baseline)"
  type        = string
}

variable "aws_region" {
  description = "AWS region — used for tagging and AZ selection"
  type        = string
}
