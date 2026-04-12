variable "architecture" {
  description = "Architecture label used in resource Name tags (baseline)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID in which to create the EFS security group"
  type        = string
}

variable "subnet_id" {
  description = "Primary public subnet ID for the EFS mount target"
  type        = string
}

variable "ecs_sg_id" {
  description = "ECS task security group ID — granted NFS access to EFS"
  type        = string
}
