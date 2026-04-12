variable "architecture" { type = string }
variable "vpc_id" { type = string }

variable "private_subnet_id" {
  description = "Primary private subnet ID for the EFS mount target"
  type        = string
}

variable "ecs_sg_id" {
  description = "ECS task security group ID — only source granted NFS access"
  type        = string
}
