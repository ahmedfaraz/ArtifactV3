terraform {
  required_version = ">= 1.5"
  backend "local" {}
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------------------------
# VPC — single public subnet, IGW, permissive SG (deliberately misconfigured)
# No VPC Flow Logs. Attack surface: any host can reach TCP/8080.
# ---------------------------------------------------------------------------
module "vpc" {
  source       = "./modules/vpc"
  architecture = "baseline"
  aws_region   = var.aws_region
}

# ---------------------------------------------------------------------------
# IAM — over-permissive task role (wildcard resource — no scoping)
# ---------------------------------------------------------------------------
module "iam" {
  source       = "./modules/iam"
  architecture = "baseline"
}

# ---------------------------------------------------------------------------
# EFS — unencrypted filesystem, world-accessible NFS mount target
# ---------------------------------------------------------------------------
module "efs" {
  source       = "./modules/efs"
  architecture = "baseline"
  vpc_id       = module.vpc.vpc_id
  subnet_id    = module.vpc.subnet_id
  ecs_sg_id    = module.vpc.security_group_id
}

# ---------------------------------------------------------------------------
# RDS — publicly_accessible = true, same public subnet as ECS task
# Timing note: RDS takes 4–8 minutes to become available after apply.
# Do not run seed_secrets.sh or attack scripts until RDS is AVAILABLE.
# ---------------------------------------------------------------------------
module "rds" {
  source       = "./modules/rds"
  architecture = "baseline"
  vpc_id       = module.vpc.vpc_id
  subnet_ids   = [module.vpc.subnet_id, module.vpc.secondary_subnet_id]
  ecs_sg_id    = module.vpc.security_group_id
  db_name      = var.db_name
  db_username  = var.db_username
  db_password  = var.db_password
}

# ---------------------------------------------------------------------------
# ECS — Fargate in public subnet, assign_public_ip=true, runs as root,
# mock credentials passed as plaintext environment variables (M1 attack surface)
# ---------------------------------------------------------------------------
module "ecs" {
  source                  = "./modules/ecs"
  architecture            = "baseline"
  aws_region              = var.aws_region
  vpc_id                  = module.vpc.vpc_id
  subnet_id               = module.vpc.subnet_id
  security_group_id       = module.vpc.security_group_id
  task_execution_role_arn = module.iam.task_execution_role_arn
  task_role_arn           = module.iam.task_role_arn
  efs_id                  = module.efs.efs_id
  db_connection_string    = "postgresql://${var.db_username}:${var.db_password}@${module.rds.rds_endpoint}:${module.rds.rds_port}/${var.db_name}"
}
