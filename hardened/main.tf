terraform {
  required_version = ">= 1.5"
  backend "local" {}
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
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
# Random suffix for S3 bucket names (global constraint: 4 hex chars)
# ---------------------------------------------------------------------------
resource "random_id" "bucket_suffix" {
  byte_length = 2
}

# ---------------------------------------------------------------------------
# S3 data bucket — scoped in the file_reader IAM policy (least-privilege)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "data" {
  bucket = "mcp-hardened-data-${random_id.bucket_suffix.hex}"
  tags   = { Name = "mcp-hardened-s3-data" }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}

# ---------------------------------------------------------------------------
# MODULE CALL ORDER: vpc → iam → efs → rds → secrets → logging → ecs
#
# NOTE: The vpc module references module.logging outputs (flow log group ARN
# and delivery role ARN).  Terraform resolves the actual execution order via
# the dependency graph — logging is applied before vpc despite appearing later
# in this file.  The source-code order reflects the logical data flow and
# the required depends_on relationship documented in the dissertation.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# VPC — private subnet, NAT GW, Flow Logs, VPC Endpoints
# Depends on logging outputs for flow log delivery (see NOTE above).
# ---------------------------------------------------------------------------
module "vpc" {
  source       = "./modules/vpc"
  architecture = "hardened"
  aws_region   = var.aws_region

  flow_log_group_arn         = module.logging.flow_log_group_arn
  flow_log_delivery_role_arn = module.logging.flow_log_delivery_role_arn
}

# ---------------------------------------------------------------------------
# IAM — least-privilege per-tool attached policies (no inline)
# ---------------------------------------------------------------------------
module "iam" {
  source       = "./modules/iam"
  architecture = "hardened"
  aws_region   = var.aws_region

  s3_data_prefix_arn = "${aws_s3_bucket.data.arn}/customers/*"
  rds_resource_arn   = module.rds.rds_resource_arn
}

# ---------------------------------------------------------------------------
# EFS — encrypted, access point with POSIX uid 1000
# ---------------------------------------------------------------------------
module "efs" {
  source            = "./modules/efs"
  architecture      = "hardened"
  vpc_id            = module.vpc.vpc_id
  private_subnet_id = module.vpc.private_subnet_id
  ecs_sg_id         = module.vpc.ecs_sg_id
}

# ---------------------------------------------------------------------------
# RDS — private subnet, not publicly accessible
# ---------------------------------------------------------------------------
module "rds" {
  source       = "./modules/rds"
  architecture = "hardened"
  aws_region   = var.aws_region
  vpc_id       = module.vpc.vpc_id
  subnet_ids   = [module.vpc.private_subnet_id, module.vpc.secondary_private_subnet_id]
  ecs_sg_id    = module.vpc.ecs_sg_id
  rds_sg_id    = module.vpc.rds_sg_id
  db_name      = var.db_name
  db_username  = var.db_username
  db_password  = var.db_password
}

# ---------------------------------------------------------------------------
# Secrets — Secrets Manager resources + resource-based Deny policies
# ---------------------------------------------------------------------------
module "secrets" {
  source                  = "./modules/secrets"
  architecture            = "hardened"
  aws_region              = var.aws_region
  task_role_arn           = module.iam.task_role_arn
  task_execution_role_arn = module.iam.task_execution_role_arn
}

# ---------------------------------------------------------------------------
# Logging — CloudTrail, CloudWatch log groups, metric filter, alarm, SNS
# MUST be provisioned before ECS (ecs depends_on this module below).
# ---------------------------------------------------------------------------
module "logging" {
  source        = "./modules/logging"
  architecture  = "hardened"
  aws_region    = var.aws_region
  bucket_suffix = random_id.bucket_suffix.hex
  alert_email   = var.alert_email
}

# ---------------------------------------------------------------------------
# ECS — hardened task definition (private subnet, no public IP,
#        readonlyRootFilesystem, uid 1000, Secrets Manager refs)
#
# depends_on module.logging is MANDATORY: ensures all CloudWatch log groups
# exist before the first ECS task starts, eliminating the detection blind
# spot during container startup (see dissertation §4.3).
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Attacker EC2 — public subnet, reaches private ECS task via VPC routing.
# ECS SG already allows inbound 8080 from VPC CIDR (10.0.0.0/16).
# ---------------------------------------------------------------------------
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_security_group" "attacker" {
  name        = "mcp-hardened-attacker-sg"
  description = "Attacker EC2 - SSH inbound, all outbound"
  vpc_id      = module.vpc.vpc_id
  tags        = { Name = "mcp-hardened-attacker-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "attacker_ssh" {
  security_group_id = aws_security_group.attacker.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "attacker_all_out" {
  security_group_id = aws_security_group.attacker.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_instance" "attacker" {
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = "t3.micro"
  subnet_id                   = module.vpc.public_subnet_id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.attacker.id]
  key_name                    = var.key_name

  user_data = <<-EOF
    #!/bin/bash
    dnf install -y python3-pip git
    pip3 install boto3 "mcp[cli]"
  EOF

  tags = { Name = "mcp-hardened-attacker-ec2" }
}

module "ecs" {
  source       = "./modules/ecs"
  architecture = "hardened"
  aws_region   = var.aws_region

  vpc_id            = module.vpc.vpc_id
  private_subnet_id = module.vpc.private_subnet_id
  ecs_sg_id         = module.vpc.ecs_sg_id

  task_execution_role_arn = module.iam.task_execution_role_arn
  task_role_arn           = module.iam.task_role_arn

  efs_id               = module.efs.efs_id
  efs_access_point_arn = module.efs.efs_access_point_arn
  efs_access_point_id  = module.efs.efs_access_point_id

  secret_aws_key_id_arn     = module.secrets.aws_access_key_secret_arn
  secret_aws_secret_key_arn = module.secrets.aws_secret_key_secret_arn
  secret_db_conn_arn        = module.secrets.db_connection_secret_arn
  secret_api_token_arn      = module.secrets.api_token_secret_arn

  app_log_group_name = module.logging.app_log_group_name

  depends_on = [module.logging]
}
