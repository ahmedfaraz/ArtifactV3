###############################################################################
# hardened/modules/rds/main.tf
#
# Private RDS PostgreSQL instance:
#   - publicly_accessible = false
#   - storage_encrypted   = true
#   - placed in private subnets
#   - accessible only from the ECS security group (via rds_sg_id from VPC module)
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# RDS SG is provisioned in the VPC module and its ID passed here as ecs_sg_id
# is used to scope the ingress rule.  The actual SG resource lives in vpc/main.tf.

# ---------------------------------------------------------------------------
# DB Subnet Group — two private subnets in different AZs (AWS requirement)
# ---------------------------------------------------------------------------
resource "aws_db_subnet_group" "mcp" {
  name        = "mcp-hardened-db-subnet-group"
  description = "Hardened RDS subnet group (private subnets only)"
  subnet_ids  = var.subnet_ids

  tags = { Name = "mcp-hardened-db-subnet-group" }
}

# ---------------------------------------------------------------------------
# RDS PostgreSQL instance — private, encrypted, IAM auth enabled
# ---------------------------------------------------------------------------
resource "aws_db_instance" "mcp" {
  identifier        = "mcp-hardened-rds"
  engine            = "postgres"
  engine_version    = "15"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_type      = "gp2"

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.mcp.name
  vpc_security_group_ids = [var.rds_sg_id]

  publicly_accessible    = false  # hardened: no public access
  multi_az               = false
  storage_encrypted      = true   # hardened: encryption at rest
  iam_database_authentication_enabled = true  # enables rds-db:connect policy

  skip_final_snapshot = true
  deletion_protection = false

  tags = { Name = "mcp-hardened-rds" }
}
