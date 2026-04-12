###############################################################################
# baseline/modules/rds/main.tf
#
# Publicly-accessible RDS PostgreSQL instance in the public subnet.
# Attack surface: port 5432 reachable from the internet via the ECS SG,
# and publicly_accessible = true allows direct external connections.
# Timing note: RDS takes 4–8 minutes to reach AVAILABLE after terraform apply.
###############################################################################

# ---------------------------------------------------------------------------
# RDS Security Group — allows port 5432 from ECS task SG
# ---------------------------------------------------------------------------
resource "aws_security_group" "rds" {
  name        = "mcp-baseline-rds-sg"
  description = "Allow PostgreSQL from ECS task security group"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from ECS task"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.ecs_sg_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mcp-baseline-rds-sg"
  }
}

# ---------------------------------------------------------------------------
# DB Subnet Group — requires ≥ 2 subnets in different AZs (AWS requirement)
# ---------------------------------------------------------------------------
resource "aws_db_subnet_group" "mcp" {
  name        = "mcp-baseline-db-subnet-group"
  description = "Baseline RDS subnet group (primary + secondary AZ)"
  subnet_ids  = var.subnet_ids

  tags = {
    Name = "mcp-baseline-db-subnet-group"
  }
}

# ---------------------------------------------------------------------------
# RDS PostgreSQL instance
# publicly_accessible = true — intentional baseline misconfiguration.
# mock credentials are set via variables; values match seed_secrets.sh.
# ---------------------------------------------------------------------------
resource "aws_db_instance" "mcp" {
  identifier        = "mcp-baseline-rds"
  engine            = "postgres"
  engine_version    = "15"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_type      = "gp2"

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.mcp.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  publicly_accessible = true   # intentional — baseline attack surface
  multi_az            = false
  storage_encrypted   = false  # intentional — no encryption at rest (baseline)

  skip_final_snapshot = true
  deletion_protection = false

  tags = {
    Name = "mcp-baseline-rds"
  }
}
