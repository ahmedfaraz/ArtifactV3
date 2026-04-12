###############################################################################
# baseline/modules/efs/main.tf
#
# Unencrypted EFS filesystem for the baseline architecture.
# Mount target accessible from the ECS SG and the VPC CIDR (for seeding).
# No encryption at rest, no access points, no POSIX uid enforcement.
# This stores credentials.env + mock_customers.csv seeded by seed_secrets.sh.
###############################################################################

# ---------------------------------------------------------------------------
# EFS Filesystem — unencrypted (baseline; no encryption at rest)
# ---------------------------------------------------------------------------
resource "aws_efs_file_system" "mcp" {
  encrypted = false

  tags = {
    Name = "mcp-baseline-efs"
  }
}

# ---------------------------------------------------------------------------
# Security Group for the EFS mount target
# Allows TCP/2049 (NFS) from:
#   - The ECS task SG (runtime access by the container)
#   - The VPC CIDR 10.0.0.0/16 (allows seed_secrets.sh run from within VPC)
# ---------------------------------------------------------------------------
resource "aws_security_group" "efs" {
  name        = "mcp-baseline-efs-sg"
  description = "Allow NFS from ECS task and VPC CIDR for seeding"
  vpc_id      = var.vpc_id

  ingress {
    description     = "NFS from ECS task security group"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [var.ecs_sg_id]
  }

  ingress {
    description = "NFS from VPC CIDR (for seed_secrets.sh)"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mcp-baseline-efs-sg"
  }
}

# ---------------------------------------------------------------------------
# EFS Mount Target — in the primary public subnet
# Timing note: Mount targets take ~90 seconds to reach the "available" state
# after terraform apply. Do not run seed_secrets.sh until the mount target
# is confirmed available.
# ---------------------------------------------------------------------------
resource "aws_efs_mount_target" "mcp" {
  file_system_id  = aws_efs_file_system.mcp.id
  subnet_id       = var.subnet_id
  security_groups = [aws_security_group.efs.id]
}
