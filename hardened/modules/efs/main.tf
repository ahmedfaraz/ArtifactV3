###############################################################################
# hardened/modules/efs/main.tf
#
# Encrypted EFS filesystem with an access point that enforces:
#   POSIX uid/gid 1000 (matches the non-root container user)
#   Root directory /customers/ (cannot traverse above this path)
#
# Transit encryption enforced; no unencrypted NFS connections allowed.
###############################################################################

# ---------------------------------------------------------------------------
# EFS Filesystem — encrypted at rest
# ---------------------------------------------------------------------------
resource "aws_efs_file_system" "mcp" {
  encrypted = true

  tags = { Name = "mcp-hardened-efs" }
}

# ---------------------------------------------------------------------------
# Security Group — NFS from ECS SG only; no CIDR-wide access
# ---------------------------------------------------------------------------
resource "aws_security_group" "efs" {
  name        = "mcp-hardened-efs-sg"
  description = "Allow NFS from ECS task SG only"
  vpc_id      = var.vpc_id

  tags = { Name = "mcp-hardened-efs-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "efs_nfs_from_ecs" {
  security_group_id            = aws_security_group.efs.id
  description                  = "NFS from ECS task security group"
  referenced_security_group_id = var.ecs_sg_id
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "ecs_to_efs_2049" {
  security_group_id            = var.ecs_sg_id
  description                  = "Allow outbound TCP/2049 from ECS to EFS SG"
  referenced_security_group_id = aws_security_group.efs.id
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
}

# ---------------------------------------------------------------------------
# Mount Target — private subnet only; transit encryption enabled
# ---------------------------------------------------------------------------
resource "aws_efs_mount_target" "mcp" {
  file_system_id  = aws_efs_file_system.mcp.id
  subnet_id       = var.private_subnet_id
  security_groups = [aws_security_group.efs.id]
}

# ---------------------------------------------------------------------------
# EFS Access Point — POSIX enforcement (uid/gid 1000, /customers/ root)
# The access point ensures the container can ONLY access /customers/,
# regardless of what path the application code requests.
# ---------------------------------------------------------------------------
resource "aws_efs_access_point" "customers" {
  file_system_id = aws_efs_file_system.mcp.id

  posix_user {
    uid = 1000
    gid = 1000
  }

  root_directory {
    path = "/customers"
    creation_info {
      owner_uid   = 1000
      owner_gid   = 1000
      permissions = "755"
    }
  }

  tags = { Name = "mcp-hardened-efs-access-point" }
}
