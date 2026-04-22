###############################################################################
# baseline/modules/vpc/main.tf
#
# Deliberately misconfigured VPC for the pre-control baseline.
# Attack surface: inbound TCP/8080 open to 0.0.0.0/0 and ::/0.
# No VPC Flow Logs — provides no network visibility (supports M3 baseline).
###############################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

# ---------------------------------------------------------------------------
# VPC
# ---------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "mcp-baseline-vpc"
  }
}

# ---------------------------------------------------------------------------
# Primary public subnet — used by ECS task and RDS instance
# CIDR: 10.0.0.0/24  AZ: first available
# ---------------------------------------------------------------------------
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.0.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "mcp-baseline-subnet-public"
  }
}

# ---------------------------------------------------------------------------
# Secondary public subnet — required by RDS DB subnet group (≥ 2 AZs)
# CIDR: 10.0.3.0/24  AZ: second available
# Not used for any compute; exists solely to satisfy the AWS requirement.
# ---------------------------------------------------------------------------
resource "aws_subnet" "public_secondary" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true

  tags = {
    Name = "mcp-baseline-subnet-public-secondary"
  }
}

# ---------------------------------------------------------------------------
# Internet Gateway
# ---------------------------------------------------------------------------
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "mcp-baseline-igw"
  }
}

# ---------------------------------------------------------------------------
# Public Route Table — 0.0.0.0/0 → IGW
# ---------------------------------------------------------------------------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "mcp-baseline-rt-public"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_secondary" {
  subnet_id      = aws_subnet.public_secondary.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# ECS Task Security Group
# INTENTIONALLY PERMISSIVE — inbound TCP/8080 from all IPv4 and IPv6.
# This is the primary M1 attack surface for the baseline scenario.
# ---------------------------------------------------------------------------
resource "aws_security_group" "ecs" {
  name        = "mcp-baseline-ecs-sg"
  description = "Baseline ECS task SG - inbound 8080 open to world (intentional)"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow inbound TCP/8080 from all IPv4 (attack surface)"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description      = "Allow inbound TCP/8080 from all IPv6 (attack surface)"
    from_port        = 8080
    to_port          = 8080
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mcp-baseline-ecs-sg"
  }
}
