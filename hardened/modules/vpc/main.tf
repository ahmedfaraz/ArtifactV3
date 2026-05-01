###############################################################################
# hardened/modules/vpc/main.tf
#
# Hardened network topology:
#   Private subnet  10.0.1.0/24  (AZ[0]) — ECS tasks and RDS primary
#   Private subnet  10.0.4.0/24  (AZ[1]) — RDS secondary (multi-AZ requirement)
#   Public  subnet  10.0.2.0/24  (AZ[0]) — NAT Gateway only; no ECS here
#
# ECS Security Group — inbound 8080 from VPC CIDR only; outbound scoped to
#   VPC Endpoint SG (443) and RDS SG (5432); no 0.0.0.0/0 egress.
#
# VPC Flow Logs delivered to the CloudWatch log group created in logging module.
# VPC Interface Endpoints: secretsmanager, ecr.api, ecr.dkr, logs
# VPC Gateway Endpoint: s3
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

  tags = { Name = "mcp-hardened-vpc" }
}

# ---------------------------------------------------------------------------
# Subnets
# ---------------------------------------------------------------------------
resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = { Name = "mcp-hardened-subnet-private" }
}

resource "aws_subnet" "private_secondary" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.4.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false

  tags = { Name = "mcp-hardened-subnet-private-secondary" }
}

resource "aws_subnet" "public_nat" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = { Name = "mcp-hardened-subnet-public-nat" }
}

# ---------------------------------------------------------------------------
# Internet Gateway (needed for NAT Gateway only)
# ---------------------------------------------------------------------------
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "mcp-hardened-igw" }
}

# ---------------------------------------------------------------------------
# NAT Gateway + Elastic IP
# ---------------------------------------------------------------------------
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "mcp-hardened-nat-eip" }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_nat.id

  tags       = { Name = "mcp-hardened-nat-gw" }
  depends_on = [aws_internet_gateway.main]
}

# ---------------------------------------------------------------------------
# Route Tables
# ---------------------------------------------------------------------------

# Public route table — IGW for NAT subnet
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "mcp-hardened-rt-public" }
}

resource "aws_route_table_association" "public_nat" {
  subnet_id      = aws_subnet.public_nat.id
  route_table_id = aws_route_table.public.id
}

# Private route table — default route via NAT GW
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = { Name = "mcp-hardened-rt-private" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_secondary" {
  subnet_id      = aws_subnet.private_secondary.id
  route_table_id = aws_route_table.private.id
}

# ---------------------------------------------------------------------------
# Security Groups
# ---------------------------------------------------------------------------

# Endpoint SG — inbound TCP/443 from ECS SG only; no explicit egress rules
# (implicit deny; return traffic is stateful and does not need egress rules)
resource "aws_security_group" "endpoints" {
  name        = "mcp-hardened-endpoints-sg"
  description = "VPC Endpoints - inbound 443 from ECS SG only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "mcp-hardened-endpoints-sg" }
}

# RDS SG — provisioned here so ECS SG can reference it
resource "aws_security_group" "rds" {
  name        = "mcp-hardened-rds-sg"
  description = "RDS - inbound 5432 from ECS SG only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "mcp-hardened-rds-sg" }
}

# ECS SG — must be created after endpoint and rds SGs (referenced in egress)
resource "aws_security_group" "ecs" {
  name        = "mcp-hardened-ecs-sg"
  description = "Hardened ECS - inbound 8080 from VPC CIDR; outbound scoped"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "mcp-hardened-ecs-sg" }
}

# ----- ECS ingress -----
resource "aws_vpc_security_group_ingress_rule" "ecs_8080_from_vpc" {
  security_group_id = aws_security_group.ecs.id
  description       = "Allow inbound TCP/8080 from VPC CIDR only"
  cidr_ipv4         = "10.0.0.0/16"
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
}

data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${var.aws_region}.s3"
}

# ----- ECS egress — TCP/443 to S3 Gateway Endpoint (ECR image layer blobs) -----
resource "aws_vpc_security_group_egress_rule" "ecs_to_s3_443" {
  security_group_id = aws_security_group.ecs.id
  description       = "Allow outbound TCP/443 to S3 Gateway Endpoint for ECR image layers"
  prefix_list_id    = data.aws_prefix_list.s3.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# ----- ECS egress — TCP/443 to endpoint SG -----
resource "aws_vpc_security_group_egress_rule" "ecs_to_endpoints_443" {
  security_group_id            = aws_security_group.ecs.id
  description                  = "Allow outbound TCP/443 to VPC Endpoint SG (ECR, SM, CW)"
  referenced_security_group_id = aws_security_group.endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

# ----- ECS egress — TCP/5432 to RDS SG -----
resource "aws_vpc_security_group_egress_rule" "ecs_to_rds_5432" {
  security_group_id            = aws_security_group.ecs.id
  description                  = "Allow outbound TCP/5432 to RDS SG"
  referenced_security_group_id = aws_security_group.rds.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# ----- Endpoint ingress — TCP/443 from ECS SG -----
resource "aws_vpc_security_group_ingress_rule" "endpoints_443_from_ecs" {
  security_group_id            = aws_security_group.endpoints.id
  description                  = "Allow inbound TCP/443 from ECS SG"
  referenced_security_group_id = aws_security_group.ecs.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

# ----- RDS ingress — TCP/5432 from ECS SG -----
resource "aws_vpc_security_group_ingress_rule" "rds_5432_from_ecs" {
  security_group_id            = aws_security_group.rds.id
  description                  = "Allow inbound TCP/5432 from ECS SG"
  referenced_security_group_id = aws_security_group.ecs.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# ---------------------------------------------------------------------------
# VPC Flow Logs → CloudWatch (log group + delivery role from logging module)
# ---------------------------------------------------------------------------
resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = var.flow_log_delivery_role_arn
  log_destination = var.flow_log_group_arn

  tags = { Name = "mcp-hardened-flow-log" }
}

# ---------------------------------------------------------------------------
# VPC Interface Endpoints
# ---------------------------------------------------------------------------
resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = { Name = "mcp-hardened-vpce-secretsmanager" }
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = { Name = "mcp-hardened-vpce-ecr-api" }
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = { Name = "mcp-hardened-vpce-ecr-dkr" }
}

resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = { Name = "mcp-hardened-vpce-logs" }
}

# ---------------------------------------------------------------------------
# S3 Gateway Endpoint — route table association (no SG needed for gateway type)
# ---------------------------------------------------------------------------
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "mcp-hardened-vpce-s3" }
}
