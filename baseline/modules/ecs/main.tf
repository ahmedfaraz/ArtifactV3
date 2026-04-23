###############################################################################
# baseline/modules/ecs/main.tf
#
# ECS Fargate cluster, ECR repository, task definition, and service for the
# baseline architecture. Key intentional vulnerabilities:
#   - Container runs as root (no USER directive in Dockerfile)
#   - Mock credentials injected as plaintext environment variables
#   - readonlyRootFilesystem not set
#   - allowPrivilegeEscalation not restricted
#   - Task deployed in public subnet with assign_public_ip = true
###############################################################################

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# ECR Repository — stores the mcp-server Docker image
# Build and push: mcp_server/Dockerfile → this repository before applying.
# ---------------------------------------------------------------------------
resource "aws_ecr_repository" "mcp" {
  name                 = "mcp-baseline-mcp-server"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = {
    Name = "mcp-baseline-ecr-repo"
  }
}

# ---------------------------------------------------------------------------
# CloudWatch Log Group — captures stdout/stderr from the container
# Group name matches the pattern expected by collect_logs.sh
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "app" {
  name              = "/mcp/baseline/app"
  retention_in_days = 7

  tags = {
    Name = "mcp-baseline-app-logs"
  }
}

# ---------------------------------------------------------------------------
# ECS Cluster
# ---------------------------------------------------------------------------
resource "aws_ecs_cluster" "mcp" {
  name = "mcp-baseline-ecs-cluster"

  tags = {
    Name = "mcp-baseline-ecs-cluster"
  }
}

# ---------------------------------------------------------------------------
# ECS Task Definition
# INTENTIONAL VULNERABILITIES (documented):
#   1. Mock credentials as plaintext environment variables (M1 attack surface)
#   2. No readonlyRootFilesystem — writable root filesystem
#   3. No user override — process runs as root (uid 0)
#   4. No allowPrivilegeEscalation = false — privilege escalation possible
#   5. EFS root directory "/" — no path restriction
# ---------------------------------------------------------------------------
resource "aws_ecs_task_definition" "mcp" {
  family                   = "mcp-baseline-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = var.task_execution_role_arn
  task_role_arn            = var.task_role_arn

  # EFS volume — mounted at /mnt/data in the container
  volume {
    name = "mcp-data"
    efs_volume_configuration {
      file_system_id = var.efs_id
      root_directory = "/"
      # No access point, no IAM auth enforcement (baseline)
      transit_encryption = "DISABLED"
    }
  }

  container_definitions = jsonencode([
    {
      name      = "mcp-server"
      image     = "${aws_ecr_repository.mcp.repository_url}:latest"
      essential = true
      cpu       = 256
      memory    = 512

      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]

      # -----------------------------------------------------------------------
      # MOCK CREDENTIALS — plaintext environment variables (M1 attack surface)
      # These exact strings are pattern-matched by attack scripts in Component 3.
      # They appear here and in seed_secrets.sh. Do NOT copy to hardened/.
      # -----------------------------------------------------------------------
      environment = [
        {
          name  = "AWS_ACCESS_KEY_ID"
          value = "AKIAIOSFODNN7EXAMPLE"
        },
        {
          name  = "AWS_SECRET_ACCESS_KEY"
          value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        },
        {
          name  = "DB_CONNECTION_STRING"
          value = var.db_connection_string
        },
        {
          name  = "INTERNAL_API_TOKEN"
          value = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.MOCK"
        },
        {
          name  = "MCP_PORT"
          value = "8080"
        }
      ]

      mountPoints = [
        {
          containerPath = "/mnt/data"
          sourceVolume  = "mcp-data"
          readOnly      = false
        }
      ]

      # CloudWatch logging — stdout/stderr captured via awslogs driver
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/mcp/baseline/app"
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "mcp"
        }
      }

      # NO readonlyRootFilesystem (intentional — baseline)
      # NO user override (intentional — runs as root)
      # NO allowPrivilegeEscalation = false (intentional — baseline)
    }
  ])

  tags = {
    Name = "mcp-baseline-task-def"
  }
}

# ---------------------------------------------------------------------------
# ECS Service — Fargate, public subnet, public IP assigned
# ---------------------------------------------------------------------------
resource "aws_ecs_service" "mcp" {
  name            = "mcp-baseline-service"
  cluster         = aws_ecs_cluster.mcp.id
  task_definition = aws_ecs_task_definition.mcp.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [var.subnet_id]
    security_groups  = [var.security_group_id]
    assign_public_ip = true
  }

  # Allow replacement of running tasks without waiting for steady state
  # (useful during iterative apply cycles)
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  depends_on = [aws_cloudwatch_log_group.app]

  tags = {
    Name = "mcp-baseline-service"
  }
}

# ---------------------------------------------------------------------------
# Retrieve ECS task public IP via external data source
#
# Delegates to fetch_ip.py (same directory) which polls AWS CLI every 15 s
# for up to 6 minutes.  Using a Python file avoids shell-escaping and CRLF
# issues that occur when embedding bash scripts in Terraform heredocs on
# Windows/WSL environments.
#
# If the Docker image has not yet been pushed to ECR the task will fail to
# start and the script returns "unavailable-push-image-and-reapply".
# Resolution: push the image then run terraform apply again.
# ---------------------------------------------------------------------------
data "external" "task_ip" {
  depends_on = [aws_ecs_service.mcp]
  program    = ["python3", "${path.module}/fetch_ip.py"]
  query = {
    cluster = aws_ecs_cluster.mcp.name
    service = aws_ecs_service.mcp.name
    region  = var.aws_region
  }
}
