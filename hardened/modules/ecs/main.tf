###############################################################################
# hardened/modules/ecs/main.tf
#
# Hardened ECS Fargate deployment:
#   - Private subnet, assign_public_ip = false
#   - readonlyRootFilesystem = true
#   - user = "1000" (non-root)
#   - allowPrivilegeEscalation equivalent: noNewPrivileges = true
#   - tmpfs at /tmp (64 MiB)
#   - All credentials sourced from Secrets Manager via secrets blocks
#   - EFS volume via access point (POSIX uid 1000)
#   - depends_on logging module (enforced in hardened/main.tf)
###############################################################################

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# ECR Repository
# ---------------------------------------------------------------------------
resource "aws_ecr_repository" "mcp" {
  name                 = "mcp-hardened-mcp-server"
  image_tag_mutability = "IMMUTABLE"  # hardened: prevent tag mutation

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { Name = "mcp-hardened-ecr-repo" }
}

# ---------------------------------------------------------------------------
# ECS Cluster
# ---------------------------------------------------------------------------
resource "aws_ecs_cluster" "mcp" {
  name = "mcp-hardened-ecs-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Name = "mcp-hardened-ecs-cluster" }
}

# ---------------------------------------------------------------------------
# ECS Task Definition — hardened
# ---------------------------------------------------------------------------
resource "aws_ecs_task_definition" "mcp" {
  family                   = "mcp-hardened-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = var.task_execution_role_arn
  task_role_arn            = var.task_role_arn

  # EFS volume via access point — enforces POSIX uid 1000 and /customers/ root
  volume {
    name = "mcp-data"
    efs_volume_configuration {
      file_system_id          = var.efs_id
      root_directory          = "/"
      transit_encryption      = "ENABLED"
      authorization_config {
        access_point_id = var.efs_access_point_id
        iam             = "ENABLED"
      }
    }
  }


  container_definitions = jsonencode([
    {
      name      = "mcp-server"
      image     = "${aws_ecr_repository.mcp.repository_url}:latest"
      essential = true
      cpu       = 256
      memory    = 512
      user      = "1000"

      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]

      # -----------------------------------------------------------------------
      # Credentials from Secrets Manager — NO plaintext environment variables
      # ECS agent retrieves secrets at task start and injects as env vars.
      # -----------------------------------------------------------------------
      secrets = [
        {
          name      = "AWS_ACCESS_KEY_ID"
          valueFrom = var.secret_aws_key_id_arn
        },
        {
          name      = "AWS_SECRET_ACCESS_KEY"
          valueFrom = var.secret_aws_secret_key_arn
        },
        {
          name      = "DB_CONNECTION_STRING"
          valueFrom = var.secret_db_conn_arn
        },
        {
          name      = "INTERNAL_API_TOKEN"
          valueFrom = var.secret_api_token_arn
        }
      ]

      environment = [
        {
          name  = "MCP_PORT"
          value = "8080"
        },
        {
          name  = "HTTP_ALLOWLIST"
          value = "https://internal.example.corp"
        }
      ]

      mountPoints = [
        {
          containerPath = "/mnt/data"
          sourceVolume  = "mcp-data"
          readOnly      = false
        },
      ]

      # readonlyRootFilesystem: prevents writing to the container layer
      readonlyRootFilesystem = true

      # privileged: false — no kernel capabilities beyond defaults
      privileged = false

      linuxParameters = {
        # noNewPrivileges prevents privilege escalation via setuid/setgid binaries
        # This is the ECS equivalent of allowPrivilegeEscalation = false (Kubernetes)
        noNewPrivileges = true

        capabilities = {
          drop = ["ALL"]
        }

        tmpfs = [
          {
            containerPath = "/tmp"
            size          = 64
          }
        ]
      }

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.app_log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "mcp"
        }
      }
    }
  ])

  tags = { Name = "mcp-hardened-task-def" }
}

# ---------------------------------------------------------------------------
# ECS Service — private subnet, no public IP
# ---------------------------------------------------------------------------
resource "aws_ecs_service" "mcp" {
  name            = "mcp-hardened-service"
  cluster         = aws_ecs_cluster.mcp.id
  task_definition = aws_ecs_task_definition.mcp.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [var.private_subnet_id]
    security_groups  = [var.ecs_sg_id]
    assign_public_ip = false
  }

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  tags = { Name = "mcp-hardened-service" }
}

# ---------------------------------------------------------------------------
# Retrieve private IP of the running ECS task (for run_all.sh attacker EC2)
# Polls every 15s up to 6 minutes. Returns "unavailable" if task not running.
# Uses a Python script to avoid bash heredoc CRLF issues on Windows-sourced files.
# ---------------------------------------------------------------------------
data "external" "task_ip" {
  depends_on = [aws_ecs_service.mcp]
  program    = ["python3", "${path.module}/fetch_private_ip.py"]
  query = {
    cluster = aws_ecs_cluster.mcp.name
    service = aws_ecs_service.mcp.name
    region  = var.aws_region
  }
}
