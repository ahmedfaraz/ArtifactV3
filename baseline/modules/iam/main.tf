###############################################################################
# baseline/modules/iam/main.tf
#
# Over-permissive IAM roles for the pre-control baseline.
# Task Role intentionally grants wildcard S3 and Secrets Manager access —
# no resource-level scoping. This is the M1/M2 attack surface for
# Scenario C (credential exfiltration → AWS API abuse).
###############################################################################

data "aws_iam_policy_document" "ecs_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------
# ECS Task Execution Role
# Grants ECS the ability to pull images from ECR and send logs to CloudWatch.
# Uses the AWS-managed AmazonECSTaskExecutionRolePolicy (minimal, correct).
# ---------------------------------------------------------------------------
resource "aws_iam_role" "task_execution" {
  name               = "mcp-baseline-ecs-execution-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json

  tags = {
    Name = "mcp-baseline-ecs-execution-role"
  }
}

resource "aws_iam_role_policy_attachment" "task_execution_managed" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ---------------------------------------------------------------------------
# ECS Task Role — OVER-PERMISSIVE (intentional baseline vulnerability)
#
# Grants:
#   s3:GetObject + s3:ListBucket on arn:aws:s3:::*     (all buckets)
#   secretsmanager:GetSecretValue on arn:aws:secretsmanager:*  (all secrets)
#
# No resource-level scoping anywhere. This allows Scenario C to demonstrate
# that a compromised task can enumerate and read any S3 bucket or secret
# in the account.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "task" {
  name               = "mcp-baseline-ecs-task-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json

  tags = {
    Name = "mcp-baseline-ecs-task-role"
  }
}

data "aws_iam_policy_document" "task_overpermissive" {
  # Wildcard S3 access — no bucket or prefix scoping
  statement {
    sid    = "S3WildcardAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = ["arn:aws:s3:::*"]
  }

  # Wildcard Secrets Manager access — no secret ARN scoping
  statement {
    sid    = "SecretsManagerWildcardAccess"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = ["arn:aws:secretsmanager:*"]
  }
}

resource "aws_iam_role_policy" "task_overpermissive" {
  name   = "mcp-baseline-task-overpermissive-policy"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_overpermissive.json
}
