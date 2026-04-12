###############################################################################
# hardened/modules/iam/main.tf
#
# Least-privilege IAM roles for the hardened architecture.
# Three SEPARATE aws_iam_policy resources — one per MCP tool — each
# attached via aws_iam_role_policy_attachment (no inline policies).
#
# file_reader  → s3:GetObject scoped to one S3 prefix ARN
# db_query     → rds-db:connect scoped to one RDS resource ARN
# http_client  → no AWS permissions (reads tags only; harmless placeholder)
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
# ECS Task Execution Role — ECR pull + CloudWatch Logs (unchanged from baseline)
# ---------------------------------------------------------------------------
resource "aws_iam_role" "task_execution" {
  name               = "mcp-hardened-ecs-execution-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json
  tags               = { Name = "mcp-hardened-ecs-execution-role" }
}

resource "aws_iam_role_policy_attachment" "task_execution_managed" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# SecretsManager read permission for task execution role (to inject secrets into containers)
data "aws_iam_policy_document" "exec_secrets_read" {
  statement {
    sid     = "ReadTaskSecrets"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      "arn:aws:secretsmanager:${var.aws_region}:*:secret:mcp-hardened-*"
    ]
  }
}

resource "aws_iam_policy" "exec_secrets_read" {
  name        = "mcp-hardened-exec-secrets-read"
  description = "Allows ECS task execution role to read hardened secrets for container injection"
  policy      = data.aws_iam_policy_document.exec_secrets_read.json
  tags        = { Name = "mcp-hardened-exec-secrets-read" }
}

resource "aws_iam_role_policy_attachment" "exec_secrets_read" {
  role       = aws_iam_role.task_execution.name
  policy_arn = aws_iam_policy.exec_secrets_read.arn
}

# ---------------------------------------------------------------------------
# ECS Task Role — least-privilege; three attached policies, no inline
# ---------------------------------------------------------------------------
resource "aws_iam_role" "task" {
  name               = "mcp-hardened-ecs-task-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json
  tags               = { Name = "mcp-hardened-ecs-task-role" }
}

# ── Policy 1: file_reader ─────────────────────────────────────────────────
# s3:GetObject scoped to the specific S3 prefix used by the file_reader tool
data "aws_iam_policy_document" "file_reader" {
  statement {
    sid     = "FileReaderScopedS3Access"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    # Scoped to the /customers/ prefix of the hardened data bucket only.
    # var.s3_data_prefix_arn = "<bucket_arn>/customers/*"
    resources = [var.s3_data_prefix_arn]
  }
}

resource "aws_iam_policy" "file_reader" {
  name        = "mcp-hardened-file-reader-policy"
  description = "Scoped S3 read access for the file_reader MCP tool"
  policy      = data.aws_iam_policy_document.file_reader.json
  tags        = { Name = "mcp-hardened-file-reader-policy" }
}

resource "aws_iam_role_policy_attachment" "file_reader" {
  role       = aws_iam_role.task.name
  policy_arn = aws_iam_policy.file_reader.arn
}

# ── Policy 2: db_query ────────────────────────────────────────────────────
# rds-db:connect scoped to the specific RDS instance resource ID + username
data "aws_iam_policy_document" "db_query" {
  statement {
    sid     = "DbQueryScopedRdsConnect"
    effect  = "Allow"
    actions = ["rds-db:connect"]
    # var.rds_resource_arn = "arn:aws:rds-db:<region>:<acct>:dbuser:<resource-id>/<username>"
    resources = [var.rds_resource_arn]
  }
}

resource "aws_iam_policy" "db_query" {
  name        = "mcp-hardened-db-query-policy"
  description = "Scoped rds-db:connect for the db_query MCP tool"
  policy      = data.aws_iam_policy_document.db_query.json
  tags        = { Name = "mcp-hardened-db-query-policy" }
}

resource "aws_iam_role_policy_attachment" "db_query" {
  role       = aws_iam_role.task.name
  policy_arn = aws_iam_policy.db_query.arn
}

# ── Policy 3: http_client ─────────────────────────────────────────────────
# No AWS permissions — the http_client tool makes external HTTP calls;
# it requires no AWS API access.  A minimal harmless Allow is used to
# create a valid (non-empty) policy document.
data "aws_iam_policy_document" "http_client" {
  statement {
    sid       = "HttpClientNoAwsPermissions"
    effect    = "Allow"
    actions   = ["tag:GetResources"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "http_client" {
  name        = "mcp-hardened-http-client-policy"
  description = "Placeholder policy for http_client tool — grants no useful AWS data access"
  policy      = data.aws_iam_policy_document.http_client.json
  tags        = { Name = "mcp-hardened-http-client-policy" }
}

resource "aws_iam_role_policy_attachment" "http_client" {
  role       = aws_iam_role.task.name
  policy_arn = aws_iam_policy.http_client.arn
}
