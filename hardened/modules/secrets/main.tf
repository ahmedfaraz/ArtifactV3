###############################################################################
# hardened/modules/secrets/main.tf
#
# Four Secrets Manager secrets — one per mock credential value.
# Each secret carries a resource-based Deny policy that blocks
# GetSecretValue for all principals EXCEPT the ECS task role.
#
# Mock values are the same strings used in the baseline credentials.env,
# ensuring attack scripts in Component 3 can exercise the same code paths.
# In a real deployment these would be rotated immediately after initial setup.
###############################################################################

# ---------------------------------------------------------------------------
# Secret 1 — AWS_ACCESS_KEY_ID (mock)
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "aws_access_key_id" {
  name                    = "mcp-hardened-aws-access-key-id"
  description             = "Mock AWS Access Key ID for hardened MCP server"
  recovery_window_in_days = 0  # immediate deletion on destroy (research lab)

  tags = { Name = "mcp-hardened-secret-aws-access-key-id" }
}

resource "aws_secretsmanager_secret_version" "aws_access_key_id" {
  secret_id     = aws_secretsmanager_secret.aws_access_key_id.id
  secret_string = "AKIAIOSFODNN7EXAMPLE"
}

resource "aws_secretsmanager_secret_policy" "aws_access_key_id" {
  secret_arn = aws_secretsmanager_secret.aws_access_key_id.arn
  policy     = data.aws_iam_policy_document.secret_deny_all_except_task[0].json
}

# ---------------------------------------------------------------------------
# Secret 2 — AWS_SECRET_ACCESS_KEY (mock)
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "aws_secret_access_key" {
  name                    = "mcp-hardened-aws-secret-access-key"
  description             = "Mock AWS Secret Access Key for hardened MCP server"
  recovery_window_in_days = 0

  tags = { Name = "mcp-hardened-secret-aws-secret-access-key" }
}

resource "aws_secretsmanager_secret_version" "aws_secret_access_key" {
  secret_id     = aws_secretsmanager_secret.aws_secret_access_key.id
  secret_string = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_secretsmanager_secret_policy" "aws_secret_access_key" {
  secret_arn = aws_secretsmanager_secret.aws_secret_access_key.arn
  policy     = data.aws_iam_policy_document.secret_deny_all_except_task[1].json
}

# ---------------------------------------------------------------------------
# Secret 3 — DB_CONNECTION_STRING (mock)
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "db_connection_string" {
  name                    = "mcp-hardened-db-connection-string"
  description             = "Mock DB connection string for hardened MCP server"
  recovery_window_in_days = 0

  tags = { Name = "mcp-hardened-secret-db-connection-string" }
}

resource "aws_secretsmanager_secret_version" "db_connection_string" {
  secret_id     = aws_secretsmanager_secret.db_connection_string.id
  secret_string = "postgresql://mcpuser:FAKEPASSWORD123@mock-rds.internal:5432/mockdb"
}

resource "aws_secretsmanager_secret_policy" "db_connection_string" {
  secret_arn = aws_secretsmanager_secret.db_connection_string.arn
  policy     = data.aws_iam_policy_document.secret_deny_all_except_task[2].json
}

# ---------------------------------------------------------------------------
# Secret 4 — INTERNAL_API_TOKEN (mock)
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "internal_api_token" {
  name                    = "mcp-hardened-internal-api-token"
  description             = "Mock internal API token for hardened MCP server"
  recovery_window_in_days = 0

  tags = { Name = "mcp-hardened-secret-internal-api-token" }
}

resource "aws_secretsmanager_secret_version" "internal_api_token" {
  secret_id     = aws_secretsmanager_secret.internal_api_token.id
  secret_string = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.MOCK"
}

resource "aws_secretsmanager_secret_policy" "internal_api_token" {
  secret_arn = aws_secretsmanager_secret.internal_api_token.arn
  policy     = data.aws_iam_policy_document.secret_deny_all_except_task[3].json
}

# ---------------------------------------------------------------------------
# Resource-based Deny policy (one per secret, all identical except index)
# Effect:  Deny  GetSecretValue  for all principals EXCEPT the ECS task role
# and the Terraform deployer identity.
# The Terraform user is exempted so it can manage secret versions in state
# without losing access after the policy is first applied.
# ---------------------------------------------------------------------------
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "secret_deny_all_except_task" {
  count = 4

  statement {
    sid    = "DenyAllExceptTaskRole"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalArn"
      values   = [
        var.task_role_arn,
        var.task_execution_role_arn,
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/terraform-lab-user",
      ]
    }
  }
}
