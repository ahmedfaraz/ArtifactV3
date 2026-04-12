output "aws_access_key_secret_arn" {
  value = aws_secretsmanager_secret.aws_access_key_id.arn
}

output "aws_secret_key_secret_arn" {
  value = aws_secretsmanager_secret.aws_secret_access_key.arn
}

output "db_connection_secret_arn" {
  value = aws_secretsmanager_secret.db_connection_string.arn
}

output "api_token_secret_arn" {
  value = aws_secretsmanager_secret.internal_api_token.arn
}

output "all_secret_arns" {
  description = "List of all four secret ARNs — used in CloudTrail event selectors"
  value = [
    aws_secretsmanager_secret.aws_access_key_id.arn,
    aws_secretsmanager_secret.aws_secret_access_key.arn,
    aws_secretsmanager_secret.db_connection_string.arn,
    aws_secretsmanager_secret.internal_api_token.arn,
  ]
}
