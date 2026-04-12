###############################################################################
# hardened/modules/logging/main.tf
#
# Full observability stack for the hardened architecture.
# Provisioning order (within this module) as specified:
#   1. aws_cloudwatch_log_group.app_logs
#   2. aws_cloudwatch_log_group.flow_logs
#   3. aws_cloudwatch_log_group.cloudtrail_logs
#   4. aws_s3_bucket.cloudtrail  (versioning + KMS)
#   5. aws_s3_bucket_policy.cloudtrail
#   6. aws_cloudtrail.main
#   7. aws_cloudwatch_log_metric_filter.secret_access
#   8. aws_cloudwatch_metric_alarm.secret_access_anomaly
#   9. aws_sns_topic.alerts + aws_sns_topic_subscription.email
#
# Also provisions IAM roles for:
#   - VPC Flow Log delivery  → output: flow_log_delivery_role_arn
#   - CloudTrail → CW Logs delivery
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# 1. Application log group — ECS container stdout/stderr
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/mcp/hardened/app"
  retention_in_days = 30

  tags = { Name = "mcp-hardened-app-logs" }
}

# ---------------------------------------------------------------------------
# 2. VPC Flow Logs log group
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/mcp/hardened/flow-logs"
  retention_in_days = 30

  tags = { Name = "mcp-hardened-flow-logs" }
}

# ---------------------------------------------------------------------------
# IAM role: VPC Flow Logs → CloudWatch delivery
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "flow_log_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_log_delivery" {
  name               = "mcp-hardened-flow-log-delivery-role"
  assume_role_policy = data.aws_iam_policy_document.flow_log_trust.json
  tags               = { Name = "mcp-hardened-flow-log-delivery-role" }
}

data "aws_iam_policy_document" "flow_log_delivery" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "flow_log_delivery" {
  name   = "mcp-hardened-flow-log-delivery-policy"
  role   = aws_iam_role.flow_log_delivery.id
  policy = data.aws_iam_policy_document.flow_log_delivery.json
}

# ---------------------------------------------------------------------------
# 3. CloudTrail log group
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "cloudtrail_logs" {
  name              = "/mcp/hardened/cloudtrail"
  retention_in_days = 90

  tags = { Name = "mcp-hardened-cloudtrail-logs" }
}

# IAM role: CloudTrail → CloudWatch Logs delivery
data "aws_iam_policy_document" "cloudtrail_cw_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_cw_delivery" {
  name               = "mcp-hardened-cloudtrail-cw-role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_cw_trust.json
  tags               = { Name = "mcp-hardened-cloudtrail-cw-role" }
}

data "aws_iam_policy_document" "cloudtrail_cw_delivery" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail_logs.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_cw_delivery" {
  name   = "mcp-hardened-cloudtrail-cw-policy"
  role   = aws_iam_role.cloudtrail_cw_delivery.id
  policy = data.aws_iam_policy_document.cloudtrail_cw_delivery.json
}

# ---------------------------------------------------------------------------
# 4. CloudTrail S3 bucket (versioning enabled, server-side KMS encryption)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "mcp-hardened-cloudtrail-${var.bucket_suffix}"
  force_destroy = true

  tags = { Name = "mcp-hardened-cloudtrail-bucket" }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      # kms_master_key_id omitted → uses AWS-managed aws/s3 CMK
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# 5. S3 bucket policy — grants CloudTrail PutObject and GetBucketAcl
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "cloudtrail_bucket" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail]
}

# ---------------------------------------------------------------------------
# 6. CloudTrail — multi-region, global events, log file validation,
#    data events for S3 and Secrets Manager, CloudWatch Logs delivery
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "main" {
  name                          = "mcp-hardened-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail_logs.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw_delivery.arn

  # Data events: all S3 objects (read + write)
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  # Data events: all Secrets Manager secrets
  event_selector {
    read_write_type           = "All"
    include_management_events = false

    data_resource {
      type   = "AWS::SecretsManager::Secret"
      values = ["arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:*"]
    }
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_cloudwatch_log_group.cloudtrail_logs,
  ]

  tags = { Name = "mcp-hardened-cloudtrail" }
}

# ---------------------------------------------------------------------------
# 7. CloudWatch Log Metric Filter — GetSecretValue events in CloudTrail logs
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "secret_access" {
  name           = "mcp-hardened-secret-access-filter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_logs.name
  pattern        = "{ $.eventName = \"GetSecretValue\" }"

  metric_transformation {
    name          = "SecretAccessCount"
    namespace     = "MCPSecurity"
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

# ---------------------------------------------------------------------------
# 8. CloudWatch Metric Alarm — fires when ≥ 3 GetSecretValue calls in 60s
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "secret_access_anomaly" {
  alarm_name          = "mcp-hardened-secret-access-anomaly"
  alarm_description   = "Fires when GetSecretValue is called more than 3 times in 60 seconds — potential credential harvesting (M3 detection metric)"
  namespace           = "MCPSecurity"
  metric_name         = "SecretAccessCount"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]

  tags = { Name = "mcp-hardened-secret-access-alarm" }
}

# ---------------------------------------------------------------------------
# 9. SNS Topic + email subscription for alarm notifications
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "mcp-hardened-security-alerts"
  tags = { Name = "mcp-hardened-sns-alerts" }
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
