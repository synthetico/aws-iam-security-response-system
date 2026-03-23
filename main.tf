terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      Project     = var.project_name
      ManagedBy   = "Terraform"
    }
  }
}

# Data source to get AWS account ID and partition
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# KMS key for SNS topic encryption
resource "aws_kms_key" "sns_encryption" {
  description             = "KMS key for encrypting SNS notifications"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name = "${var.project_name}-sns-encryption-key"
  }
}

resource "aws_kms_alias" "sns_encryption" {
  name          = "alias/${var.project_name}-sns-encryption"
  target_key_id = aws_kms_key.sns_encryption.key_id
}

# SNS Topic for alerting IT team (encrypted at rest)
resource "aws_sns_topic" "credential_exposure_alerts" {
  name              = "${var.project_name}-credential-exposure-alerts"
  display_name      = "IAM Credential Exposure Alerts"
  kms_master_key_id = aws_kms_key.sns_encryption.id

  tags = {
    Name = "${var.project_name}-alerts"
  }
}

# SNS Topic Policy to allow EventBridge and Lambda to publish
resource "aws_sns_topic_policy" "credential_exposure_alerts" {
  arn = aws_sns_topic.credential_exposure_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.credential_exposure_alerts.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# SNS Email Subscription
resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.credential_exposure_alerts.arn
  protocol  = "email"
  endpoint  = var.sns_email_endpoint
}

# SQS Dead Letter Queue for failed Lambda invocations
resource "aws_sqs_queue" "lambda_dlq" {
  count = var.enable_dlq ? 1 : 0

  name                      = "${var.lambda_function_name}-dlq"
  message_retention_seconds = 1209600 # 14 days

  tags = {
    Name = "${var.lambda_function_name}-dlq"
  }
}

# CloudWatch Log Group for Lambda function
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.lambda_function_name}"
  retention_in_days = var.cloudwatch_log_retention_days

  tags = {
    Name = "${var.lambda_function_name}-logs"
  }
}

# IAM Role for Lambda Execution
resource "aws_iam_role" "lambda_execution_role" {
  name = "${var.lambda_function_name}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.lambda_function_name}-execution-role"
  }
}

# Custom inline policy for IAM actions (least privilege)
resource "aws_iam_role_policy" "lambda_iam_policy" {
  name = "${var.lambda_function_name}-iam-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DisableCompromisedAccessKeys"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:ListAccessKeys"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:user/*"
      }
    ]
  })
}

# CloudWatch Logs policy for Lambda
resource "aws_iam_role_policy" "lambda_cloudwatch_policy" {
  name = "${var.lambda_function_name}-cloudwatch-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchLogging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
      }
    ]
  })
}

# SNS publish policy for Lambda
resource "aws_iam_role_policy" "lambda_sns_policy" {
  name = "${var.lambda_function_name}-sns-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSNSPublish"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.credential_exposure_alerts.arn
      },
      {
        Sid    = "AllowKMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.sns_encryption.arn
      }
    ]
  })
}

# SQS DLQ policy for Lambda (if enabled)
resource "aws_iam_role_policy" "lambda_dlq_policy" {
  count = var.enable_dlq ? 1 : 0

  name = "${var.lambda_function_name}-dlq-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSQSSendMessage"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.lambda_dlq[0].arn
      }
    ]
  })
}

# Archive the Lambda function code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

# Lambda Function
resource "aws_lambda_function" "credential_killswitch" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = var.lambda_function_name
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.credential_exposure_alerts.arn
      LOG_LEVEL     = "INFO"
    }
  }

  dynamic "dead_letter_config" {
    for_each = var.enable_dlq ? [1] : []
    content {
      target_arn = aws_sqs_queue.lambda_dlq[0].arn
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy.lambda_iam_policy,
    aws_iam_role_policy.lambda_cloudwatch_policy,
    aws_iam_role_policy.lambda_sns_policy
  ]

  tags = {
    Name = var.lambda_function_name
  }
}

# EventBridge Rule for AWS Health Events
resource "aws_cloudwatch_event_rule" "credential_exposure" {
  name        = "${var.project_name}-credential-exposure-rule"
  description = "Capture AWS Health events for exposed IAM credentials"

  event_pattern = jsonencode({
    source      = ["aws.health"]
    detail-type = ["AWS Health Event"]
    detail = {
      service = ["IAM"]
      eventTypeCategory = ["issue"]
      eventTypeCode = ["AWS_RISK_CREDENTIALS_EXPOSED"]
    }
  })

  tags = {
    Name = "${var.project_name}-credential-exposure-rule"
  }
}

# EventBridge Target - Lambda Function
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.credential_exposure.name
  target_id = "InvokeCredentialKillswitchLambda"
  arn       = aws_lambda_function.credential_killswitch.arn
}

# Lambda Permission to allow EventBridge invocation
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.credential_killswitch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.credential_exposure.arn
}

# CloudWatch Alarm for Lambda Errors
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.lambda_function_name}-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alert when Lambda function encounters errors"
  alarm_actions       = [aws_sns_topic.credential_exposure_alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.credential_killswitch.function_name
  }

  tags = {
    Name = "${var.lambda_function_name}-error-alarm"
  }
}

# CloudWatch Alarm for DLQ Messages (if enabled)
resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  count = var.enable_dlq ? 1 : 0

  alarm_name          = "${var.lambda_function_name}-dlq-messages"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Average"
  threshold           = 0
  alarm_description   = "Alert when messages appear in the DLQ"
  alarm_actions       = [aws_sns_topic.credential_exposure_alerts.arn]

  dimensions = {
    QueueName = aws_sqs_queue.lambda_dlq[0].name
  }

  tags = {
    Name = "${var.lambda_function_name}-dlq-alarm"
  }
}
