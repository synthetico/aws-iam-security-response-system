# Outputs for AWS IAM Security Response System

output "lambda_function_arn" {
  description = "ARN of the Lambda function that disables compromised credentials"
  value       = aws_lambda_function.credential_killswitch.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.credential_killswitch.function_name
}

output "lambda_role_arn" {
  description = "ARN of the IAM role used by the Lambda function"
  value       = aws_iam_role.lambda_execution_role.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule that triggers the Lambda function"
  value       = aws_cloudwatch_event_rule.credential_exposure.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.credential_exposure.name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for credential exposure alerts"
  value       = aws_sns_topic.credential_exposure_alerts.arn
}

output "sns_topic_name" {
  description = "Name of the SNS topic"
  value       = aws_sns_topic.credential_exposure_alerts.name
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group for Lambda function logs"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch Log Group"
  value       = aws_cloudwatch_log_group.lambda_logs.arn
}

output "dlq_url" {
  description = "URL of the Dead Letter Queue (if enabled)"
  value       = var.enable_dlq ? aws_sqs_queue.lambda_dlq[0].url : null
}

output "dlq_arn" {
  description = "ARN of the Dead Letter Queue (if enabled)"
  value       = var.enable_dlq ? aws_sqs_queue.lambda_dlq[0].arn : null
}

output "kms_key_id" {
  description = "ID of the KMS key used for SNS encryption"
  value       = aws_kms_key.sns_encryption.key_id
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for SNS encryption"
  value       = aws_kms_key.sns_encryption.arn
}

output "lambda_error_alarm_arn" {
  description = "ARN of the CloudWatch alarm for Lambda errors"
  value       = aws_cloudwatch_metric_alarm.lambda_errors.arn
}

output "deployment_instructions" {
  description = "Instructions for deploying this infrastructure"
  value = <<-EOT
    DEPLOYMENT INSTRUCTIONS:

    1. Set the SNS email endpoint variable:
       export TF_VAR_sns_email_endpoint="your-email@example.com"

    2. Initialize Terraform:
       terraform init

    3. Review the planned changes:
       terraform plan

    4. Apply the configuration:
       terraform apply

    5. Confirm the SNS email subscription:
       Check your email and click the confirmation link sent by AWS SNS.

    6. Test the setup (optional):
       You can test by simulating an AWS Health event or by manually invoking the Lambda function.

    IMPORTANT NOTES:
    - The SNS subscription requires email confirmation before alerts will be delivered.
    - CloudWatch logs are retained for ${var.cloudwatch_log_retention_days} days.
    - The Lambda function has a ${var.lambda_timeout} second timeout.
    - Dead Letter Queue is ${var.enable_dlq ? "enabled" : "disabled"}.
  EOT
}
