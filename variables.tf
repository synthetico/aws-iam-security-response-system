# Variables for AWS IAM Security Response System

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "lambda_function_name" {
  description = "Name of the Lambda function that disables compromised credentials"
  type        = string
  default     = "iam_leaked_credential_killswitch"
}

variable "sns_email_endpoint" {
  description = "Email address to receive notifications when credentials are disabled"
  type        = string
  # This should be provided via terraform.tfvars or -var flag
}

variable "cloudwatch_log_retention_days" {
  description = "Number of days to retain CloudWatch logs for audit trails"
  type        = number
  default     = 90
}

variable "environment" {
  description = "Environment name for resource tagging"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name for resource tagging"
  type        = string
  default     = "iam-security-automation"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 60
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 256
}

variable "enable_dlq" {
  description = "Enable Dead Letter Queue for failed Lambda invocations"
  type        = bool
  default     = true
}
