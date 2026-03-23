# AWS IAM Security Response System

Automated security response system that detects and disables compromised AWS IAM credentials in real-time using AWS Health events, EventBridge, and Lambda.

## Architecture

The system automatically responds to AWS Health credential exposure events:

1. **AWS Health** detects compromised credentials and publishes `AWS_RISK_CREDENTIALS_EXPOSED` events
2. **EventBridge Rule** captures these events and triggers the Lambda function
3. **Lambda Function** (`iam_leaked_credential_killswitch`) disables the compromised access keys
4. **SNS Topic** sends encrypted notifications to the IT team
5. **CloudWatch Logs** maintains a 90-day audit trail
6. **Dead Letter Queue** captures failed invocations for investigation

View the architecture diagram in the Canvas tab.

## Features

- **Automatic Response**: Instantly disables compromised IAM access keys when AWS Health detects exposure
- **Least Privilege**: Lambda role has only the minimum IAM permissions required (UpdateAccessKey, ListAccessKeys)
- **Encryption**: SNS topic encrypted at rest with AWS KMS
- **Audit Trail**: CloudWatch Logs with 90-day retention for compliance and forensics
- **Error Handling**: Comprehensive error handling for edge cases (inactive keys, missing users)
- **Dead Letter Queue**: Failed Lambda invocations captured for investigation
- **Monitoring**: CloudWatch alarms for Lambda errors and DLQ messages
- **Email Alerts**: IT team receives detailed notifications with remediation steps

## Prerequisites

- AWS account with appropriate permissions
- Terraform >= 1.0
- Email address for receiving security alerts

## Deployment

### 1. Configure Email Endpoint

Create a `terraform.tfvars` file:

```hcl
sns_email_endpoint = "security-team@example.com"
```

### 2. Initialize Terraform

```bash
terraform init
```

### 3. Review Planned Changes

```bash
terraform plan
```

### 4. Deploy Infrastructure

```bash
terraform apply
```

### 5. Confirm SNS Subscription

Check the email inbox for the SNS confirmation message and click the confirmation link. **Alerts will not be delivered until the subscription is confirmed.**

## Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region for deployment | `us-east-1` |
| `lambda_function_name` | Name of the Lambda function | `iam_leaked_credential_killswitch` |
| `sns_email_endpoint` | Email for security alerts | **Required** |
| `cloudwatch_log_retention_days` | Log retention period | `90` |
| `lambda_timeout` | Lambda timeout in seconds | `60` |
| `lambda_memory_size` | Lambda memory in MB | `256` |
| `enable_dlq` | Enable Dead Letter Queue | `true` |

## Lambda Function Details

The Python 3.11 Lambda function (`lambda_function.py`) includes:

- **Event Parsing**: Extracts compromised credential details from AWS Health events
- **IAM Operations**: Lists and disables compromised access keys
- **Error Handling**:
  - Handles non-existent users gracefully
  - Skips already-inactive keys
  - Catches and logs API errors
- **Notifications**: Sends detailed SNS alerts with:
  - Disabled credentials summary
  - Failed operations (if any)
  - Recommended remediation steps
  - CloudWatch Logs location
- **Logging**: Structured logging for audit and troubleshooting

## IAM Permissions

The Lambda execution role has three inline policies:

### 1. IAM Policy (Least Privilege)
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:UpdateAccessKey",
      "iam:ListAccessKeys"
    ],
    "Resource": "arn:aws:iam::ACCOUNT_ID:user/*"
  }]
}
```

### 2. CloudWatch Logs Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ],
    "Resource": "arn:aws:logs:REGION:ACCOUNT_ID:log-group:/aws/lambda/FUNCTION_NAME:*"
  }]
}
```

### 3. SNS Publish Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["sns:Publish"],
    "Resource": "arn:aws:sns:REGION:ACCOUNT_ID:TOPIC_NAME"
  }]
}
```

## Monitoring and Alerting

### CloudWatch Alarms

1. **Lambda Error Alarm**: Triggers when the Lambda function encounters errors
2. **DLQ Message Alarm**: Triggers when messages appear in the Dead Letter Queue

Both alarms send notifications to the SNS topic.

### CloudWatch Logs

Lambda logs are stored at `/aws/lambda/iam_leaked_credential_killswitch` with 90-day retention.

## Testing

To test the system, you can manually invoke the Lambda function with a sample AWS Health event:

```bash
aws lambda invoke \
  --function-name iam_leaked_credential_killswitch \
  --payload file://test-event.json \
  response.json
```

Sample test event (`test-event.json`):

```json
{
  "version": "0",
  "id": "test-event-id",
  "detail-type": "AWS Health Event",
  "source": "aws.health",
  "time": "2024-01-01T12:00:00Z",
  "region": "us-east-1",
  "resources": [],
  "detail": {
    "eventArn": "arn:aws:health:us-east-1::event/IAM/AWS_RISK_CREDENTIALS_EXPOSED/test",
    "service": "IAM",
    "eventTypeCode": "AWS_RISK_CREDENTIALS_EXPOSED",
    "eventTypeCategory": "issue",
    "startTime": "2024-01-01T12:00:00Z",
    "affectedEntities": [
      {
        "entityValue": "IAM_USER/test-user/AKIAIOSFODNN7EXAMPLE"
      }
    ]
  }
}
```

**Note**: Replace `test-user` with an actual IAM user and `AKIAIOSFODNN7EXAMPLE` with a real access key ID for testing.

## Security Best Practices

- **Least Privilege**: Lambda role has only essential IAM permissions
- **Encryption**: SNS topic encrypted with KMS key (key rotation enabled)
- **Audit Trail**: 90-day CloudWatch Logs retention for compliance
- **Error Handling**: Graceful handling of edge cases prevents partial failures
- **Dead Letter Queue**: Failed invocations preserved for investigation
- **Resource Tagging**: All resources tagged for tracking and cost allocation
- **Event Filtering**: EventBridge rule only captures relevant AWS Health events

## Incident Response Workflow

When credentials are compromised:

1. **Detection**: AWS Health detects credential exposure
2. **Automatic Response**: Lambda disables the compromised access key(s)
3. **Notification**: IT team receives email with details
4. **Investigation**:
   - Review CloudWatch Logs for execution details
   - Check AWS CloudTrail for unauthorized API activity
   - Investigate how credentials were exposed
5. **Remediation**:
   - Rotate all credentials for affected users
   - Review and update security policies
   - Implement additional preventive controls

## Outputs

After deployment, Terraform outputs the following:

- `lambda_function_arn`: Lambda function ARN
- `eventbridge_rule_arn`: EventBridge rule ARN
- `sns_topic_arn`: SNS topic ARN
- `cloudwatch_log_group_name`: CloudWatch Log Group name
- `dlq_url`: Dead Letter Queue URL (if enabled)
- `kms_key_arn`: KMS encryption key ARN

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

## Cost Considerations

- **Lambda**: Pay per invocation (should be rare - only when credentials are exposed)
- **EventBridge**: No cost for rules (only data transfer)
- **SNS**: Minimal cost for notifications
- **CloudWatch Logs**: Storage costs for 90-day retention
- **KMS**: Key storage and API requests
- **SQS DLQ**: Minimal cost (only for failed invocations)

Expected monthly cost: **< $5** under normal conditions (no credential exposures)

## Compliance and Audit

This system supports compliance requirements:

- **NIST 800-53**: IA-4, IR-4, AU-6
- **PCI DSS**: Requirement 8.1.4, 10.2
- **SOC 2**: CC6.1, CC7.3
- **ISO 27001**: A.9.4.2, A.12.4.1

## References

- [AWS Health Events Documentation](https://docs.aws.amazon.com/health/latest/ug/what-is-aws-health.html)
- [Automating Incident Response for Exposed AWS Credentials](https://www.severalclouds.com/success-stories/automating-incident-response-for-exposed-aws-credentials-with-aws-health)
- [Terraform EventBridge Best Practices](https://spacelift.io/blog/terraform-eventbridge)
- [EventBridge Security Best Practices](https://awsforengineers.com/blog/eventbridge-security-best-practices/)

## Support

For issues or questions:

1. Check CloudWatch Logs for Lambda execution details
2. Review Terraform state for resource configuration
3. Verify SNS email subscription is confirmed
4. Check EventBridge rule is enabled and properly configured

## License

This infrastructure code is provided as-is for security automation purposes.
