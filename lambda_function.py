"""
AWS IAM Leaked Credential Killswitch Lambda Function

This function automatically disables compromised AWS IAM access keys when
AWS Health detects credential exposure events (AWS_RISK_CREDENTIALS_EXPOSED).

Author: Security Automation Team
"""

import json
import logging
import os
from typing import Dict, List, Any
import boto3
from botocore.exceptions import ClientError, BotoCoreError

# Configure logging
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

# Initialize AWS clients
iam_client = boto3.client('iam')
sns_client = boto3.client('sns')

# Environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for processing AWS Health credential exposure events.

    Args:
        event: AWS Health event containing exposed credential information
        context: Lambda context object

    Returns:
        Response dictionary with status and details
    """
    logger.info("Received AWS Health Event")
    logger.debug(f"Event details: {json.dumps(event, default=str)}")

    try:
        # Extract event details
        event_details = event.get('detail', {})
        event_type_code = event_details.get('eventTypeCode', '')

        # Validate this is a credential exposure event
        if event_type_code != 'AWS_RISK_CREDENTIALS_EXPOSED':
            logger.warning(f"Unexpected event type: {event_type_code}")
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Event type not handled',
                    'eventType': event_type_code
                })
            }

        # Extract affected resources (access keys)
        affected_entities = event_details.get('affectedEntities', [])

        if not affected_entities:
            logger.warning("No affected entities found in the event")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'No affected entities to process'})
            }

        # Process each exposed credential
        results = process_exposed_credentials(affected_entities, event_details)

        # Send notification to IT team
        send_notification(results, event_details)

        logger.info(f"Successfully processed {len(results['disabled'])} credential(s)")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Credentials processed successfully',
                'disabled': results['disabled'],
                'failed': results['failed'],
                'skipped': results['skipped']
            }, default=str)
        }

    except Exception as e:
        logger.error(f"Unexpected error processing event: {str(e)}", exc_info=True)

        # Send error notification
        send_error_notification(str(e), event)

        # Re-raise to trigger DLQ if configured
        raise


def process_exposed_credentials(
    affected_entities: List[Dict[str, Any]],
    event_details: Dict[str, Any]
) -> Dict[str, List[Dict[str, str]]]:
    """
    Process and disable exposed IAM access keys.

    Args:
        affected_entities: List of affected IAM entities from AWS Health event
        event_details: Full event details for logging

    Returns:
        Dictionary containing lists of disabled, failed, and skipped credentials
    """
    results = {
        'disabled': [],
        'failed': [],
        'skipped': []
    }

    for entity in affected_entities:
        entity_value = entity.get('entityValue', '')

        if not entity_value:
            logger.warning("Entity missing entityValue, skipping")
            continue

        # Parse the entity value to extract username and access key ID
        # Expected format: "IAM_USER/username/AKIAIOSFODNN7EXAMPLE"
        try:
            parts = entity_value.split('/')

            if len(parts) < 3:
                logger.warning(f"Unexpected entity format: {entity_value}")
                results['skipped'].append({
                    'entity': entity_value,
                    'reason': 'Invalid format'
                })
                continue

            username = parts[1]
            access_key_id = parts[2]

            logger.info(f"Processing exposed key: {access_key_id} for user: {username}")

            # Disable the access key
            disable_result = disable_access_key(username, access_key_id)

            if disable_result['success']:
                results['disabled'].append({
                    'username': username,
                    'accessKeyId': access_key_id,
                    'timestamp': disable_result['timestamp']
                })
            else:
                results['failed'].append({
                    'username': username,
                    'accessKeyId': access_key_id,
                    'error': disable_result['error']
                })

        except Exception as e:
            logger.error(f"Error processing entity {entity_value}: {str(e)}")
            results['failed'].append({
                'entity': entity_value,
                'error': str(e)
            })

    return results


def disable_access_key(username: str, access_key_id: str) -> Dict[str, Any]:
    """
    Disable a specific IAM access key for a user.

    Args:
        username: IAM username
        access_key_id: Access key ID to disable

    Returns:
        Dictionary with success status, timestamp, and error (if any)
    """
    import datetime

    try:
        # First, verify the access key exists and get its current status
        try:
            response = iam_client.list_access_keys(UserName=username)
            access_keys = response.get('AccessKeyMetadata', [])

            key_exists = False
            current_status = None

            for key in access_keys:
                if key['AccessKeyId'] == access_key_id:
                    key_exists = True
                    current_status = key['Status']
                    break

            if not key_exists:
                logger.warning(f"Access key {access_key_id} not found for user {username}")
                return {
                    'success': False,
                    'error': 'Access key not found',
                    'timestamp': datetime.datetime.utcnow().isoformat()
                }

            if current_status == 'Inactive':
                logger.info(f"Access key {access_key_id} already inactive, skipping")
                return {
                    'success': True,
                    'error': 'Already inactive',
                    'timestamp': datetime.datetime.utcnow().isoformat()
                }

        except ClientError as e:
            error_code = e.response['Error']['Code']

            if error_code == 'NoSuchEntity':
                logger.warning(f"User {username} does not exist")
                return {
                    'success': False,
                    'error': 'User not found',
                    'timestamp': datetime.datetime.utcnow().isoformat()
                }
            else:
                raise

        # Disable the access key
        iam_client.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )

        logger.info(f"Successfully disabled access key {access_key_id} for user {username}")

        return {
            'success': True,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }

    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"IAM API error disabling key {access_key_id}: {error_code} - {error_message}")

        return {
            'success': False,
            'error': f"{error_code}: {error_message}",
            'timestamp': datetime.datetime.utcnow().isoformat()
        }

    except BotoCoreError as e:
        logger.error(f"BotoCore error disabling key {access_key_id}: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        }


def send_notification(results: Dict[str, List], event_details: Dict[str, Any]) -> None:
    """
    Send SNS notification to IT team about disabled credentials.

    Args:
        results: Processing results with disabled, failed, and skipped credentials
        event_details: AWS Health event details
    """
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not set, skipping notification")
        return

    try:
        disabled_count = len(results['disabled'])
        failed_count = len(results['failed'])
        skipped_count = len(results['skipped'])

        # Build notification message
        subject = f"🔒 IAM Credential Exposure Alert - {disabled_count} Key(s) Disabled"

        message_parts = [
            "AWS IAM CREDENTIAL EXPOSURE DETECTED",
            "=" * 50,
            "",
            f"Event Time: {event_details.get('startTime', 'N/A')}",
            f"Event Type: {event_details.get('eventTypeCode', 'N/A')}",
            f"Region: {event_details.get('eventRegion', 'N/A')}",
            f"Event ARN: {event_details.get('eventArn', 'N/A')}",
            "",
            "SUMMARY:",
            f"  - Credentials Disabled: {disabled_count}",
            f"  - Failed to Disable: {failed_count}",
            f"  - Skipped: {skipped_count}",
            ""
        ]

        if results['disabled']:
            message_parts.append("DISABLED CREDENTIALS:")
            for item in results['disabled']:
                message_parts.append(
                    f"  - User: {item['username']}, "
                    f"Key: {item['accessKeyId']}, "
                    f"Time: {item['timestamp']}"
                )
            message_parts.append("")

        if results['failed']:
            message_parts.append("FAILED TO DISABLE:")
            for item in results['failed']:
                message_parts.append(
                    f"  - User: {item.get('username', 'N/A')}, "
                    f"Key: {item.get('accessKeyId', 'N/A')}, "
                    f"Error: {item['error']}"
                )
            message_parts.append("")

        if results['skipped']:
            message_parts.append("SKIPPED:")
            for item in results['skipped']:
                message_parts.append(
                    f"  - Entity: {item.get('entity', 'N/A')}, "
                    f"Reason: {item['reason']}"
                )
            message_parts.append("")

        message_parts.extend([
            "REQUIRED ACTIONS:",
            "1. Review the affected IAM users immediately",
            "2. Rotate all credentials for the affected users",
            "3. Check CloudTrail logs for unauthorized API activity",
            "4. Investigate how the credentials were exposed",
            "5. Review security policies and access controls",
            "",
            f"CloudWatch Logs: /aws/lambda/{os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'N/A')}",
            "",
            "This is an automated alert from the IAM Security Response System."
        ])

        message = "\n".join(message_parts)

        # Publish to SNS
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )

        logger.info("Notification sent successfully to SNS topic")

    except ClientError as e:
        logger.error(f"Error sending SNS notification: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error sending notification: {str(e)}")


def send_error_notification(error_message: str, event: Dict[str, Any]) -> None:
    """
    Send error notification when Lambda function fails.

    Args:
        error_message: Error description
        event: Original event that caused the error
    """
    if not SNS_TOPIC_ARN:
        return

    try:
        subject = "⚠️ IAM Credential Killswitch Lambda Error"

        message = "\n".join([
            "ERROR IN IAM CREDENTIAL KILLSWITCH LAMBDA",
            "=" * 50,
            "",
            f"Error: {error_message}",
            "",
            "Event Details:",
            json.dumps(event, indent=2, default=str),
            "",
            "REQUIRED ACTIONS:",
            "1. Check Lambda CloudWatch logs for detailed error information",
            "2. Verify IAM permissions for the Lambda function",
            "3. Check the Dead Letter Queue for failed events",
            "4. Manually review and disable any exposed credentials",
            "",
            f"CloudWatch Logs: /aws/lambda/{os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'N/A')}",
        ])

        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )

    except Exception as e:
        logger.error(f"Failed to send error notification: {str(e)}")
