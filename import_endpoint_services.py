import os
import boto3
import time
import logging
from sts import establish_role
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Error message provided if service is not available in a region yet.
endpoint_service_api_not_available = (
    "This request has been administratively disabled.")


def import_endpoint_services(event, context):
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    endpoint_service_table = dynamodb.Table(
        os.environ['DYNAMODB_TABLE_ENDPOINT_SERVICES'])
    # ttl time to expire items in DynamoDB table, default 48 hours
    # ttl provided in seconds
    ttl_expire_time = (
        int(time.time()) + os.environ.get('TTL_EXPIRE_TIME', 172800))
    account = event['account']
    region = event['region']
    endpoint_services = endpoint_service_table.scan()['Items']

    ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = establish_role(account)
    client = boto3.client('ec2',
                          aws_access_key_id=ACCESS_KEY,
                          aws_secret_access_key=SECRET_KEY,
                          aws_session_token=SESSION_TOKEN,
                          region_name=region
                         )
    elbv2_client = boto3.client('elbv2',
                                aws_access_key_id=ACCESS_KEY,
                                aws_secret_access_key=SECRET_KEY,
                                aws_session_token=SESSION_TOKEN,
                                region_name=region
                                )

    logger.info(
        'Looking up endpoint details on account {} in region {}'
        .format(account, region))

    # Some Regions don't support this service yet,
    # capture and log these exceptions
    try:
        endpoint_services = client.describe_vpc_endpoint_service_configurations()
    except ClientError as e:
        if e.response['Error']['Message'] == endpoint_service_api_not_available:
            logger.error('Error: {}'.format(e))
            # Bail out here if AWS doesn't support Endpoint Services in region
            return logger.info(
                'VPC Endpoint Service is not available in {}'.format(region))
        elif e.response['Error']['Code'] == "UnauthorizedOperation":
            return logger.warning(
                f"Unable to access resources in {account}:{region}")
        else:
            return logger.error('Unknown error: {}'.format(
                e.response['Error']['Message']))

    for endpoint_srv in endpoint_services['ServiceConfigurations']:
        nlb_arns = {}
        service_id = endpoint_srv['ServiceId']
        service_name = endpoint_srv['ServiceName']
        service_state = endpoint_srv['ServiceState']
        acceptance_required = endpoint_srv['AcceptanceRequired']
        endpoint_service_nlb_arns = endpoint_srv['NetworkLoadBalancerArns']
        # Fetch tags of NLBs and map into a dictionary
        for nlb in endpoint_service_nlb_arns:
            nlb_tags_response = elbv2_client.describe_tags(
                ResourceArns=[nlb])
            nlb_tags = nlb_tags_response['TagDescriptions'][0]['Tags']
            nlb_arns.update({nlb: [nlb_tags]})

        logger.info(
            'Recording Endpoint Service: {0} to nlbs {1} for account {2}'
            .format(service_name, nlb_arns, account)
        )

        endpoint_service_table.put_item(
            Item={
                'id': service_id,
                'ServiceName': service_name,
                'AccountID': account,
                'ServiceState': service_state,
                'AcceptanceRequired': acceptance_required,
                'NetworkLoadBalancerArns': endpoint_service_nlb_arns,
                'Region': region,
                'NLBTags': nlb_arns,
                'ttl': ttl_expire_time
            }
        )
