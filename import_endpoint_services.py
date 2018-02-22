import json
import os
import boto3
import uuid
import sys
sys.path.insert(0, './vendor')
import time
import logging
from sts import establish_role
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Error message provided if service is not available in a region yet.
endpoint_service_api_not_available = """An error occurred \
(AuthFailure) when calling the DescribeVpcEndpointServiceConfigurations \
operation: This request has been administratively disabled."""

def import_endpoint_services(event, context):
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    endpoint_service_table = dynamodb.Table(
        os.environ['DYNAMODB_TABLE_ENDPOINT_SERVICES'])
    account = event['account']
    region  = event['region']
    endpoint_services = endpoint_service_table.scan()['Items']

    ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = establish_role(account)
    client = boto3.client('ec2',
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
    except client.exceptions.ClientError as e:
        if e.response['Error']['Message'] == endpoint_service_api_not_available:
            logger.info(
                'VPC Endpoint Service is not available in {}').format(region)
            logger.error('Error: {}'.format(e))
            sys.exit(0)
        else:
            logger.error('Unknown error: {}'.format(e.response['Error'['Message']]))
            sys.exit(1)

    for endpoint_srv in endpoint_services['ServiceConfigurations']:
        service_id = endpoint_srv['ServiceId']
        service_name = endpoint_srv['ServiceName']
        service_state= endpoint_srv['ServiceState']
        acceptance_required = endpoint_srv['AcceptanceRequired']
        nlb_arns = endpoint_srv['NetworkLoadBalancerArns']
        # ttl set to 48 hours
        ttl_expire_time = int(time.time()) + 172800

        logger.info(
            'Recording Endpoint Service: {0} to nlbs {1} for account {2}'
            .format(service_name, nlb_arns, account)
        )

        response = endpoint_service_table.put_item(
            Item={
                'id': service_id,
                'ServiceName': service_name,
                'AccountID': account,
                'ServiceState': service_state,
                'AcceptanceRequired': acceptance_required,
                'NetworkLoadBalancerArns': nlb_arns,
                'Region': region,
                'ttl': ttl_expire_time
            }
        )
