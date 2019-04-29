import json
import os
import boto3
import uuid
import sys
sys.path.insert(0, './vendor')
import time
import logging
from sts import establish_role
from ttl_manager import ttl_manager
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Error message provided if service is not available in a region yet.
endpoint_service_api_not_available = (
    "This request has been administratively disabled.")

def import_endpoint_services(event, context):
    dynamodb = boto3.resource('dynamodb')
    endpoint_service_table_name = os.environ['DYNAMODB_TABLE_ENDPOINT_SERVICES']
    endpoint_service_table = dynamodb.Table(endpoint_service_table_name)
    # ttl time to expire items in DynamoDB table, default 48 hours
    # ttl provided in seconds
    ttl_expire_time = (
        int(time.time()) + os.environ.get('TTL_EXPIRE_TIME', 172800))
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
        ttl_manager(True, endpoint_service_table_name, 'ttl') 
    except client.exceptions.ClientError as e:
        if e.response['Error']['Message'] == endpoint_service_api_not_available:
            logger.error('Error: {}'.format(e))
            # Bail out here if AWS doesn't support Endpoint Services in region
            return logger.info(
                'VPC Endpoint Service is not available in {}'.format(region))
        else:
            ttl_manager(True, endpoint_service_table_name, 'ttl') 
            return logger.error(
                f'Unknown error, disabling dynamodb TTL on table {endpoint_service_table_name}: {e.response["Error"]["Message"]}')

    for endpoint_srv in endpoint_services['ServiceConfigurations']:
        nlb_arns = {}
        service_id = endpoint_srv['ServiceId']
        service_name = endpoint_srv['ServiceName']
        service_state= endpoint_srv['ServiceState']
        acceptance_required = endpoint_srv['AcceptanceRequired']
        endpoint_service_nlb_arns = endpoint_srv['NetworkLoadBalancerArns']
        # Fetch tags of NLBs and map into a dictionary
        for nlb in endpoint_service_nlb_arns:
            try:
                nlb_tags_response = elbv2_client.describe_tags(
                    ResourceArns=[nlb])
                # Ensure TTL is enabled on the table
                ttl_manager(True, endpoint_service_table_name, 'ttl') 
            except:
                logger.error(f'Unable to run describe_tags AWS API call, disabling TTL on table')
                ttl_manager(False, endpoint_service_table_name, 'ttl')
            nlb_tags = nlb_tags_response['TagDescriptions'][0]['Tags']
            nlb_arns.update({nlb: [nlb_tags]})

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
                'NetworkLoadBalancerArns': endpoint_service_nlb_arns,
                'Region': region,
                'NLBTags': nlb_arns,
                'ttl': ttl_expire_time
            }
        )
