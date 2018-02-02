import boto3
import logging
import os
import sys
import time
sys.path.insert(0, './vendor')
from sts import establish_role
from boto3.dynamodb.conditions import Key, Attr

environment = os.environ['ENV']
dynamodb = boto3.resource('dynamodb')
lambda_client = boto3.client('lambda')

accounts_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ACCOUNTS'])
accounts = accounts_table.scan()['Items']
regions = ([region['RegionName']
                for region in client.describe_regions()['Regions']])

def invoke_process(fuction_name):
    invoke_scanner_payload = (
        json.JSONEncoder().encode(
            {
                "account": host['AccountID'],
                "region": host['Region']
            }
        )
    )
    lambda_client.invoke(
        FunctionName=fuction_name
            'cidr-house-rules-port-scan-{}-invoke_scanner'.format(environment)
        InvocationType='Event',
        Payload=invoke_scanner_payload,
    )

def runner(event, context):
    """Launch child import processes on a per account, per region basis
    """

    logger.info('Running available_ips...')
    for region in regions:
        for acct in accounts:
            logger.info(
"""
Invoking cidr-house-rules-{0}-available_ips on account {1} in region {2}
""".format(environment, acct['id'], region)
            )
            invoke_process(
                'cidr-house-rules-{}-available_ips'.format(environment)
            )
