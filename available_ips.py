import boto3
import logging
import os
import sys
import time
sys.path.insert(0, './vendor')
from sts import establish_role
from ttl_manager import ttl_manager
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def available_ips(event, context):
    """
    Take in event data which should contain AWS account and region and
    record AvailableIpAddressCount for all subnets in all regions
    """

    dynamodb = boto3.resource('dynamodb')
    available_ips_table_name = os.environ['DYNAMODB_TABLE_AVAILABLE_IPS']
    available_ips_table = dynamodb.Table(available_ips_table_name)
    account = event['account']
    region  = event['region']
    # ttl time to expire items in DynamoDB table, default 48 hours
    # ttl provided in seconds
    ttl_expire_time = (
        int(time.time()) + os.environ.get('TTL_EXPIRE_TIME', 172800))

    ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = establish_role(account)
    client = boto3.client('ec2',
                          aws_access_key_id=ACCESS_KEY,
                          aws_secret_access_key=SECRET_KEY,
                          aws_session_token=SESSION_TOKEN,
                          region_name=region
                         )
    try:
        subnets = client.describe_subnets()
        # Ensure TTL is enabled on the table
        ttl_manager(True, available_ips_table_name, 'ttl') 
    except:
        logger.error(f'Unable to run describe_subnets AWS API call, disabling TTL on table: {available_ips_table_name}')
        ttl_manager(False, available_ips_table_name, 'ttl')

    if not subnets['Subnets']:
        logger.info("No allocated subnets for account: {0} in region {1}"
                    .format(account, region))
    else:
        for subnet in subnets['Subnets']:
            vpc_id = subnet['VpcId']
            available_ips = str(subnet['AvailableIpAddressCount'])
            subnet_id = subnet['SubnetId']
            subnet = subnet['CidrBlock']
            unique_id = f'{account}{vpc_id}{subnet_id}{subnet}'

            response = available_ips_table.put_item(
                Item={
                    'id': unique_id,
                    'VpcId': vpc_id,
                    'AccountID': account,
                    'SubnetId': subnet_id,
                    'Subnet': subnet,
                    'Region': region,
                    'AvailableIpAddressCount': available_ips,
                    'ttl': ttl_expire_time
                }
            )
            logger.info("Dynamodb response: {}".format(response))
