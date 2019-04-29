import json
import os
import boto3
import logging
import time
from sts import establish_role
from ttl_manager import ttl_manager
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def import_nat_gateways(event, context):
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    nat_table_name = os.environ['DYNAMODB_TABLE_NAT_GATEWAYS']
    nat_table = dynamodb.Table(nat_table_name)
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
        nats = client.describe_nat_gateways()
        # Ensure TTL is enabled on the table
        ttl_manager(True, nat_table_name, 'ttl') 
    except:
        logger.error(f'Unable to run describe_nat_gateways AWS API call, disabling TTL on table {nat_table_name}')
        ttl_manager(False, nat_table_name, 'ttl')

    for nat in nats['NatGateways']:
        public_ip = nat['NatGatewayAddresses'][0]['PublicIp']
        nat_id = nat['NatGatewayId']
        nat_vpc_id = nat['VpcId']

        logger.info('Logging NAT Gateway: {0} for account {1}'.format(
            public_ip, account)
        )

        response = nat_table.put_item(
            Item={
                'id': nat_id,
                'PublicIp': public_ip,
                'AccountID': account,
                'VpcId': nat_vpc_id,
                'Region': region,
                'ttl': ttl_expire_time
            }
        )
