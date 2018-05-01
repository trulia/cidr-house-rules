import json
import os
import sys
sys.path.insert(0, './vendor')
import boto3
import logging
import time
from sts import establish_role
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def locate_and_remove_duplicate_nat_id_entry(
    public_ip, nat_id, nat_table, nat_table_scan):
    """Function to test for a duplicate entry. This can happen if NAT gateway
    is created and deleted and the same public IP is reassigned to the account.
    this will discover and remove previous entry, by passing the TTL process.
    """
    for nat in nat_table_scan:
        if nat['PublicIp'] == public_ip and nat['id'] != nat_id:
            logger.info(
                f'Found previously recorded public IP:{public_ip}'
            )
            logger.info(f'Removing previous entry: {nat_id}')
            print(nat_id)
            print(public_ip)
            response = nat_table.delete_item(
                Key={
                    'id': nat_id
                }
            )

def import_nat_gateways(event, context):
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    nat_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_NAT_GATEWAYS'])
    nat_table_scan = nat_table.scan()['Items']
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
    nats = client.describe_nat_gateways()

    for nat in nats['NatGateways']:
        public_ip = nat['NatGatewayAddresses'][0]['PublicIp']
        nat_id = nat['NatGatewayId']
        nat_vpc_id = nat['VpcId']

        logger.info('Logging NAT Gateway: {0} for account {1}'.format(
            public_ip, account)
        )

        locate_and_remove_duplicate_nat_id_entry(
            public_ip, nat_id, nat_table, nat_table_scan
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
