import os
import sys
sys.path.insert(0, './vendor')
import boto3
import logging
import time
from sts import establish_role
from ttl_manager import ttl_manager
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def classic_elb_importer(classic_elbs, table, account, region, ttl_expire_time):
    for elb in classic_elbs['LoadBalancerDescriptions']:
        elb_dns_name = elb['DNSName']
        elb_name = elb['LoadBalancerName']
        logger.info(
            'Discovered Classic ELB in use: {0} with DNS: {1}'
            .format(elb_name, elb_dns_name))
        response = table.put_item(
            Item={
                'id': elb_dns_name,
                'LoadBalancerName': elb_name,
                'AccountID': account,
                'Region': region,
                'ttl': ttl_expire_time
            }
        )
        logger.info("Dynamodb response: {}".format(response))

def import_elbs(event, context):
    """Import AWS ELB resource
    """
    dynamodb = boto3.resource('dynamodb')
    elb_table_name = os.environ['DYNAMODB_TABLE_ELB']
    elb_table = dynamodb.Table(elb_table_name)
    account = event['account']
    region  = event['region']
    # ttl time to expire items in DynamoDB table, default 48 hours
    # ttl provided in seconds
    ttl_expire_time = (
        int(time.time()) + os.environ.get('TTL_EXPIRE_TIME', 172800))

    ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = establish_role(account)
    classic_elb_client = boto3.client('elb',
                                      aws_access_key_id=ACCESS_KEY,
                                      aws_secret_access_key=SECRET_KEY,
                                      aws_session_token=SESSION_TOKEN,
                                      region_name=region
                                      )
    try:
        classic_elbs = classic_elb_client.describe_load_balancers()
        # Ensure TTL is enabled on the table
        ttl_manager(True, elb_table_name, 'ttl') 
    except:
        logger.error(f'Unable to run describe_load_balancers AWS API call, disabling TTL on table')
        ttl_manager(False, elb_table_name, 'ttl')

    if not classic_elbs['LoadBalancerDescriptions']:
        logger.info("No ELBs allocated for account: {0} in region {1}"
                    .format(account, region))
    else:
        classic_elb_importer(
        classic_elbs, elb_table, account, region, ttl_expire_time)
