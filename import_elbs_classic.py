import os
import boto3
import logging
import time
from sts import establish_role
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def classic_elb_importer(
        classic_elbs, table, account, region, ttl_expire_time):
    for elb in classic_elbs['LoadBalancerDescriptions']:
        elb_dns_name = elb['DNSName']
        elb_name = elb['LoadBalancerName']
        logger.info(
            'Discovered Classic ELB in use: {0} with DNS: {1}'
            .format(elb_name, elb_dns_name))
        table.put_item(
            Item={
                'id': elb_dns_name,
                'LoadBalancerName': elb_name,
                'AccountID': account,
                'Region': region,
                'ttl': ttl_expire_time
            }
        )


def import_elbs(event, context):
    """Import AWS ELB resource
    """
    dynamodb = boto3.resource('dynamodb')
    elb_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ELB'])
    account = event['account']
    region = event['region']
    classic_elbs = {}
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
    except ClientError as e:
        if e.response['Error']['Code'] == "UnauthorizedOperation":
            return logger.warning(
                f"Unable to access resources in {account}:{region}")

    if not classic_elbs['LoadBalancerDescriptions']:
        logger.info("No ELBs allocated for account: {0} in region {1}"
                    .format(account, region))
    else:
        classic_elb_importer(
            classic_elbs, elb_table, account, region, ttl_expire_time)
