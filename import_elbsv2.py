import os
import boto3
import logging
import time
from sts import establish_role
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def elbv2_importer(
        elbv2, table, account, region, ttl_expire_time):
    for elb in elbv2['LoadBalancers']:
        elb_dns_name = elb['DNSName']
        elb_name = "NA"
        elb_arn = elb['LoadBalancerArn']
        logger.info(
            'Discovered ELBv2 in use: {0} with DNS: {1}'
            .format(elb_arn, elb_dns_name))
        table.put_item(
            Item={
                'id': elb_dns_name,
                'LoadBalancerName': elb_name,
                'LoadBalancerArn': elb_arn,
                'AccountID': account,
                'Region': region,
                'ttl': ttl_expire_time
            }
        )


def import_elbs(event, context):
    """Import AWS ALB, NLB resources
    """
    dynamodb = boto3.resource('dynamodb')
    elb_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ELB'])
    account = event['account']
    region = event['region']
    elbsv2 = {}
    # ttl time to expire items in DynamoDB table, default 48 hours
    # ttl provided in seconds
    ttl_expire_time = (
        int(time.time()) + os.environ.get('TTL_EXPIRE_TIME', 172800))

    ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = establish_role(account)
    elbv2_client = boto3.client('elbv2',
                                aws_access_key_id=ACCESS_KEY,
                                aws_secret_access_key=SECRET_KEY,
                                aws_session_token=SESSION_TOKEN,
                                region_name=region
                                )
    try:
        elbsv2 = elbv2_client.describe_load_balancers()
    except ClientError as e:
        if e.response['Error']['Code'] == "UnauthorizedOperation":
            return logger.warning(
                f"Unable to access resources in {account}:{region}")

    if 'LoadBalancers' not in elbsv2:
        logger.info("No ELBv2s allocated for account: {0} in region {1}"
                    .format(account, region))
    else:
        elbv2_importer(
            elbsv2, elb_table, account, region, ttl_expire_time)
