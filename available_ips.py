import boto3
import logging
import os
import time
from sts import establish_role
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def available_ips(event, context):
    """
    Take in event data which should contain AWS account and region and
    record AvailableIpAddressCount for all subnets in all regions
    """

    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    available_ips_table = dynamodb.Table(
        os.environ['DYNAMODB_TABLE_AVAILABLE_IPS'])
    account = event['account']
    region = event['region']
    # ttl time to expire items in DynamoDB table, default 48 hours
    # ttl provided in seconds
    ttl_expire_time = (
        int(time.time()) + os.environ.get('TTL_EXPIRE_TIME', 172800))

    ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = establish_role(account)
    client = boto3.client('ec2',
                          aws_access_key_id=ACCESS_KEY,
                          aws_secret_access_key=SECRET_KEY,
                          aws_session_token=SESSION_TOKEN,
                          region_name=region)

    try:
        subnets = client.describe_subnets()
    except ClientError as e:
        if e.response['Error']['Code'] == "UnauthorizedOperation":
            return logger.warning(
                f"Unable to access resources in {account}:{region}")

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

            logger.info(f"Found subnet {subnet_id} in vpc {vpc_id} {region}")
            available_ips_table.put_item(
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
