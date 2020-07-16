import os
import boto3
import logging
import time
from sts import establish_role
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def import_eips(event, context):
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    eip_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_EIP'])
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
        eips = client.describe_addresses()
    except ClientError as e:
        if e.response['Error']['Code'] == "UnauthorizedOperation":
            return logger.warning(
                f"Unable to access resources in {account}:{region}")

    if not eips['Addresses']:
        logger.info("No allocated EIPs for account: {0} in region {1}"
                    .format(account, region))
    else:
        for eip in eips['Addresses']:
            eip_address = eip['PublicIp']
            if 'AssociationId' in eip:
                eip_association_id = eip['AssociationId']
            else:
                logger.info(
                    "No AllocadtionId found for EIP {0} in account {1} {2}"
                    .format(eip_address, account, region))
                eip_association_id = "none"
            if 'AllocationId' in eip:
                eip_id = eip['AllocationId']
            else:
                logger.info(
                    "No AllocadtionId found for EIP {0} in account {1} {2}"
                    .format(eip_address, account, region))
                eip_id = "none"

            logger.info('Discovered EIP in use: {0} with ID: {1}'
                        .format(eip_address, eip_id))

            eip_table.put_item(
                Item={
                    'id': eip_address,
                    'AllocationId': eip_id,
                    'AccountID': account,
                    'AssociationId': eip_association_id,
                    'Region': region,
                    'ttl': ttl_expire_time
                }
            )
