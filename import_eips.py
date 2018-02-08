import json
import os
import boto3
import logging
from sts import establish_role
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def import_eips(event, context):
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    eip_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_EIP'])
    account = event['account']
    region  = event['region']

    ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = establish_role(account)
    client = boto3.client('ec2',
                          aws_access_key_id=ACCESS_KEY,
                          aws_secret_access_key=SECRET_KEY,
                          aws_session_token=SESSION_TOKEN,
                          region_name=region
                         )
    eips = client.describe_addresses()
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

            response = eip_table.put_item(
                Item={
                    'id': eip_address,
                    'AllocationId': eip_id,
                    'AccountID': account, 
                    'AssociationId': eip_association_id,
                    'Region': region
                },
                ConditionExpression='attribute_not_exists(eip_id)'
            )
            logger.info("Dynamodb response: {}".format(response))
