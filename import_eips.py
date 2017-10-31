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
    accounts_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ACCOUNTS'])
    accounts = accounts_table.scan()['Items']
    regions = [region['RegionName'] for region in client.describe_regions()['Regions']]

    for region in regions:
        for acct in accounts:
            ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = establish_role(acct)
            client = boto3.client('ec2',
                                  aws_access_key_id=ACCESS_KEY,
                                  aws_secret_access_key=SECRET_KEY,
                                  aws_session_token=SESSION_TOKEN,
                                  region_name=region
                                 )
            eips = client.describe_addresses()
            if not eips['Addresses']:
                logger.info("No allocated EIPs for acct: {0} in region {1}"
                            .format(acct['id'], region))
            else:
                for eip in eips['Addresses']:
                    acct_id = acct['id']
                    eip_address = eip['PublicIp']
                    if 'AssociationId' in eip:
                        eip_association_id = eip['AssociationId']
                    else:
                        logger.info(
                            "No AllocadtionId found for EIP {0} in acct {1} {2}"
                                    .format(eip_address, acct['id'], region))
                        eip_association_id = "none"
                    if 'AllocationId' in eip:
                        eip_id = eip['AllocationId']
                    else:
                        logger.info(
                            "No AllocadtionId found for EIP {0} in acct {1} {2}"
                                    .format(eip_address, acct['id'], region))
                        eip_id = "none"

                    logger.info('Discovered EIP in use: {0} with ID: {1}'
                                .format(eip_address, eip_id))

                    response = eip_table.put_item(
                        Item={
                            'id': eip_address,
                            'AllocationId': eip_id,
                            'AccountID': acct_id,
                            'AssociationId': eip_association_id,
                            'Region': region
                        },
                        ConditionExpression='attribute_not_exists(eip_id)'
                    )
                    logger.info("Dynamodb response: {}".format(response))
