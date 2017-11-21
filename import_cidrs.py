import os
import sys
sys.path.insert(0, './vendor')
import boto3
import logging
from sts import establish_role
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def import_cidrs(event, context):
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    cidr_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_CIDRS'])
    accounts_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ACCOUNTS'])
    accounts = accounts_table.scan()['Items']
    cidrs = cidr_table.scan()['Items']
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
            vpcs = client.describe_vpcs()

            for vpc in vpcs['Vpcs']:
                acct_id = acct['id']
                vpc_cidr = vpc['CidrBlock']
                vpc_id = vpc['VpcId']
                unique_id = "{0}{1}{2}{3}".format(
                    acct_id, vpc_cidr, region, vpc_id)

                logger.info(
                "Found vpc-id: {0} and cidr: {1} ({2}) from "
                "account {3} in Dyanmodb".format(
                    vpc['VpcId'], vpc['CidrBlock'], region, acct['id']
                    )
                )

                response = cidr_table.put_item(
                    Item={
                        'id': unique_id,
                        'cidr': vpc_cidr,
                        'AccountID': acct_id,
                        'Region': region,
                        'VpcId': vpc_id,
                    },
                    ConditionExpression='attribute_not_exists(unique_id)'
                )
                logger.info("Dynamodb response: {}".format(response))

                if 'CidrBlockAssociationSet' in vpc:
                    for cidr_associaton in vpc['CidrBlockAssociationSet']:
                        cidr_state = cidr_associaton['CidrBlockState']['State']
                        if cidr_state == "associated":
                            unique_id = ("{0}{1}{2}{3}".format(
                                acct_id,
                                cidr_associaton['CidrBlock'],
                                region, vpc_id))
                            response = cidr_table.put_item(
                                Item={
                                    'id': unique_id,
                                    'cidr': cidr_associaton['CidrBlock'],
                                    'AccountID': acct_id,
                                    'Region': region,
                                    'VpcId': vpc_id,
                                },
                                ConditionExpression=(
                                    'attribute_not_exists(unique_id)')
                            )
                            logger.info("Dynamodb response: {}".format(response))
                        else:
                            logger.info("CIDR: {} not associated".format(
                                cidr_associaton['CidrBlock']))
