import os
import sys
import time
import boto3
import logging
from sts import establish_role
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def import_cidrs(event, context):
    """
    Take event data which should include AWS account and region and import
    CIDR blocks that are in use
    """
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    cidr_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_CIDRS'])
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
                          region_name=region
                         )
    try:
        vpcs = client.describe_vpcs()
    except ClientError as e:
        if e.response['Error']['Code'] == "UnauthorizedOperation":
            return logger.warning(
                f"Unable to access resources in {account}:{region}")

    for vpc in vpcs['Vpcs']:
        vpc_cidr = vpc['CidrBlock']
        vpc_id = vpc['VpcId']
        unique_id = "{0}{1}{2}{3}".format(
            account, vpc_cidr, region, vpc_id)

        logger.info(
            "Found vpc-id: {0} and cidr: {1} ({2}) from "
            "account {3} in Dyanmodb".format(
                vpc['VpcId'], vpc['CidrBlock'], region, account
            )
        )

        cidr_table.put_item(
            Item={
                'id': unique_id,
                'cidr': vpc_cidr,
                'AccountID': account,
                'Region': region,
                'VpcId': vpc_id,
            },
            ConditionExpression='attribute_not_exists(unique_id)'
        )

        if 'CidrBlockAssociationSet' in vpc:
            for cidr_associaton in vpc['CidrBlockAssociationSet']:
                cidr_state = cidr_associaton['CidrBlockState']['State']
                if cidr_state == "associated":
                    unique_id = ("{0}{1}{2}{3}".format(
                        account,
                        cidr_associaton['CidrBlock'],
                        region, vpc_id))
                    cidr_table.put_item(
                        Item={
                            'id': unique_id,
                            'cidr': cidr_associaton['CidrBlock'],
                            'AccountID': account,
                            'Region': region,
                            'VpcId': vpc_id,
                            'ttl': ttl_expire_time
                        }
                    )
                else:
                    logger.info("CIDR: {} not associated".format(
                        cidr_associaton['CidrBlock']))
