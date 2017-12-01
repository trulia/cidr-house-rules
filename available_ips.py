import boto3
import logging
import os
import sys
sys.path.insert(0, './vendor')
from sts import establish_role
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def available_ips(event, context):
    """Record AvailableIpAddressCount for all subnets in all regions
    """
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    available_ips_table = dynamodb.Table(
        os.environ['DYNAMODB_TABLE_AVAILABLE_IPS'])
    accounts_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ACCOUNTS'])
    accounts = accounts_table.scan()['Items']
    regions = ([region['RegionName']
                for region in client.describe_regions()['Regions']])

    for region in regions:
        for acct in accounts:
            ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = establish_role(acct)
            client = boto3.client('ec2',
                                  aws_access_key_id=ACCESS_KEY,
                                  aws_secret_access_key=SECRET_KEY,
                                  aws_session_token=SESSION_TOKEN,
                                  region_name=region
                                 )
            subnets = client.describe_subnets()
            if not subnets['Subnets']:
                logger.info("No allocated subnets for acct: {0} in region {1}"
                            .format(acct['id'], region))
            else:
                for subnet in subnets['Subnets']:
                    vpc_id = subnet['VpcId']
                    available_ips = str(subnet['AvailableIpAddressCount'])
                    acct_id = acct['id']
                    subnet_id = subnet['SubnetId']
                    subnet = subnet['CidrBlock']
                    unique_id = f'{acct_id}{vpc_id}{subnet_id}{subnet}'

                    response = available_ips_table.put_item(
                        Item={
                            'id': unique_id,
                            'VpcId': vpc_id,
                            'AccountID': acct_id,
                            'SubnetId': subnet_id,
                            'Subnet': subnet,
                            'Region': region,
                            'AvailableIpAddressCount': available_ips
                        }
                    )
                    logger.info("Dynamodb response: {}".format(response))
