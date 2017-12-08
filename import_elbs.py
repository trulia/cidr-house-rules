import os
import sys
sys.path.insert(0, './vendor')
import boto3
import logging
import time
from sts import establish_role
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def classic_elb_importer(classic_elbs, acct_id, region, ttl_expire_time):
    for elb in classic_elbs['LoadBalancerDescriptions']:
        elb_dns_name = elb['DNSname']
        elb_name = elb['LoadBalancerName']
        logger.info(
            'Discovered Classic ELB in use: {0} with DNS: {1}'
            .format(elb_name, elb_dns_name))
        response = elb_table.put_item(
            Item={
                'id': elb_dns_name,
                'LoadBalancerName': elb_name,
                'AccountID': acct_id,
                'Region': region,
                'ttl': ttl_expire_time
            }
        )
        logger.info("Dynamodb response: {}".format(response))

def elbv2_importer(elbv2, acct_id, region, ttl_expire_time):
    for elb in elbv2['LoadBalancers']:
        elb_dns_name = elb['DNSname']
        elb_name = ""
        elb_arn = elb['LoadBalancerArn']
        logger.info(
            'Discovered ELBv2 in use: {0} with DNS: {1}'
            .format(elb_arn, elb_dns_name))
        response = elb_table.put_item(
            Item={
                'id': elb_dns_name,
                'LoadBalancerName': elb_name,
                'LoadBalancerArn': elb_arn,
                'AccountID': acct_id,
                'Region': region,
                'ttl': ttl_expire_time
            }
        )
        logger.info("Dynamodb response: {}".format(response))


def import_elbs(event, context):
    """Import AWS ELB, ALB, NLB resources
    """
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    elb_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ELB'])
    accounts_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ACCOUNTS'])
    accounts = accounts_table.scan()['Items']
    regions = [region['RegionName'] for region in client.describe_regions()['Regions']]

    for region in regions:
        for acct in accounts:
            acct_id = acct['id']
            ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = establish_role(acct)
            classic_elb_client = boto3.client('elb',
                                              aws_access_key_id=ACCESS_KEY,
                                              aws_secret_access_key=SECRET_KEY,
                                              aws_session_token=SESSION_TOKEN,
                                              region_name=region
                                              )
            elbv2_client = boto3.client('elbv2',
                                        aws_access_key_id=ACCESS_KEY,
                                        aws_secret_access_key=SECRET_KEY,
                                        aws_session_token=SESSION_TOKEN,
                                        region_name=region
                                        )
            classic_elbs = classic_elb_client.describe_load_balancers()
            elbsv2 = elbv2_client.describe_load_balancers()
            # ttl set to 48 hours
            ttl_expire_time = int(time.time()) + 172800

            if not classic_elbs['LoadBalancerDescriptions']:
                logger.info("No ELBs allocated for acct: {0} in region {1}"
                            .format(acct['id'], region))
            else:
                classic_elb_importer(
                    classic_elbs, acct_id, region, ttl_expire_time)

            if not elbsv2['LoadBalancers']:
                logger.info("No ELBv2s allocated for acct: {0} in region {1}"
                            .format(acct['id'], region))
            else:
                elbv2_importer(
                    elbsv2, acct_id, region, ttl_expire_time)