import json
import os
import boto3
import ipaddress
import logging
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def check_conflict(event, context):
    """Take in a CIDR block and check for conflicts against all known blocks
    to cidr-house-rules
    """
    dynamodb = boto3.resource('dynamodb')
    cidr_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_CIDRS'])
    input_cidr = event['queryStringParameters']['cidr']
    cidrs = cidr_table.scan()['Items']

    try:
        ipaddress.ip_network(input_cidr)
    except ValueError:
        return {
            "statusCode": 422,
            "body": 'Invalid CIDR input'
        }

    for cidr in cidrs:
        compare_input_cidr = ipaddress.ip_network(input_cidr)
        known_cidr = ipaddress.ip_network(cidr['cidr'])

        if compare_input_cidr.overlaps(known_cidr):
            return ({ "statusCode": 200, "body":
            '''*** Warning, CIDR overlaps with another with another AWS acct ***
            Account: {0}
            Region: {1}
            VpcId: {2}
            CIDR: {3}
            '''.format(
            cidr['AccountID'], cidr['Region'], cidr['VpcId'],
            cidr['cidr'])
            })
    else:
        return { "statusCode": 200, "body": 'OK, no CIDR conflicts' }

def add_account(event, context):
    dynamodb = boto3.resource('dynamodb')
    accounts_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ACCOUNTS'])
    input_account = event['queryStringParameters']['account']
    input_team = event['queryStringParameters']['team']
    try:
        response = accounts_table.put_item(
            Item={
                'id': input_account,
                'team': input_team
            })
        return {
                "statusCode": 200,
                "body": 'OK'
            }
    except ValueError:
        return {
            "statusCode": 422,
            "body": 'Invalid input'
        }

def get_nat_gateways_for_team(event, context):
    dynamodb = boto3.resource('dynamodb')
    accounts_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ACCOUNTS'])
    nat_gateways_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_NAT_GATEWAYS'])
    input_team = event['queryStringParameters']['team']

    try:
        accounts = accounts_table.scan()
        for a in accounts['Items']:
            if a['team'] == input_team:
                account_id = a['id']

        response = []
        nat_gateways = nat_gateways_table.scan()
        for n in nat_gateways['Items']:
            if n['AccountID'] == account_id:
                response.append(n['PublicIp'] + '/32')

        #Create a repsponse that looks like this:
        #50.112.204.31/32,50.112.53.175/32,52.34.22.83/32,52.38.146.43/32
        formatted_response = (str(response)
        .strip("[")
        .strip("]")
        .replace('\'','')
        .replace(" ",""))

        if not formatted_response:
            logger.info("No NAT Gateways for account: {}".format(account_id))
            return {
                "statusCode": 422,
                "body": "No NAT Gateways found for account: {}"
                .format(account_id)
            }

        logger.info("Here is the formatted response for NAT gatways: {}"
                    .format(formatted_response))

        return {
                "statusCode": 200,
                "body": formatted_response
               }

    except ValueError:
        return {
            "statusCode": 422,
            "body": 'Invalid input'
        }

def get_eips_for_team(event, context):
    dynamodb = boto3.resource('dynamodb')
    accounts_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ACCOUNTS'])
    eips_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_EIP'])
    input_team = event['queryStringParameters']['team']

    try:
        accounts = accounts_table.scan()
        for a in accounts['Items']:
            if a['team'] == input_team:
                account_id = a['id']

        response = []
        eips = eips_table.scan()
        for e in eips['Items']:
            if e['AccountID'] == account_id:
                response.append(e['PublicIp'] + '/32')

        #TODO error out if response is empty
        print(response)

        return {
                "statusCode": 200,
                "body": str(json.dumps(response))
        }
    except ValueError:
        return {
            "statusCode": 422,
            "body": 'Invalid input'
        }
