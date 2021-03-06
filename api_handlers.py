import json
import os
import boto3
import ipaddress
import logging
import math
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
        return _return_422('Invalid CIDR input')

    for cidr in cidrs:
        compare_input_cidr = ipaddress.ip_network(input_cidr)
        known_cidr = ipaddress.ip_network(cidr['cidr'])

        if compare_input_cidr.overlaps(known_cidr):
            return _return_200(
                f'''*** Warning, CIDR overlaps with another AWS acct ***
                Account: {cidr['AccountID']}
                Region: {cidr['Region']}
                VpcId: {cidr['VpcId']}
                CIDR: {cidr['cidr']}
                ''')
    else:
        return _return_200('OK, no CIDR conflicts')

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
        return _return_200("OK")

    except ValueError:
        _return_422('Invalid input')

def get_number_of_nat_gateway_pages(event, context):
    """Get the number of pages of NAT gateways with given number of results per
    page with ?results_per_page parameter"""

    logger.info(f'DEBUG: {event}')

    dynamodb = boto3.resource('dynamodb')
    nat_gateways_table = dynamodb.Table(
        os.environ['DYNAMODB_TABLE_NAT_GATEWAYS'])

    try:
        response = []
        nat_gateways = nat_gateways_table.scan()
        for n in nat_gateways['Items']:
            response.append(n['PublicIp'] + '/32')

        results_per_page = _check_results_per_page(event)

        logger.info(f'response: {response}')
        pages = math.ceil(len(response) / results_per_page)
        logger.info(f'pages: {pages}')

        return _return_200(pages)

    except ValueError:
        _return_422('Invalid input')

def get_nat_gateways_for_all(event, context):
    """Return NAT Gateways for all teams. Optional, pagination with ?page and
    ?results_per_page URI query parameters"""

    logger.info(f'DEBUG: {event}')

    dynamodb = boto3.resource('dynamodb')
    nat_gateways_table = dynamodb.Table(
        os.environ['DYNAMODB_TABLE_NAT_GATEWAYS'])

    try:
        response = []
        nat_gateways = nat_gateways_table.scan()
        for n in nat_gateways['Items']:
            response.append(n['PublicIp'] + '/32')

        results_per_page = _check_results_per_page(event)

        if event['queryStringParameters']:
            if event['queryStringParameters']['page']:
                page = int(event['queryStringParameters']['page'])
                logger.info(f'response: {response}')
                paged_response = _ip_list_pagination(
                    response, results_per_page)
                logger.info(f'paged_response: {paged_response}')
                # formatted_response should be the page requested
                formatted_response = _ip_list_formatter(paged_response[0 + page])
                logger.info(f'formatted_response: {formatted_response}')
        else:
            formatted_response = _ip_list_formatter(response)

        if not formatted_response:
            _no_items_found("NAT Gateway", "All accounts")

        return _return_200(formatted_response)

    except ValueError:
        return _return_422('Invalid input')

def get_nat_gateways_for_team(event, context):
    dynamodb = boto3.resource('dynamodb')
    accounts_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ACCOUNTS'])
    nat_gateways_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_NAT_GATEWAYS'])
    if 'team' in event['queryStringParameters']:
        input_teams = [event['queryStringParameters']['team']]
    else:
        input_teams = event['queryStringParameters']
    response = []
    logger.info(f'Event: {event}')

    if not input_teams:
        return _return_422(
            'Invalid input. Provide atleast 1 team as query parameter')

    try:
        for team in input_teams:
            accounts = accounts_table.scan()
            for a in accounts['Items']:
                if a['team'] == team:
                    account_id = a['id']

            nat_gateways = nat_gateways_table.scan()
            for n in nat_gateways['Items']:
                if n['AccountID'] == account_id:
                    response.append(n['PublicIp'] + '/32')

        formatted_response = _ip_list_formatter(response)

        if not formatted_response:
            _no_items_found("NAT Gateway", account_id)
        logger.info(f'NAT gatways: {formatted_response}')
        return _return_200(formatted_response)

    except ValueError:
        return _return_422('Invalid input')

def get_elbs_for_all(event, context):
    dynamodb = boto3.resource('dynamodb')
    elbs_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ELB'])

    try:
        response = []
        elbs = elbs_table.scan()
        for elb in elbs['Items']:
            response.append(elb['id'])

        return _return_200(str(json.dumps(response)))

    except ValueError:
        return _return_404("Unable to scan elbs table")

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

        return _return_200(str(json.dumps(response)))

    except ValueError:
        _return_422('Invalid input')

def get_service_endpoints_for_all(event, context):
    dynamodb = boto3.resource('dynamodb')
    endpoint_services_table = dynamodb.Table(
        os.environ['DYNAMODB_TABLE_ENDPOINT_SERVICES'])

    try:
        response = []
        endpoint_services = endpoint_services_table.scan()
        for endpoint in endpoint_services['Items']:
            response.append(endpoint['ServiceName'])

        return _return_200(str(json.dumps(response)))

    except ValueError:
        _return_404('Unable to scan endpoint_services table')

def get_service_endpoint_for_nlb(event, context):
    dynamodb = boto3.resource('dynamodb')
    endpoint_services_table = dynamodb.Table(
        os.environ['DYNAMODB_TABLE_ENDPOINT_SERVICES'])
    nlb_name = event['queryStringParameters']['nlb']

    # Expects the NLB to be tagged with a 'Name' key
    # Find NLBs that have a "Name" tag and compare with event input nlb_name
    try:
        response = ""
        endpoint_services = endpoint_services_table.scan()
        for endpoint in endpoint_services['Items']:
            for arn in endpoint['NetworkLoadBalancerArns']:
                nlb_tags = endpoint.get('NLBTags', None)
                if nlb_tags:
                    for tags in nlb_tags[arn][0]:
                        if (tags.get('Key')) == 'Name':
                            if tags.get('Value') == nlb_name:
                                response = endpoint['ServiceName']

        return _return_200(str(json.dumps(response)))

    except ValueError:
        _return_404(f'Unable to find NLB with Name tag {nlb_name}')

def _ip_list_formatter(ip_list):
    """Create a repsponse that looks like this:
    50.112.204.31/32,50.112.53.175/32,52.34.22.83/32,52.38.146.43/32
    """
    formatted_response = (str(ip_list)
    .strip("[")
    .strip("]")
    .replace('\'','')
    .replace(" ",""))
    return formatted_response

def _ip_list_pagination(ip_list, results_per_page):
    """Return paginated results for list of ips."""
    paged_response = [ip_list[i:i+results_per_page]
     for i in range(0, len(ip_list), results_per_page)]
    return paged_response

def _no_items_found(service, account_id):
    """Return 422 response code when items not found in DynamoDB"""
    logger.info(f'No {service} for account: {account_id}')
    return {
        "statusCode": 422,
        "body": f'No {service} found for account: {account_id}'
    }

def _check_results_per_page(event):
    if event['queryStringParameters']:
        if event['queryStringParameters']['results_per_page']:
            results_per_page = (
                int(event['queryStringParameters']['results_per_page']))
    else:
        # Default to 50 results per page if parameter not given
        results_per_page = 50

    return results_per_page

def _return_200(response_body):
    """Return 200 response with provided body message"""
    return {
        "statusCode": 200,
        "body": response_body
        }

def _return_404(response_body):
    """Return 404 response with provided body message"""
    return {
        "statusCode": 404,
        "body": response_body
    }

def _return_422(response_body):
    """Return 422 response with provided body message"""
    return {
        "statusCode": 422,
        "body": response_body
    }
