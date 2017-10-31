import json
import os
import boto3
import uuid
import logging
from sts import establish_role
from boto3.dynamodb.conditions import Key, Attr

def prune_tables(event, context):
    recorded_eips = {}
    recorded_cidrs = {}
    recorded_nats = {}
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    nat_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_NAT_GATEWAYS'])
    cidr_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_CIDRS'])
    eips_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_EIP'])
    accounts_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ACCOUNTS'])
    accounts = accounts_table.scan()['Items']
    cidrs = cidr_table.scan()['Items']
    nats = client.describe_nat_gateways()
    vpcs = client.describe_vpcs()
    eips = client.describe_addresses()
    response = cidr_table.scan(AttributesToGet=['id','AccountID','Region','VpcId','cidr'])['Items']
    scan_nats_table = nat_table.scan(AttributesToGet=['id','AccountID','PublicIp','VpcId'])['Items']
    scan_eips_table = eips_table.scan(AttributesToGet=['id','AccountID','Region'])['Items']
    for i in response:
        id = i['VpcId']
        recorded_cidrs[id] = [i['id'],i['cidr'], i['Region'], i['AccountID']]

    for j in scan_nats_table:
        nats_id = j['id']
        recorded_nats[nats_id] = [j['AccountID'], j['PublicIp'], j['VpcId']]

    for j in scan_eips_table:
        eips_id = j['id']
        recorded_eips[eips_id] = [j['AccountID'], j['Region']]

    cidrs_keys_list = [k for k, v in recorded_cidrs.items() if (v[3] == acct and v[2] == region)]
    nats_keys_list = [k for k, v in recorded_nats.items() if (v[0] == acct)]
    eips_keys_list = [k for k, v in recorded_eips.items() if (v[0] == acct)]
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
        cidr_removals = []
        nat_removals = []
        eip_removals = []
        active_cidrs = {}
        active_nats = {}
        active_eips = {}
        for vpc in vpcs['Vpcs']:
            id = vpc['VpcId']
            active_cidrs[id] = [vpc['CidrBlock'], region, acct]

        for nat in nats['NatGateways']:
            public_ip = nat['NatGatewayAddresses'][0]['PublicIp']
            nat_id = nat['NatGatewayId']
            nat_vpc_id = nat['VpcId']
	        active_nats[nat_id] = [nat_id, public_ip, region, acct]

        for eip in eips['Addresses']:
            acct_id = acct['id']
            eip_address = eip['PublicIp']
            if 'AssociationId' in eip:
                eip_association_id = eip['AssociationId']
            else:
                eip_association_id = "none"
                if 'AllocationId' in eip:
                eip_id = eip['AllocationId']
            else:
                eip_id = "none"
            active_eips[eip_address] = [eip_id, eip_association_id, region, acct]

        cidr_keys = list(active_cidrs)
        nats_keys = list(active_cidrs)
        eips_keys = list(active_eips)

        cidr_removals = [x for x in cidrs_keys_list if x not in cidr_keys]
        nat_removals = [x for x in nats_keys_list if x not in nats_keys]
        eip_removals = [x for x in eips_keys_list if x not in eips_keys]

        for r in nat_removals:
            id = r
            print ("Removing \"%s\" NAT from %s" % (id, os.environ['DYNAMODB_TABLE_NAT_GATEWAYS']))
            nat_table.delete_item(Key={'id': id})
        for r in cidr_removals:
            id = recorded_cidrs[r][0]
            print ("Removing \"%s\" CIDR block from %s" % (id, os.environ['DYNAMODB_TABLE_CIDRS']))
            cidr_table.delete_item(Key={'id': id})
        for r in eip_removals:
            id = r
            print ("Removing \"%s\" EIP from %s" % (id, os.environ['DYNAMODB_TABLE_CIDRS']))
            eips_table.delete_item(Key={'id': id})
