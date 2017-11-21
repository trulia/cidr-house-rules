import json
import os
import boto3
import uuid
import logging
from sts import establish_role
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def prune_tables(event, context):
    recorded_eips = {}
    recorded_cidrs = {}
    recorded_nats = {}
    dynamodb = boto3.resource('dynamodb')
    client = boto3.client('ec2')
    nats_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_NAT_GATEWAYS'])
    cidrs_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_CIDRS'])
    eips_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_EIP'])
    accounts_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_ACCOUNTS'])
    accounts = accounts_table.scan()['Items']
    cidrs = cidrs_table.scan()['Items']
    scan_cidrs_table = cidrs_table.scan(
        AttributesToGet=['id','AccountID','Region','VpcId','cidr'])['Items']
    scan_nats_table = nats_table.scan(
        AttributesToGet=['id','AccountID','PublicIp','VpcId','Region'])['Items']
    scan_eips_table = eips_table.scan(
        AttributesToGet=['id','AccountID','Region'])['Items']

    for i in scan_cidrs_table:
        cidr_id = i['id']
        recorded_cidrs[cidr_id] = [i['VpcId'], i['cidr'], i['Region'], i['AccountID']]
        logger.info("CIDRS Found: Account: {0} Region: {1} Cidr: {2}".format(
        i['AccountID'], i['Region'], i['cidr']))

    for j in scan_nats_table:
        nats_id = j['id']
        recorded_nats[nats_id] = [j['AccountID'], j['PublicIp'], j['VpcId'],
                                  j['Region']]
        logger.info("Nat Found: Account: {0} PublicIp: {1} VpcId: {2}".format(
        j['AccountID'], j['PublicIp'], j['VpcId']))

    for e in scan_eips_table:
        eips_id = e['id']
        recorded_eips[eips_id] = [e['AccountID'], e['Region']]
        logger.info("EIP Found: Account: {0} PublicIp: {1} Region: {2}".format(
        e['AccountID'], e['id'], e['Region']))

    regions = ([region['RegionName'] for region in
                client.describe_regions()['Regions']])

    for region in regions:
        for acct in accounts:
            ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = establish_role(acct)
            client = boto3.client('ec2',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN,
            region_name=region
            )
            nats = client.describe_nat_gateways()
            vpcs = client.describe_vpcs()
            eips = client.describe_addresses()
            active_cidrs = (["{0}{1}{2}{3}".format(
                acct['id'], vpc['CidrBlock'], region, vpc['VpcId'])
                             for vpc in vpcs['Vpcs']])
            active_cidr_associations = (["{0}{1}{2}{3}".format(
                acct['id'], cidr_associaton['CidrBlock'], region, vpc['VpcId'])
                             for vpc in vpcs['Vpcs']
                             for cidr_associaton in vpc['CidrBlockAssociationSet']
                             if 'CidrBlockAssociationSet' in vpc
                             and cidr_associaton['CidrBlockState']['State']
                             == "associated"])
            active_nats = (["{0}".format(nat['NatGatewayId'])
                            for nat in nats['NatGateways']])
            active_eips = (["{0}".format(eip['PublicIp'])
                            for eip in eips['Addresses']
                            ])
            cidrs_keys_list = ([k for k, v in recorded_cidrs.items()
                                if (v[3] == str(acct['id'])
                                    and v[2] == str(region))])
            nats_keys_list = ([k for k, v in recorded_nats.items()
                              if (v[0] == str(acct['id'])
                                  and v[3] == str(region))])
            eips_keys_list = ([k for k, v in recorded_eips.items()
                              if (v[0] == str(acct['id'])
                                  and v[1] == str(region))])

            logger.info("Current active_cidrs: {}".format(active_cidrs))
            logger.info("Current active_cidr_associations: {}".format(
                active_cidr_associations))
            logger.info("Current recorded cidrs: {}".format(cidrs_keys_list))
            logger.info("Current active_nats: {}".format(active_nats))
            logger.info("Current recorded nats: {}".format(nats_keys_list))
            logger.info("Current active_eips: {}".format(active_eips))
            logger.info("Current recorded eips: {}".format(eips_keys_list))

            all_cidrs = set(list(active_cidrs + active_cidr_associations))
            cidrs_to_prune = list(set(cidrs_keys_list) - set(all_cidrs))
            nats_to_prune = list(set(nats_keys_list) - set(active_nats))
            eips_to_prune = list(set(eips_keys_list) - set(active_eips))

            logger.info("cidrs_to_prune: {}".format(cidrs_to_prune))
            logger.info("nats_to_prune: {}".format(nats_to_prune))
            logger.info("eips_to_prune: {}".format(eips_to_prune))

            for cidr in cidrs_to_prune:
                logger.info("Found unused cidr: {} - removing".format(cidr))
                cidrs_table.delete_item(Key={'id': cidr})

            for nat in nats_to_prune:
                logger.info("Found unused nat: {} - removing".format(nat))
                nats_table.delete_item(Key={'id': nat})

            for eip in eips_to_prune:
                logger.info("Found unused eip: {} - removing".format(eip))
                eips_table.delete_item(Key={'id': eip})
