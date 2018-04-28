import unittest
import os
import sys
import boto3
import json
sys.path.insert(0, './')
import sts
import import_nat_gateways
from moto import mock_dynamodb2, mock_sts, mock_ec2

class TestImportNatGateways(unittest.TestCase):

    @mock_ec2
    @mock_dynamodb2
    @mock_sts
    def test_import_nat_gateways(self):
        """Setup DynamoDB tables for NatDynamoDbTable.
        Provision some NAT Gatways
        """

        os.environ['DYNAMODB_TABLE_NAT_GATEWAYS'] = 'cidr-house-rules-test-nats'
        self.client = boto3.client('ec2', region_name='us-east-1')
        self.dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        self.dynamodb.create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'PublicIp',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'AccountID',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'Region',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'VpcId',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'ttl',
                    'AttributeType': 'S'
                },
            ],
            TableName='cidr-house-rules-test-nats',
            KeySchema=[
                {
                    'AttributeName': 'id',
                    'KeyType': 'HASH'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 1,
                'WriteCapacityUnits': 1
            },
        )
        self.nats_table = self.dynamodb.Table(
            os.environ['DYNAMODB_TABLE_NAT_GATEWAYS'])

        # Provision moto mock VPCs, subnets and NAT Gateways
        zones = ['us-east-1a', 'us-east-1b']

        for i in range(0, 5):
            self.client.create_vpc(
                CidrBlock='10.0.100.0/24'
            )
            self.client.allocate_address(
                Domain='vpc'
            )

        vpcs = self.client.describe_vpcs()
        eips = self.client.describe_addresses()

        for i in range(0, 5):
            self.client.create_subnet(
                CidrBlock=f'10.{i}.100.0/24',
                VpcId=vpcs['Vpcs'][i]['VpcId']
            )

        subnet_ids = self.client.describe_subnets()

        for i in range(0, 5):
            self.client.create_nat_gateway(
                AllocationId=eips['Addresses'][i]['AllocationId'],
                SubnetId=subnet_ids['Subnets'][i]['SubnetId']
            )

        invoke_payload = (
            json.JSONEncoder().encode(
                {
                    "account": 12345678919,
                    "region": 'us-east-1'
                }
            )
        )
        invoke_payload_json = json.loads(invoke_payload)

        # Invoke import_nat_gateways lambda
        import_nat_gateways.import_nat_gateways(invoke_payload_json, None)
        nats_table_items = self.nats_table.scan()['Items']
        nats = self.client.describe_nat_gateways()

        # Validate that 5 EIPs were imported
        self.assertEqual(len(nats_table_items), 5)

        # Validate NAT Gateways found in Dynamodb table, do they match with mock
        for nat in nats_table_items:
            self.assertIn(nat['id'], [nat_id['NatGatewayId']
                                      for nat_id in nats['NatGateways']])

if __name__ == '__main__':
    unittest.main()
