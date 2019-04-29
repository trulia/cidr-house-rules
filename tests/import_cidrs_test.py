import unittest
import os
import sys
import boto3
import json
sys.path.insert(0, './')
import sts
import import_cidrs
from moto import mock_dynamodb2, mock_sts, mock_ec2

class TestImportCidrs(unittest.TestCase):

    @mock_ec2
    @mock_dynamodb2
    @mock_sts
    def test_import_cidrs(self):
        """Setup DynamoDB tables for AccountsDynamoDbTable and ELBDynamoDbTable.
        Provision some VPCs and some additional cidrs
        """
        
        boto3.setup_default_session()
        os.environ['DYNAMODB_TABLE_CIDRS'] = 'cidr-house-rules-test-cidrs'
        self.client = boto3.client('ec2', region_name='us-east-1')
        self.ec2 = boto3.resource('ec2', region_name='us-east-1')
        self.dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        self.dynamodb.create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'cidr',
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
            TableName='cidr-house-rules-test-cidrs',
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
        self.cidrs_table = self.dynamodb.Table(os.environ['DYNAMODB_TABLE_CIDRS'])

        # Provision moto mock VPCs
        zones = ['us-east-1a', 'us-east-1b']

        self.client.create_vpc(
            CidrBlock='10.0.100.0/24'
        )
        self.client.create_vpc(
            CidrBlock='192.168.2.0/24'
        )
        self.client.create_vpc(
            CidrBlock='10.2.0.0/16'
        )

        # Get all VPCs
        vpcs = self.client.describe_vpcs()

        # Assign additional cidr block to vpc3
        self.client.associate_vpc_cidr_block(
            CidrBlock='10.5.100.0/24',
            VpcId=vpcs['Vpcs'][3]['VpcId']
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

        # Invoke import_cidrs lambda
        import_cidrs.import_cidrs(invoke_payload_json, None)
        cidrs_table_items = self.cidrs_table.scan()['Items']

        # Run assertions on Cidrs
        for i in range(0, 4):
            self.assertEqual(vpcs['Vpcs'][i]['CidrBlock'],
                             cidrs_table_items[i]["cidr"],
                             msg=f"""
                             {vpcs["Vpcs"][i]["CidrBlock"]}
                             not found in table item {i}"""
                             )

        # Test additional associated cidr to vpc3
        self.assertEqual('10.5.100.0/24', cidrs_table_items[4]["cidr"],
                         msg="f'10.5.100.0/24 not found in table item 4'")

if __name__ == '__main__':
    unittest.main()
