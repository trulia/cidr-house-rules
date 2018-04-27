import unittest
import os
import sys
import boto3
import json
sys.path.insert(0, './')
import sts
import available_ips
from moto import mock_ec2, mock_dynamodb2, mock_sts

class TestAvailableIps(unittest.TestCase):

    @mock_ec2
    @mock_dynamodb2
    @mock_sts
    def test_available_ips(self):
        """Setup DynamoDB tables for accounts, available-ips and turn up a
        couple mock instances to use some IPs as well
        """

        os.environ["DYNAMODB_TABLE_AVAILABLE_IPS"] = "cidr-house-rules-test-available-ips"
        self.client = boto3.client('ec2', region_name='us-east-1')
        self.dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        self.dynamodb.create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'VpcId',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'AccountId',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'SubnetId',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'Subnet',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'Region',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'AvailableIpAddressCount',
                    'AttributeType': 'S'
                },
            ],
            TableName='cidr-house-rules-test-available-ips',
            KeySchema=[
                {
                    'AttributeName': 'id',
                    'KeyType': 'HASH'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 1,
                'WriteCapacityUnits': 5
            },
        )
        self.available_ips_table = self.dynamodb.Table(os.environ["DYNAMODB_TABLE_AVAILABLE_IPS"])
        self.client.run_instances(ImageId='ami-03cf127a', MinCount=100, MaxCount=100)
        invoke_payload = (
            json.JSONEncoder().encode(
                {
                    "account": 12345678919,
                    "region": 'us-east-1'
                }
            )
        )
        invoke_payload_json = json.loads(invoke_payload)
        available_ips.available_ips(invoke_payload_json, None)
        available_ips_table_items = self.available_ips_table.scan()['Items']
        self.assertIn('12345678919', available_ips_table_items[0]['id'])

if __name__ == '__main__':
    unittest.main()
