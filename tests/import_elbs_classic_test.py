import unittest
import os
import sys
import boto3
import json
sys.path.insert(0, './')
import sts
import import_elbs_classic
from moto import mock_dynamodb2, mock_sts, mock_elb

class TestImportElbsClassic(unittest.TestCase):

    @mock_elb
    @mock_dynamodb2
    @mock_sts
    def test_import_elbs_classic(self):
        """Setup DynamoDB tables for AccountsDynamoDbTable and ELBDynamoDbTable.
        Provision some ELBs classics and test import_elbs_classic
        """

        os.environ['DYNAMODB_TABLE_ELB'] = 'cidr-house-rules-test-elb'
        self.client = boto3.client('elb', region_name='us-east-1')
        self.dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        self.dynamodb.create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'LoadBalancerName',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'AccountId',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'Region',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'ttl',
                    'AttributeType': 'S'
                },
            ],
            TableName='cidr-house-rules-test-elb',
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
        self.elb_table = self.dynamodb.Table(os.environ['DYNAMODB_TABLE_ELB'])

        # Provision moto mock ELBs
        zones = ['us-east-1a', 'us-east-1b']
        listener1 = {
            'Protocol': 'http',
            'LoadBalancerPort': 80,
            'InstanceProtocol': 'http',
            'InstancePort': 8080
        }
        listener2 = {
            'Protocol': 'https',
            'LoadBalancerPort': 443,
            'InstanceProtocol': 'http',
            'InstancePort': 8080,
            'SSLCertificateId': 'arn:aws:iam::123456789012:server-certificate/my-server-cert'
        }
        self.client.create_load_balancer(
            LoadBalancerName='lb0',
            AvailabilityZones=zones,
            Listeners=[listener1],
            Scheme='internal'
        )
        self.client.create_load_balancer(
            LoadBalancerName='lb1',
            AvailabilityZones=zones,
            Listeners=[listener1],
            Scheme='internal'
        )
        self.client.create_load_balancer(
            LoadBalancerName='lb2',
            AvailabilityZones=zones,
            Listeners=[listener2],
            Scheme='internet-facing'
        )

        # Get all ELBs
        balancers = self.client.describe_load_balancers()
        lb0 = balancers['LoadBalancerDescriptions'][0]
        lb1 = balancers['LoadBalancerDescriptions'][1]
        lb2 = balancers['LoadBalancerDescriptions'][2]

        invoke_payload = (
            json.JSONEncoder().encode(
                {
                    "account": 12345678919,
                    "region": 'us-east-1'
                }
            )
        )
        invoke_payload_json = json.loads(invoke_payload)

        # Invoke import_elbs_classic lambda
        import_elbs_classic.import_elbs(invoke_payload_json, None)
        elb_table_items = self.elb_table.scan()['Items']

        # Run assertions on assocaited EIPs
        self.assertEqual(lb0['DNSName'], elb_table_items[0]["id"],
                         msg="f'{lb0} not found in table item 0'")
        self.assertEqual(lb1['DNSName'], elb_table_items[1]["id"],
                         msg="f'{lb1} not found in table item 1'")
        self.assertEqual(lb2['DNSName'], elb_table_items[2]["id"],
                         msg="f'{lb2} not found in table item 2'")

if __name__ == '__main__':
    unittest.main()
