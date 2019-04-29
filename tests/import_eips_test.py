import unittest
import os
import sys
import boto3
import json
sys.path.insert(0, './')
import sts
import import_eips
from moto import mock_ec2, mock_dynamodb2, mock_sts

class TestImportEips(unittest.TestCase):

    @mock_ec2
    @mock_dynamodb2
    @mock_sts
    def test_import_eips(self):
        """Setup DynamoDB tables for AccountsDynamoDbTable and EIPDynamoDbTable.
        Provision some EIPs and associate to ec2 instances
        """
        
        boto3.setup_default_session()
        os.environ['DYNAMODB_TABLE_EIP'] = 'cidr-house-rules-test-eips'
        self.client = boto3.client('ec2', region_name='us-east-1')
        self.dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        self.dynamodb.create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'AllocationId',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'AccountId',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'AssociationId',
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
            TableName='cidr-house-rules-test-eips',
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
        self.eips_table = self.dynamodb.Table(os.environ['DYNAMODB_TABLE_EIP'])
        reservation = self.client.run_instances(
            ImageId='ami-03cf127a', MinCount=5, MaxCount=5)
        instance0 = reservation['Instances'][0]
        instance1 = reservation['Instances'][1]
        instance2 = reservation['Instances'][2]

        # EIPs to be associated with ec2 instances
        eip0 = self.client.allocate_address(Domain='vpc')
        eip1 = self.client.allocate_address(Domain='vpc')
        eip2 = self.client.allocate_address(Domain='vpc')

        # An EIP not to  e assocaited with an ec2 instance
        eip3 = self.client.allocate_address(Domain='vpc')

        self.client.associate_address(InstanceId=instance0['InstanceId'],
                                      AllocationId=eip0['AllocationId'])
        self.client.associate_address(InstanceId=instance1['InstanceId'],
                                      AllocationId=eip1['AllocationId'])
        self.client.associate_address(InstanceId=instance2['InstanceId'],
                                      AllocationId=eip2['AllocationId'])
        public_ip_0 = eip0['PublicIp']
        public_ip_1 = eip1['PublicIp']
        public_ip_2 = eip2['PublicIp']
        public_ip_3 = eip3['PublicIp']
        invoke_payload = (
            json.JSONEncoder().encode(
                {
                    "account": 12345678919,
                    "region": 'us-east-1'
                }
            )
        )
        invoke_payload_json = json.loads(invoke_payload)

        # Invoke import_eips lambda
        import_eips.import_eips(invoke_payload_json, None)
        eips_table_items = self.eips_table.scan()['Items']

        # Run assertions on assocaited EIPs
        self.assertEqual(public_ip_0, eips_table_items[0]['id'],
                         msg=f'{public_ip_0} not found in table item 0')
        self.assertEqual(public_ip_1, eips_table_items[1]['id'],
                         msg=f'{public_ip_1} not found in table item 1')
        self.assertEqual(public_ip_2, eips_table_items[2]['id'],
                         msg=f'{public_ip_2} not found in table item 2')

        # Test an EIP that isn't associated to an EC2 instance
        self.assertEqual(public_ip_3, eips_table_items[3]['id'],
                         msg=f'{public_ip_3} not found in table item 3')

if __name__ == '__main__':
    unittest.main()
