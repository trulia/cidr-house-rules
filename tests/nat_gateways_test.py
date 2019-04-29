import unittest
import os
import sys
import boto3
import json
sys.path.insert(0, './')
import sts
import import_nat_gateways
import api_handlers
from moto import mock_dynamodb2, mock_sts, mock_ec2

class TestNatGateways(unittest.TestCase):

    @mock_ec2
    @mock_dynamodb2
    @mock_sts
    def test_nat_gateways(self):
        """Setup DynamoDB tables for NatDynamoDbTable.
        Provision some NAT Gatways
        """

        boto3.setup_default_session()
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
                CidrBlock=f'10.{i}.100.0/24'
            )

        for i in range(0, 70):
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

        for i in eips['Addresses']:
            self.client.create_nat_gateway(
                AllocationId=[i][0]['AllocationId'],
                SubnetId=subnet_ids['Subnets'][0]['SubnetId']
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

        # Mock API Gateway event
        api_response_get_number_of_nat_gateway_pages_default = (
            {'body': None,
             'headers': {'Accept': '*/*',
                         'CloudFront-Forwarded-Proto': 'https',
                         'CloudFront-Is-Desktop-Viewer': 'true',
                         'CloudFront-Is-Mobile-Viewer': 'false',
                         'CloudFront-Is-SmartTV-Viewer': 'false',
                         'CloudFront-Is-Tablet-Viewer': 'false',
                         'CloudFront-Viewer-Country': 'US',
                         'Host': 'foobar.execute-api.us-west-2.amazonaws.com',
                         'User-Agent': 'curl/7.54.0',
                         'Via': '2.0 6895.cloudfront.net (CloudFront)',
                         'X-Amz-Cf-Id': 'foobar===',
                         'X-Amzn-Trace-Id': 'Root=1-5afb0foobar',
                         'X-Forwarded-For': '127.0.0.1',
                         'X-Forwarded-Port': '443',
                         'X-Forwarded-Proto': 'https',
                         'x-api-key': 'foobarapikey'
                         },
             'httpMethod': 'GET',
             'isBase64Encoded': False,
             'path': '/get_number_of_nat_gateway_pages',
             'pathParameters': None,
             'queryStringParameters': None,
             'requestContext': {'accountId': '123456789',
                                'apiId': 'foobarapi',
                                'extendedRequestId': 'foobarreqid',
                                'httpMethod': 'GET',
                                'identity': {'accessKey': None,
                                             'accountId': None,
                                             'apiKey': 'foobarapikey',
                                             'apiKeyId': 'foobarkeyid',
                                             'caller': None,
                                             'cognitoAuthenticationProvider': None,
                                             'cognitoAuthenticationType': None,
                                             'cognitoIdentityId': None,
                                             'cognitoIdentityPoolId': None,
                                             'sourceIp': '127.0.0.1',
                                             'user': None,
                                             'userAgent': 'curl/7.54.0',
                                             'userArn': None},
                                'path': '/dev/get_number_of_nat_gateway_pages',
                                'protocol': 'HTTP/1.1',
                                'requestId': 'foobarrequestid',
                                'requestTime': '15/May/2018:16:31:14 +0000',
                                'requestTimeEpoch': 1526401874029,
                                'resourceId': 'foobarid',
                                'resourcePath': '/get_number_of_nat_gateway_pages',
                                'stage': 'dev'},
             'resource': '/get_number_of_nat_gateway_pages',
             'stageVariables': None}
            )

        api_response_get_number_of_nat_gateway_pages_10_per_page = (
            {'body': None,
             'headers': {'Accept': '*/*',
                         'CloudFront-Forwarded-Proto': 'https',
                         'CloudFront-Is-Desktop-Viewer': 'true',
                         'CloudFront-Is-Mobile-Viewer': 'false',
                         'CloudFront-Is-SmartTV-Viewer': 'false',
                         'CloudFront-Is-Tablet-Viewer': 'false',
                         'CloudFront-Viewer-Country': 'US',
                         'Host': 'foobar.execute-api.us-west-2.amazonaws.com',
                         'User-Agent': 'curl/7.54.0',
                         'Via': '2.0 6895.cloudfront.net (CloudFront)',
                         'X-Amz-Cf-Id': 'foobar===',
                         'X-Amzn-Trace-Id': 'Root=1-5afb0foobar',
                         'X-Forwarded-For': '127.0.0.1',
                         'X-Forwarded-Port': '443',
                         'X-Forwarded-Proto': 'https',
                         'x-api-key': 'foobarapikey'
                         },
             'httpMethod': 'GET',
             'isBase64Encoded': False,
             'path': '/get_number_of_nat_gateway_pages',
             'pathParameters': None,
             'queryStringParameters': {'results_per_page': '10'},
             'requestContext': {'accountId': '123456789',
                                'apiId': 'foobarapi',
                                'extendedRequestId': 'foobarreqid',
                                'httpMethod': 'GET',
                                'identity': {'accessKey': None,
                                             'accountId': None,
                                             'apiKey': 'foobarapikey',
                                             'apiKeyId': 'foobarkeyid',
                                             'caller': None,
                                             'cognitoAuthenticationProvider': None,
                                             'cognitoAuthenticationType': None,
                                             'cognitoIdentityId': None,
                                             'cognitoIdentityPoolId': None,
                                             'sourceIp': '127.0.0.1',
                                             'user': None,
                                             'userAgent': 'curl/7.54.0',
                                             'userArn': None},
                                'path': '/dev/get_number_of_nat_gateway_pages',
                                'protocol': 'HTTP/1.1',
                                'requestId': 'foobarrequestid',
                                'requestTime': '15/May/2018:16:31:14 +0000',
                                'requestTimeEpoch': 1526401874029,
                                'resourceId': 'foobarid',
                                'resourcePath': '/get_number_of_nat_gateway_pages',
                                'stage': 'dev'},
             'resource': '/get_number_of_nat_gateway_pages',
             'stageVariables': None}
            )

        number_of_pages = api_handlers.get_number_of_nat_gateway_pages(
            api_response_get_number_of_nat_gateway_pages_default, None
        )

        number_of_pages_with_10_as_result = (
            api_handlers.get_number_of_nat_gateway_pages(
                api_response_get_number_of_nat_gateway_pages_10_per_page, None)
            )

        # Validate that 5 EIPs were imported
        self.assertEqual(len(nats_table_items), 70)

        # Validate NAT Gateways found in Dynamodb table, do they match with mock
        for nat in nats_table_items:
            self.assertIn(nat['id'], [nat_id['NatGatewayId']
                                      for nat_id in nats['NatGateways']])

        # Validate api_handler response for get_number_of_nat_gateway_pages with
        # default of 50 results per page
        self.assertEqual(number_of_pages['body'], 2)

        # Validate api_handler response for get_number_of_nat_gateway_pages with
        # with requested 10 results per page
        self.assertEqual(number_of_pages_with_10_as_result['body'], 7)

if __name__ == '__main__':
    unittest.main()
