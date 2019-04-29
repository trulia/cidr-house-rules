import boto3


def ttl_manager(update, table_name, ttl_attribute):
    """
    Function to enable or disable TimeToLiveSpecification on a table, via True or False flag as 'update' variable input

    See: 
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb.html#DynamoDB.Client.update_time_to_live
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb.html#DynamoDB.Client.describe_time_to_live
    """

    client = boto3.client('dynamodb')

    current_ttl_status = client.describe_time_to_live(
        TableName=table_name
    )

    status = current_ttl_status['TimeToLiveDescription']['TimeToLiveStatus']

    if status == "ENABLING" or "DISABLING":
        return f'Dynamodb {table_name} TTL is presently {status}'

    elif update == True and status == "DISABLED" or update == False and status == "ENABLED":
        try:
            response = client.update_time_to_live(
                TableName=table_name,
                TimeToLiveSpecification={
                    'Enabled': update, 
                    'AttributeName': ttl_attribute
                }
            )
        except:
            print(f'Failed to update TTL settings on {table_name}')
        
