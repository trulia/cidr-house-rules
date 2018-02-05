import boto3
import json
from datetime import date, datetime

class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()

        return json.JSONEncoder.default(self, o)

def establish_role(acct):
    sts_connection = boto3.client('sts')
    acct_b = sts_connection.assume_role(
        RoleArn="arn:aws:iam::{}:role/role_cidr_house".format(acct),
        RoleSessionName="cross_acct_lambda"
    )
    d = json.dumps(acct_b, cls=DateTimeEncoder)

    jsonn = json.loads(d)

    ACCESS_KEY = jsonn['Credentials']['AccessKeyId']
    SECRET_KEY = jsonn['Credentials']['SecretAccessKey']
    SESSION_TOKEN = jsonn['Credentials']['SessionToken']

    return ACCESS_KEY, SECRET_KEY, SESSION_TOKEN
