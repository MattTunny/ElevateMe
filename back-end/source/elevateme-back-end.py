import boto3
import json
from decimal import *
import decimal
import uuid
import time
import ldap3
import os
from base64 import b64decode
from datetime import datetime, timedelta
from botocore.vendored import requests

# Environments
webhook = os.environ['WEBHOOK']
ldap_server = os.environ['LDAPSERVER']
ldap_user = os.environ['LDAPUSER']
ldap_password = os.environ['LDAPPASSWORD']
region = os.environ['REGION']
db_table = os.environ['DBTABLE']

# AWS Details
dynamodb = boto3.resource('dynamodb', region_name=f'{region}')
table = dynamodb.Table(f'{db_table}')

# ###### Get encrypted password from SSM instead of passing in os.environment parameter ########
# ssm_client = boto3.client('ssm')
# x = ssm_client.get_parameter(Name='YOUR_TAG_NAME', WithDecryption=True)
# ldap_password = x['Parameter']['Value']

# Convert slack name to AD admin account name.
allowed_users = {
    'matt.tunny': 'Tunny.Admin',
    'john.lewis': 'Lewis.Admin',
    'john.doh': 'Doh.Admin',
    'daniel.bobbie': 'Bobbie.Admin',
    'reece.smith': 'Smith.Admin'
}

allowed_groups = {
    'Domain Admins', # Domain Admins
    'DMZ-Server-Admins', # example group for custom dmz servers
    'Schema Admins', # Scheme Admins
    'AD-ExchangeSearchAdmins', # example group for exchange search rights.
    'AuditServers', # example group for audit servers
    'AWS-CloudAdmins' # example group for Cloud Admins
}

# Helper class to convert a DynamoDB item to JSON.
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            else:
                return int(o)
        return super(DecimalEncoder, self).default(o)

# Add user from AD Group
def add_user_from_adgroup(ldap_server, ldap_user, ldap_password, user, group):

    server = ldap3.Server(f'{ldap_server}')
    conn = ldap3.Connection(server, ldap_user, ldap_password, auto_bind=True)
    conn.extend.microsoft.add_members_to_groups(f'cn={user},ou=Users,ou=corporate,dc=corporate,dc=internal', f'cn={group},cn=Users,dc=corporate,dc=internal')
    conn.unbind()

# Get details from SQS Message
def sqs_event(event):

    print('Running SQS Function...')
    body = {
        "message": "Elevate Me Message...",
        "event": event
    }

    print(json.dumps(body))

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response

# Update DynamoDB
def update_dynamodb(event):

    print('running update_dynamodb function....')

    # Current Time + TTL time to expire dynamodb records after 2 hours + UUID
    time_when_elevated = int(time.time())
    time_now = datetime.now()
    human_time = '{:%H:%M:%S}'.format(time_now)
    # Revoke at
    revoke_at = time_when_elevated + 3600 #3600
    human_revoke_at = time_now + timedelta(hours=1)
    revoke_human_time = '{:%H:%M:%S}'.format(human_revoke_at)
    random_id = uuid.uuid4()

    user = event['Records'][0]['messageAttributes']['User']['stringValue']
    ad_user = allowed_users[f'{user}']
    adgroup = event['Records'][0]['messageAttributes']['Group']['stringValue']

    print(f'User = {ad_user}')
    print(f'Group = {adgroup}')
    print(f'Time when Elevated = {time_when_elevated}')
    print(f'Revoke = {revoke_at}')

    # Push DynamoDB
    response = table.update_item(
        Key={
            'Id': f'{random_id}'
        },
        UpdateExpression="set #user = :user, #adgroup = :adgroup, #time_when_elevated = :time_when_elevated, #revoke_at=:revoke_at, #revoke_at_friendly=:revoke_at_friendly, #elevated_time_friendly=:elevated_time_friendly",
        ExpressionAttributeNames={
            '#user': 'User',
            '#adgroup': 'ADgroup',
            '#time_when_elevated': 'TimeWhenElevated',
            '#revoke_at': 'RevokeAt',
            '#revoke_at_friendly': 'RevokeAtFriendly',
            '#elevated_time_friendly': 'ElevatedTimeFriendly'
        },
        ExpressionAttributeValues={
            ':user': ad_user,
            ':adgroup': adgroup,
            ':time_when_elevated': time_when_elevated,
            ':revoke_at': revoke_at,
            ':revoke_at_friendly': revoke_human_time,
            ':elevated_time_friendly': human_time
        },
        ReturnValues="UPDATED_NEW"
    )
    print(json.dumps(response, indent=4, cls=DecimalEncoder))

def lambda_handler(event, context):

    # Read SQS event
    sqs_event(event)

    # Confirm user and group are allowed to be Elevated.
    group_on_queue = event['Records'][0]['messageAttributes']['Group']['stringValue']
    user_on_queue = event['Records'][0]['messageAttributes']['User']['stringValue']
    ad_user_on_queue = allowed_users[f'{user_on_queue}']

    if group_on_queue in allowed_groups and user_on_queue in allowed_users.keys():
        print('User and group allowed to continue')

        # Scan DynamoDB for current Elevated users before adding users (stops spam Elevating)
        print('scanning dynamodb table for current elveated users...')
        dbresponse = table.scan()
        items = dbresponse['Items']
        
        if len(items) > 0:
            
            current_users = []
            current_groups = []
            current_revoke = []
            
            for i in items:
                current_users.append(i['User'])
                current_groups.append(i['ADgroup'])
                current_revoke.append(i['RevokeAt'])
        
            # Check user isn't already elevated.
            if group_on_queue in current_groups and ad_user_on_queue in current_users:
                print('skipping as user already in group with time to spare...')
                response = requests.post(webhook, data=json.dumps({'text': ad_user_on_queue + ' is already elevated in ' + group_on_queue + ' ....' }))

            else:
                # User not in table, adding...
                print('adding user to group....')

                try:
                    print('Trying to add user to AD group...')
                    add_user_from_adgroup(ldap_server, ldap_user, ldap_password, ad_user_on_queue, group_on_queue)
                    response = requests.post(webhook, data=json.dumps({'text': ad_user_on_queue + ' elevated into ' + group_on_queue + ' ....' }))

                    try:
                        print('trying to add user to dynamodb...')
                        update_dynamodb(event)

                    except Exception as error:
                        print('Failed to update DynamoDB Table....')
                        print(error)
                        response = requests.post(webhook, data=json.dumps({'text': f'{error}' }))

                except Exception as error:
                    print('Failed to Add user to AD Group....')
                    print(error)
                    response = requests.post(webhook, data=json.dumps({'text': f'{error}' }))   
                    
                    
        else:
            # Table empty, adding user...
            print('DynamoDB Table is empty, elevate new user.')
            try:
                print('Trying to add user to AD group...')
                add_user_from_adgroup(ldap_server, ldap_user, ldap_password, ad_user_on_queue, group_on_queue)
                response = requests.post(webhook, data=json.dumps({'text': ad_user_on_queue + ' elevated into ' + group_on_queue + ' ....' }))

                try:
                    print('trying to add user to dynamodb...')
                    update_dynamodb(event)

                except Exception as error:
                    print('Failed to update DynamoDB Table....')
                    print(error)
                    response = requests.post(webhook, data=json.dumps({'text': f'{error}' }))

            except Exception as error:
                print('Failed to Add user to AD Group....')
                print(error)
                response = requests.post(webhook, data=json.dumps({'text': f'{error}' }))
                
    else:
        # User or Group not on the list baby!
        print('user or group not allowed to elevate')
        response = requests.post(webhook, data=json.dumps({'text': '*Failed to Elevate* ' + ad_user_on_queue + ' from: ' + group_on_queue + ' ....User or group not in allow list.' }))