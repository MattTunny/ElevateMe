import boto3
import time
import json
import ldap3
from botocore.vendored import requests
import os

# Environments
webhook = os.environ['WEBHOOK']
ldap_server = os.environ['LDAPSERVER']
ldap_user = os.environ['LDAPUSER']
ldap_password = os.environ['LDAPPASSWORD']
region = os.environ['REGION']
db_table = os.environ['DBTABLE']

# DynamoDB Table Details
dynamodb = boto3.resource('dynamodb', region_name=f'{region}')
table = dynamodb.Table(f'{db_table}')

# Send Slack/Teams message when user is revoked. (teams webhook works exactly the same as slack's)
def send_slack_message(webhook, user, group):

    delete_message = user + ' in group ' + group + ' has been revoked...'
    payload = {'text': f'{delete_message}'}
    response = requests.post(webhook, data=json.dumps(payload))

    return response

# Remove user from AD Group
def remove_user_from_adgroup(ldap_server, ldap_user, ldap_password, user, group):

    server = ldap3.Server(f'{ldap_server}')
    conn = ldap3.Connection(server, ldap_user, ldap_password, auto_bind=True)
    conn.extend.microsoft.remove_members_from_groups(f'cn={user},ou=Users,ou=corporate,dc=corporate,dc=internal', f'cn={group},cn=Users,dc=corporate,dc=internal')
    conn.unbind()

def check_table_and_revoke(event):

    # Get Current time in unix and friendly
    time_now_unix = int(time.time())

    # Connect to DynamoDB
    print('scanning table...')
    response = table.scan()
    items = response['Items']

    if len(items) > 0:

        for x in items:
            print(f'current time = {time_now_unix}')
            print(f'revoke time = ' + str(x['RevokeAt']))
            if x['RevokeAt'] <= time_now_unix:

                print(x['User'] + ' in group: ' + x['ADgroup'] + ' has lapse revoke time...ID: ' + x['Id'])

                # Remove user from AD and DynamoDB.
                try:
                    print('trying to remove user from ad....')
                    remove_user_from_adgroup(ldap_server, ldap_user, ldap_password, user=x['User'], group=x['ADgroup'])
                    print('pass...')
                    print('trying to deleting user...' + x['User'] + ' from Dynamo..')
                    table.delete_item(
                        Key={ 'Id': x['Id'] }
                    )
                    print('pass...')
                    print('Sending Slack message to team....')
                    send_slack_message(webhook=webhook, user=x['User'], group=x['ADgroup'])

                except Exception as error:
                    print(error)
                    response = requests.post(webhook, data=json.dumps({'text': '*Failed to Revoke:* ' + x['User'] + ' from: ' + x['ADgroup'] + '...Error: *' + str(error) + '*' }))

            else:
                print(x['User'] + ' in ' + x['ADgroup'] + ' with time to spare...')
    else:
        print('no users in table, skipping...')

    return response

def lambda_handler(event, context):
    return check_table_and_revoke(event)

# if __name__ == "__main__":
#     lambda_handler({}, {})
