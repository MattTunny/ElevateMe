import boto3
import json
import os
from base64 import b64decode
from urlparse import parse_qs


queue_url = os.environ['SQSQUEUE']
expected_token = os.environ['SLACKTOKEN']

sqs = boto3.client('sqs')


def respond(err, res=None):
    return {
        'statusCode': '400' if err else '200',
        'body': err.message if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }

# Send message to SQS queue
def send_sqs_message(user, group):

    response = sqs.send_message(
        QueueUrl=queue_url,
        DelaySeconds=0,
        MessageAttributes={
            'User': {
                'DataType': 'String',
                'StringValue': '{}'.format(user)
            },
            'Group': {
                'DataType': 'String',
                'StringValue': '{}'.format(group)
            }
        },
        MessageBody=(
            'adding user: {} into group: {}'.format(user, group)
        )
    )

    return response


def lambda_handler(event, context):
    params = parse_qs(event['body'])
    print (event['body'])
    
    token = params['token'][0]
    if token != expected_token:
        print ("Request token (%s) does not match expected", token)
        return respond(Exception('Invalid request token'))

    user = params['user_name'][0]
    command = params['command'][0]
    channel = params['channel_name'][0]
    command_text = params['text'][0]

    try:
        send_sqs_message(user,command_text)
    except Exception as Error:
        print (Error)
        respond(None, "*Failed to Elevate %s *into %s...." % (user, command_text))

    return respond(None, "Trying to Elevate %s into %s...." % (user, command_text))