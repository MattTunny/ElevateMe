# (ChatOps + Active Directory + Serverless): ElevateMe

I work for @AWSCloud & my opinions are my own.


# Basic Intro
ElevateMe is a event driven ChatOps security tool for elevating Microsoft AD users using Slack into sensitive Active Directory groups for a limited amount of time in an automated secure way that is visible to all channel members. Here are some use cases it works really well with:

- Domain/Enterprise/Schema Admins etc.
- Exchange Search Rights.
- Sensitive AD Groups for your Organization that aren't often used. (HR/Finance/Audit resources etc)  
- Short term contractors or limited days contractors.

Essentially ElevateMe enables you to reduce your attack surface on sensitive groups inside your organization while still enabling your users to elevate themselves the required access when they need in a fast secure way.
<br>

# Demo
![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/demo-extended2.gif)
<br>
<br>
![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/elevateme2.png)
<br>

### Front-End

>This is a simply front end lambda/apigateway that speaks to slack from the slack blueprint in lambda. Users speak to this lambda/api gateway when requesting to elevate to groups. This app just confirms slack token and send username/group to sqs queue.

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/elevated-1.png)

### Back-end

>This lambda triggers as soon as the front-end lambda puts the message into the sqs queue. Allowed users and groups are defined and evaluated. If user/group passes tests it connects to AD and puts users into group. Also writes to DynamoDB table and logs user/group/elevated time and revoke time.

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/elevated-2.png)

### Cron-Revoker

>This is a simple 5 minute cron job that checks DynamodB tables for users that have expired the time you have defined to elevate. If time has elapsed then it will connect to AD and remove users from AD Group and send a slack message.

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-revoke.png)

*Note: Back-End and Cron-Revoker lambda's need to be packaged, They cannot be edited without being re-packaged. Front-End is a blueprint from slack.*


# Requirements

- [Python](https://www.python.org/downloads/)
- [PipEnv](https://github.om/pyenv/pyenv) or whatever package management you want to use.
- [AWS SAM](https://github.com/awslabs/serverless-application-model)
- AWS Account + VPC connectivity to your AD/LDAP Server
- 1 Security Group for Lambda's (No Inbound access, open outbound)
- 1 S3 bucket to store your files
- 1 windows service account and any AD Groups you want to use (I use the service account 'elevateme_sa' in this example with "Domain Admins as the group)
- Slack Administrator access to install your own app.

# Install Steps:

## Clone repo
`git clone https://github.com/MattTunny/ElevateMe.git`

## Pre Account Setup

- Make a s3 bucket for your lambda's:
`aws s3 mb s3://your-unique-bucket-name --region ap-southeast-2`

- Copy your VPC Id you want to use `aws ec2 describe-vpcs`

- Create a ec2 security group for your lambda. (you don't need to add any rules to it, its secure by default.) `aws ec2 create-security-group --group-name my-lambda-security-group --description "Lambda Security Group - No Inbound" --vpc-id vpc-1234567890123456`

- Confirm it only has outbound access:
`aws ec2 describe-security-groups --group-ids sg-1234567890123456`

## Active Directory Setup
- Create a service account for ElevateMe to use. It only requires Read/Write permissions for the AD Groups you want Elevated.
- In this example I have left the username and password as default Parameters in the template files however **this is bad practice**, you want to encrypt these credentials in SSM Parameter Store. I have left the code hashed out to reuse.
```python
###### Get encrypted password from SSM instead of passing in os.environment parameter ########
ssm_client = boto3.client('ssm')
x = ssm_client.get_parameter(Name='YOUR_TAG_NAME', WithDecryption=True)
ldap_password = x['Parameter']['Value']
```
- If you use Domain Admins see "Considerations for Domain Admins/Enterprise Admins" at bottom of readme

<br>

## Create Slack App
- Create a Slack Team if you don’t have one already
- Navigate to [https://api.slack.com/apps](https://api.slack.com/apps)
- Click Create App

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-1.png)
- Enter ElevateMe and click your Slack Team you have rights to add apps to. (if you don't have admin access you can create a new one for free)

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-2.png)
- Click Incoming Webhooks

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-3.png)
- Click Add New Webhook to Workspace

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-4.png)
- Click Authorize and Select Channel you want bot to live in.

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-5.png)
- Copy the webhook url & paste into the WebHook Parameter default in back-end/back-end.yaml and cron-revoker/cron-revoker.yaml

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-6.png)
- Go back to the slack website and Select Basic Information

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-7.png)
- Scroll Down to Verification Token, Copy and Paste it into the Slack Token Parameter Default in front-end/front-end.yaml

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-8.png)

<br>
<br>
<br>

## **Create Back-end App**

- Navigate to ./back-end/source and open elevateme-back-end.py
- Change "allowed_users", "allowed_groups" and "cn={user},ou=Users,ou=corp,dc=corp,dc=internal" to match your environment.
- (remember you need to add the security group your 2-3 private subnets)
- package python up:
```bash
$ make install && make build
```
- go up one folder "cd .."
- make sure parameters are correct in back-end.yaml
- run sam package: 
```bash
sam package --template-file back-end.yaml --s3-bucket your-unique-bucket-name --s3-prefix back-end --output-template back-end-output.yaml
```
- run sam deploy:
```bash
sam deploy --template-file back-end-output.yaml --stack-name ElevateMeBackEnd --capabilities CAPABILITY_IAM
```
- Log into AWS console and open Cloudformation and Copy the SQS Queue, SQSqueueName and DynamoDB Table.
- paste SQSqueueName and SQSqueue Default Parameters in ./front-end/front-end.yaml
- Paste DynamoDB Name into DBTable Default Parameter in ./cron-revoker/cron-revoker.yaml
<br>
<br>
<br>

## **Create Front-End App**

- Navigate to ./front-end
- Make sure Default Parameters are correct in front-end.yaml
- You don't need to build this python app like the other 2.
- run sam package:
```bash
sam package --template-file front-end.yaml --s3-bucket your-unique-bucket-name --s3-prefix front-end --output-template front-end-output.yaml
```
- run sam deploy: 
```bash
sam deploy --template-file front-end-output.yaml --stack-name ElevateMeFrontEnd --capabilities CAPABILITY_IAM
```
- Open up AWS Console and open API Gateway > ElevateMeFrontEnd > Stages > Prod. Copy URL
- Go back to slack website with your app and Select Basic Information.
![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-7.png)

- Select Add Features and Functionality, Click Slash Command.
![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-9.png)

- Click Create New Command
![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-10.png)

- Fill in details, Paste Api Gateway url into Request URL and add /elevateme to end of it. (if its giving you an error, check for space at front or url)
![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-11-fix.png)

- Click Save
- You may get re-prompted to authenticate app. Click Apply.
- You should now see integration added in the slack channel you specified.
![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/slack-12.png)
<br>
<br>
<br>

## **Create Cron-Revoker App**

1. Navigate to ./cron-revoker/cron-revoker.yaml
2. Make sure all your Default Parameters are right (remember you need to add the security group your 2-3 private subnets)
3. Navigate to ./source
4. Change your AD DN for users and groups "cn={user},ou=Users,ou=corp,dc=corp,dc=internal" to match your environment.
5. package python up: 
```bash
$ make install && make build
```
6. go up one folder "cd .."
7. make sure parameters are correct in cron-revoker.yaml
8. run sam package:
```bash
sam package --template-file cron-revoker.yaml --s3-bucket your-unique-bucket-name --s3-prefix cron-revoker --output-template cron-revoker-output.yaml
```
9. run sam deploy 
```bash
sam deploy --template-file cron-revoker-output.yaml --stack-name ElevateMeRevoker --capabilities CAPABILITY_IAM
```

<br>
<br>

# Considerations for Domain Admins/Enterprise Admins

Active Directory has a hidden gem for protecting groups like Domain Admins and other sensitive groups.
It's called the AdminSDHolder. If you modify the security properties of these types of groups it will let you do it however about an hour later you will notice your change is gone.

This is the SDProp service running every hour cleaning up any permissions that might have been modified. It cleans the permissions of all the sensitive groups by reading the permissions of an OU "YourDomain" > System > AdminSDHolder (turn on advanced features to see the System OU) then applying it to all the groups. 

You can read about it more [here](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

To work around this give your service account permissions to add/remove users on the "YourDomain" > System > AdminSDHolder. It only need permissions to read/write.

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/ad-1.png)

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/ad-2.png)


# FAQ

## But I need to stay in Domain Admins 24/7....

Over the years Microsoft has actually done quite a good job with RBAC (Role Based Access Control) with most of its products (AD, Exchange, SQL etc). 
The main issue I have seen at a lot of Enterprise companies is these solutions are usually implemented from a projects team that is never the same team to support the product (if only there was some ill defined term we could call this?). 

Most Microsoft products have the RBAC permissions ready to go they just need to be implemented and populated. 

Now it is true you need to be a member of Domain Admins to log into a Domain Controller but this should be a rare event for general operations work. 

>If you are RDPing into Domain Controllers to use "Users and Computers" you're doing it wrong...

## Does this app work for Teams?

Currently Teams don't support /slash commands which means you can apply everything for this repo except for the front-end script. You would need to build your own front end server/app to handle that part.

I am currently trying to build a bot to handle the /slash command in teams. Work in progress.

## Slack keeps saying "internal server address"

![](https://github.com/MattTunny/ElevateMe/blob/master/pictures/error-1.png)

- Make sure your lambda has access to ldap from the subnets you provided. 
- Easy way to test to is to spin up a linux box in that subnet and run the python code to connect to your ldap server.