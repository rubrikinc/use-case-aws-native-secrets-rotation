# Quick Start Guide: AWS Secrets Manager Key Rotation for Rubrik Native Protection

## Introduction: AWS Secrets Manager Key Rotation for Rubrik Native Protection
Rubrik’s API first architecture enables organizations to embrace and integrate Rubrik functionality into their 
existing automation processes. Many AWS consumers prefer to manage the rotation secrets via the AWS Secrets Manager service.
This solution is designed to allow customers to quickly deploy an architecture that provides IAM credential rotation for 
Rubrik EC2 Native protection across multiple AWS accounts. The diagram below logically describes a fully deployed deployed environment
with a "Hub" account that that contains the rotation logic for all "Spoke" accounts protected by Rubrik.


![image](https://user-images.githubusercontent.com/16825470/54544748-a2ee3700-4976-11e9-9594-d63569fe3b4b.png)

### Deployment of the solution consists of the following steps, which are covered in more detail in the sections below:
1. Deploy the rotation logic and IAM assets into your hub account using deploy_lambda_function.cform  
2. Deploy the IAM assets into your spoke accounts using deploy_crossaccount_role.cform
3. Create IAM access keys for each IAM user
4. Add cloud native sources to Rubrik for each spoke account
5. Create secrets for each AWS account in AWS Secrets Manager as documented, validate rotation works properly

## 1. Deploy the rotation logic and IAM assets into your hub account using deploy_lambda_function.cform 

Using deploy_lambda_function.cform, deploy a CloudFormation Stack into the desired region in your hub account. You will 
need to download the latest rk_secret_rotator.zip from the releases section of this repository and place it in an S3 
bucket in the same region where you will be deploying this stack. Typically this soluton will be deployed into some sort of 
shared services environment as connectivity back to the Rubrik is required.

### deploy_lambda_function.cform takes the following parameters:

#### Lambda Function Source Parameters
Parameter | Description
------------ | -------------
lambdaBucketName | Name of the S3 bucket containing rk_secret_rotator.zip, must be in the same region as the target for this stack deployment.
lambdaZipName | Name of the lambda function zip file inside the S3 bucket, defaults to rk_secret_rotator.zip.

#### Lambda Execution VPC Parameters
Parameter | Description
------------ | -------------
lambdaVpcId | VPC that the lambda function will use for execution, must have connectivity back to Rubrik on 443 via VPN, DirectConnect, or VPC Peering as well as connectivity to the secrets manager and IAM API endpoints.
lambdaSubnet1 | First subnet that the lambda function will use for execution, must have connectivity back to Rubrik on 443 via VPN, DirectConnect, or VPC Peering as well as connectivity to the secrets manager and IAM API endpoints.
lambdaSubnet2 | Second subnet that the lambda function will use for execution, must have connectivity back to Rubrik on 443 via VPN, DirectConnect, or VPC Peering as well as connectivity to the secrets manager and IAM API endpoints.
lambdaSsecurityGroup | Security group that the lambda function will use for execution, must allow connectivity back to Rubrik on 443 as well as connectivity to the secrets manager and IAM API endpoints.

#### Rubrik Specific Parameters
Parameter | Description
------------ | -------------
localRubrikIAMUser | Name of the Rubrik IAM user for THIS AWS account (assumes we are protecting the hub account as well).
RubrikCDMHostname | Hostname or IP address of the Rubrik cluster we will be rotating EC2 Native Protection Secrets on.
RubrikCDMUsername | Username used to connect to the Rubrik API.
RubrikSecretKMSKey | KMS Key ARN that will be used to encrypt the Rubrik CDM credentials in secrets manager.

#### Stack Outputs
Output | Description
------------ | -------------
rubrikec2tagfunctionARN | ARN of the Lambda function created
rubrikEc2SecretRotatorRoleARN | ARN of the role created for lambda

### Add password to /rubrik/rubrik_cdm_credentials in Secrets Manager
Once the stack has been created, you will need to add the password for your rubrik cluster to /rubrik/rubrik_cdm_credentials 
in secrets manager. Simply browse to the newly created secret inside of the Secrets Manager console, then populate the rubrikpassword value with the approrpiate password.

![image](https://user-images.githubusercontent.com/16825470/54553076-cec5e880-4987-11e9-91ab-a9d95dc40d38.png)

## 1. Deploy the rotation logic and IAM assets into your hub account using deploy_lambda_function.cform 
