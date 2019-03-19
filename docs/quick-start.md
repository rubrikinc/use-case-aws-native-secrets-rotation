# Quick Start Guide: AWS Secrets Manager Key Rotation for Rubrik Native Protection

Rubrik’s API first architecture enables organizations to embrace and integrate Rubrik functionality into their existing automation processes. Many AWS consumers prefer to manage the rotation secrets via the AWS Secrets Manager service.

This solution is designed to allow customers to quickly deploy an architecture that provides IAM credential rotation for  Rubrik EC2 Native protection across multiple AWS accounts. The diagram below logically describes a fully deployed deployed environment with a "Hub" account that that contains the rotation logic for all "Spoke" accounts protected by Rubrik.


![image](https://user-images.githubusercontent.com/16825470/54544748-a2ee3700-4976-11e9-9594-d63569fe3b4b.png)

Deployment of the solution consists of the following steps, which are covered in more detail in the sections below:

1. Deploy the rotation logic and IAM assets into your hub account using `deploy_lambda_function.cform` 
2. Deploy the IAM assets into your spoke accounts using `deploy_crossaccount_role.cform`
3. Create IAM access keys for each IAM user
4. Add cloud native sources to Rubrik for each AWS account
5. Create secrets for each AWS account in AWS Secrets Manager as documented, validate rotation works properly

## 1. Deploy the rotation logic and IAM assets into your hub account using `deploy_lambda_function.cform`

Using `deploy_lambda_function.cform`, deploy a CloudFormation Stack into the desired region in your hub account. You will need to download the latest `rk_secret_rotator.zip` from the [releases section of this repository](https://github.com/rubrikinc/aws-native-secrets-rotation/releases) and place it in an S3 
bucket in the same region where you will be deploying this stack. Typically this soluton will be deployed into some sort of shared services environment as connectivity back to the Rubrik is required.

**`deploy_lambda_function.cform` takes the following parameters:**

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

### `deploy_lambda_function.cform` produces the following outputs:

#### Stack Outputs
Output | Description
------------ | -------------
rubrikec2tagfunctionARN | ARN of the Lambda function created
rubrikEc2SecretRotatorRoleARN | ARN of the role created for lambda

### Add password to `/rubrik/rubrik_cdm_credentials` in Secrets Manager
Once the stack has been created, you will need to add the password for your rubrik cluster to `/rubrik/rubrik_cdm_credentials` 
in secrets manager. Simply browse to the newly created secret inside of the Secrets Manager console, then populate the rubrikpassword value with the approrpiate password.

![image](https://user-images.githubusercontent.com/16825470/54553076-cec5e880-4987-11e9-91ab-a9d95dc40d38.png)

## 2. Deploy the IAM assets into your spoke accounts using deploy_crossaccount_role.cform
Using `deploy_crossaccount_role.cform`, deploy a CloudFormation Stack into the desired region in each of your spoke account accounts. This stack will create all of the necessary IAM assets for protecting the spoke account with Rubrik EC2 Native protection as well rotating the IAM user's credentials via Secrets Manager from the hub account.

### `deploy_crossaccount_role.cform` takes the following parameters:
#### IAM Parameters
Parameter | Description
------------ | -------------
IAMusername | Name of the Rubrik IAM user for to be provisioned in this account
SourceAccount | Account number of the source account for key rotation (hub account)

### `deploy_crossaccount_role.cform` produces the following outputs:

#### Stack Outputs
Output | Description
------------ | -------------
rubrikEc2SecretRotatorRoleARN | ARN of IAM role used to rotate credentials on Rubrik IAM User
rubrikEc2ProtectionUserARN | ARN of IAM user used for Rubrik EC2 Native Protection

## 3. Create IAM access keys for each hub and spoke IAM user
Using the AWS console, or the following AWS CLI command: `aws iam create-access-key --user-name username` create access keys for each of the IAM users that will be used for EC2 native protection via Rubrik. By default, this will be **rubrikEc2ProtectionUser** in your spoke accounts and will be the user you specified in the **localRubrikIAMUser** parameter in Step 1. Store these keys in a secure location for use in the next step.

## 4. Add cloud native sources to Rubrik for each AWS account
1. Log in to Rubrik
2. Click on the settings/gear icon in the top right hand corner of the Rubrik console
3. Choose Cloud Sources
4. Click the plus sign to add a cloud source
5. Enter the access key and secret key for the AWS account you are protecting
6. Select the regions you wish to protect
7. Configure file level indexing (if applicable)
8. Click Add
9. Validate that the Cloud Source successfully refreshes and enters a connected state
10. Repeat for each AWS account that Rubrik will be protecting

## 5. Create secrets for each AWS account in AWS Secrets Manager as documented, validate rotation works properly
Once you have the Cloud Sources added to Rubrik, we can configure rotation via secrets manager. The simplest way to accomplish this is using secret templates in this repo. Examples for the [Hub Account Secret](../local_account_secret_example.json) and for the [Spoke Account Secrets](../assumerole_cross_account_secret_example.json) are available in this repo. 

### Each Secret Consists of the following parameters:
Paramter | Description | Example Value
----------| ------------------------------------------------------|-------------
accountid |  Account number of the AWS account we are protecting. | 123456789012
rolearn (spoke only) |  ARN of the role created in the spoke account for rotation, available as output rubrikEc2SecretRotatorRoleARN from deploy_crossaccount_role.cform | arn:aws:iam::123456789012:role/rubrik_ec2_crossaccount_role
iamuser | Name of the IAM user used to protect this AWS account | example-username
iamaccesskey| Access key currently used to by iamuser (created in step 4, must match cloud source in rubrik or rotation will fail) | ABCDEFGHIJKLMNOPQRST
iamsecretkey | Secret key currently used to by iamuser (created in step 4) | th1s1sAn3xampl3k3yfR0MAWS

### Execute the following steps for each of your protected AWS accounts in the hub account to enable and test rotation

1. In the hub account, select store a new secret in Secrets Manager
2. Select other types of secrets and toggle the view to plaintext
3. Paste in the appropriate template from this repo (Hub/Spoke)
4. Update the values to correspond to the AWS account you are protecting
5. Choose the appropriate KMS key to encrypt your secret
6. Click Next

![image](https://user-images.githubusercontent.com/16825470/54560737-6253e500-4999-11e9-9129-df0d5c72c401.png)

7. Enter your desired name for the secret
8. Enter your desired descroption for the secret
9. Click Next

![image](https://user-images.githubusercontent.com/16825470/54561557-4bae8d80-499b-11e9-8b7f-b88d472edbe5.png)

10. Select Enable automatic rotation
11. Set the rotation interval to your desired value
12. Select the lambda function deployed by deploy_lambda_function.cform
13. Click Next, then click Store on the following screen. This should initiate rotation on your secret immediately, see CloudWatch Logs for detail on success or failure.

![image](https://user-images.githubusercontent.com/16825470/54561773-caa3c600-499b-11e9-9bef-b4dfe4640ae6.png)