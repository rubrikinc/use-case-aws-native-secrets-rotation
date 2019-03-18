#!/usr/local/bin/python3

import boto3
import logging
import os
import ast
import json
import rubrik_cdm
from copy import deepcopy
import urllib3
urllib3.disable_warnings()

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Secrets Manager Rotation Template
    This is a template for creating an AWS Secrets Manager rotation lambda
    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)
        context (LambdaContext): The Lambda runtime information
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not properly configured for rotation
        KeyError: If the event parameters do not contain the expected keys
    """
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the local secret manager client
    secret_service_client = boto3.client('secretsmanager')

    # Make sure the version is staged correctly
    metadata = secret_service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    # retrieve current secret
    current_secret = ast.literal_eval(secret_service_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")['SecretString'])

    # if the secret is for the account this function is executing in, use this function's role to talk to IAM
    if current_secret['accountid'] == context.invoked_function_arn.split(":")[4]:
        iam_service_client = boto3.client('iam')
    # otherwise, attempt to assume a role into the target account
    else:
        iam_service_client = assume_role(role_arn=current_secret['rolearn'], session_name=current_secret['accountid']+'_session').client('iam')

    if step == "createSecret":
        create_secret(secret_service_client, arn, token, iam_service_client, current_secret)

    elif step == "setSecret":
        set_secret(secret_service_client, arn, token)

    elif step == "testSecret":
        test_secret(secret_service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(secret_service_client, arn, token, iam_service_client)

    else:
        raise ValueError("Invalid step parameter")


def assume_role(role_arn=None, session_name='my_session'):
    """
    If role_arn is given assumes a role and returns boto3 session
    otherwise return a regular session with the current IAM user/role
    """
    if role_arn:
        client = boto3.client('sts')
        response = client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'])
        return session
    else:
        return boto3.Session()


def create_secret(secret_service_client, arn, token, iam_service_client, current_secret):
    """Create the secret
    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.
    Args:
        secret_service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
    """
    # Make sure the current secret exists
    secret_service_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        secret_service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except secret_service_client.exceptions.ResourceNotFoundException:     
        
        # Generate new IAM credentials for this secret, fail if too many keys already exist
        if len(iam_service_client.list_access_keys(UserName=current_secret['iamuser'])['AccessKeyMetadata']) > 1:
            logger.error("User %s has more than one access key definied, cannot rotate" % current_secret['iamuser'])
            raise ValueError("User %s has more than one access key definied, cannot rotate" % current_secret['iamuser'])

        else:
            new_access_keys = iam_service_client.create_access_key(UserName=current_secret['iamuser'])

            # Create new secret string
            new_secret = deepcopy(current_secret)
            new_secret['iamaccesskey'] = new_access_keys['AccessKey']['AccessKeyId']
            new_secret['iamsecretkey'] = new_access_keys['AccessKey']['SecretAccessKey']
            new_secret_json = json.dumps(new_secret)

            # Put the secret
            secret_service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=new_secret_json, VersionStages=['AWSPENDING'])
            logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


def set_secret(secret_service_client, arn, token):
    """Set the secret
    This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
    credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.
    Args:
        secret_service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    # Retrieve secrets
    current_secret = ast.literal_eval(secret_service_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")['SecretString'])
    pending_secret = ast.literal_eval(secret_service_client.get_secret_value(SecretId=arn, VersionStage="AWSPENDING")['SecretString'])
    rubrik_credentials = ast.literal_eval(secret_service_client.get_secret_value(SecretId='/rubrik/rubrik_cdm_credentials', VersionStage="AWSCURRENT")['SecretString'])


    # connect to rubrik api
    rubrik = rubrik_cdm.Connect(rubrik_credentials['rubrikhost'], rubrik_credentials['rubrikuser'], rubrik_credentials['rubrikpassword'])


    # find cloud native source, generate config for update operation
    cloud_sources = rubrik.get('internal', '/aws/account', timeout=15, authentication=True)['data']
    logger.info('attempting to get current cloud source detail from rubrik...')
    for source in cloud_sources:
        source_detail = rubrik.get('internal', '/aws/account/'+source['id'], timeout=15, authentication=True)
        logger.info('got cloud source detail for %s' % source['id'])
        logger.info(source_detail)
        logger.info('checking if source detail access key %s matches current access key %s' % (source_detail['accessKey'], current_secret['iamaccesskey']))
        if source_detail['accessKey'] == current_secret['iamaccesskey']:
            logger.info('found match!')
            source_update_detail = deepcopy(source_detail)
            source_update_detail['secretKey'] = pending_secret['iamsecretkey']
            source_update_detail['accessKey'] = pending_secret['iamaccesskey']
            details_to_remove = ('configuredSlaDomainName', 'primaryClusterId', 'id', 'configuredSlaDomainId')
            for key in details_to_remove:
                source_update_detail.pop(key, None)
        else:
            logger.info('no match found')

    # if we found a matching Cloud Source, rotate the access key
    if source_update_detail:
        rubrik.update_aws_native_account(source_update_detail['name'], source_update_detail, timeout=30)
    else:
        logger.error("Could not find Cloud Native Source on Rubrik %s with access key %s" % (rubrik_credentials['rubrikhost'], current_secret['iamaccesskey']))
        raise ValueError("Could not find Cloud Native Source on Rubrik %s with access key %s" % (rubrik_credentials['rubrikhost'], current_secret['iamaccesskey']))


def test_secret(secret_service_client, arn, token):
    """Test the secret
    This method should validate that the AWSPENDING secret works in the service that the secret belongs to. For example, if the secret
    is a database credential, this method should validate that the user can login with the password in AWSPENDING and that the user has
    all of the expected permissions against the database.
    Args:
        secret_service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    # retrieve pending secret
    pending_secret = ast.literal_eval(secret_service_client.get_secret_value(SecretId=arn, VersionStage="AWSPENDING")['SecretString'])
    
    # connect to rubrik api
    rubrik_credentials = ast.literal_eval(secret_service_client.get_secret_value(SecretId='/rubrik/rubrik_cdm_credentials', VersionStage="AWSCURRENT")['SecretString'])
    rubrik = rubrik_cdm.Connect(rubrik_credentials['rubrikhost'], rubrik_credentials['rubrikuser'], rubrik_credentials['rubrikpassword'])

    # find relevant cloud source
    cloud_sources = rubrik.get('internal', '/aws/account', timeout=60, authentication=True)['data']
    for source in cloud_sources:
        source_detail = rubrik.get('internal', '/aws/account/'+source['id'], timeout=60, authentication=True)
        if source_detail['accessKey'] == pending_secret['iamaccesskey']:
            source_id = source_detail['id']
    
    # check if the cloud source can iterate subnets in us-east-1
    try:
        rubrik.get('internal', '/aws/account/%s/subnet?region=us-east-1' % (source_id), timeout=60, authentication=True)
    except:
        logger.error("Error iterating subnets in us-east-1 for Cloud Source %s" % source_id)
        raise ValueError("Error iterating subnets in us-east-1 for Cloud Source %s" % source_id)

    logger.info("testSecret: Successfully tested %s with new access keys" % source_id)


def finish_secret(secret_service_client, arn, token, iam_service_client):
    """Finish the secret
    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.
    Args:
        secret_service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist
    """
    # Get info about the depricated access key for deletion
    depricated_secret = ast.literal_eval(secret_service_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")['SecretString'])
    
    # First describe the secret to get the current version
    metadata = secret_service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    secret_service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (version, arn))
    
    # Delete the depricated access key
    iam_service_client.delete_access_key(UserName=depricated_secret['iamuser'], AccessKeyId=depricated_secret['iamaccesskey'])
    logger.info("Deleted depricated access key %s" % depricated_secret['iamaccesskey'])