#
##
##########################################################################
#                                                                        #
#       aws_handler                                                      #
#                                                                        #
#       (c) Vamegh Hedayati                                              #
#                                                                        #
#       Please see https://github.com/vamegh/pylibs                      #
#                    for License Information                             #
#                             GNU/LGPL                                   #
##########################################################################
##
#
#  aws_handler - This handles various aws functions

import base64
import boto3
import json
import logging
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


#yaml config data expected structure:
#
# aws:
#   region: 'eu-west-2'
#   profile: 'default'
#   authenticate: false / true
#   role_arn: <arn_of_role_to_assume> (optional)
#   mfa_arn: <arn_of_mfa usually located on primary account> (optional)

class AWS(object):
    def __init__(self, data=None):
        self.data = data
        self.client = None
        self.session = None
        
    def login(self):
        if 'profile'  not in self.data['aws']:
            self.data['aws']['profile'] = 'default'

        if self.data['aws']['authenticate']:
            # auth is handled by this library - via assume role function
            self.session = self.get_assume_role_session()
        else:
            # auth is handled seperately ie via saml2aws or aws-vault or  existing ~/.aws/credentials
            self.session = self.get_session_profil()

        if not self.session:
            logging.error(f"Sorry you do not have your aws credentials configured\n"
                          f"Please configure this first, these are stored in ~/.aws/credentials. "
                          f"Please provide the correct profile name to use, if different from 'default'")
            raise ValueError('AWS Profile Not Found')

    def get_session (profile):
        aws_profile = self.data['aws']['profile']
        aws_region = self.data['aws']['region']
        return boto3.session.Session(profile_name=aws_profile,
                                     region_name=aws_region)

    def get_assume_role_session(self):
        aws_profile = self.data['aws']['profile']
        aws_region = self.data['aws']['region']
        aws_role_arn = self.data['aws']['role_arn']
        aws_mfa_arn = self.data['aws']['mfa_arn']

        sts_default_provider_chain = boto3.client('sts')
        # Prompt for MFA time-based one-time password (TOTP)
        logging.info("Initiating AWS Login, This authenticates against your chosen profile")
        mfa_TOTP = str(input("Enter the MFA code: "))

        response = sts_default_provider_chain.assume_role(
            RoleArn=aws_role_arn,
            RoleSessionName='aws_login',
            SerialNumber=aws_mfa_arn,
            TokenCode=mfa_TOTP
        )
        creds = response['Credentials']

        logging.warning(f"\nexport AWS_ACCESS_KEY_ID={creds['AccessKeyId']}"
                        f"\nexport AWS_SECRET_ACCESS_KEY={creds['SecretAccessKey']}"
                        f"\nexport AWS_SESSION_TOKEN={creds['SessionToken']}")


        return boto3.session.Session(region_name=aws_region,
                                     profil_name=aws_profile
                                     aws_access_key_id=creds['AccessKeyId'],
                                     aws_secret_access_key=creds['SecretAccessKey'],
                                     aws_session_token=creds['SessionToken'])

    def secrets_manager_client(self):
        aws_region = self.data['aws']['region']
        self.client = self.session.client = (
            service_name='secretsmanager',
            aws_region_name=aws_region
        )

    def ssm_client(self):
        aws_region = self.data['aws']['region']
        self.client = self.session.client = (
            service_name='ssm',
            aws_region_name=aws_region
        )

    def cloudformation_client(self):
        aws_region = self.data['aws']['region']
        self.client = self.session.client = (
            service_name='cloudformation',
            aws_region_name=aws_region
        )

    def get_secret(self, secret=None):
        secret_data = {}
        secret_name = secret.lower()

        try:
            response = self.client.get_secret_value(SecretId=secret_name)
        except ClientError as list_e:
            if list_e.response['Error']['Code'] == 'DecryptionFailureException':
                logging.error('Secrets Manager cannot decrypt the protected secret text using the provided KMS key')
                exit(1)
            elif list_e.response['Error']['Code'] == 'AccessDeniedException':
                logging.error('Access Denied')
                exit(1)
            elif list_e.response['Error']['Code'] == 'ResourceNotFoundException':
                logging.warning(f'secret: {secret_name} not found :: skipping entry')
                exit(1)
            else:
                raise list_e
        else:
            if 'SecretString' in response:
                secret = response['SecretString']
            else:
                secret = base64.b64decode(response['SecretBinary'])

        try:
            secret_data[secret_name] = json.loads(secret)
        except (TypeError, ValueError):
            secret_data[secret_name] = secret

        return secret_data


