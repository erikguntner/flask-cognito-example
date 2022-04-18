from os import environ as env
from typing import Dict
from functools import wraps


import boto3
from flask import Blueprint, request, jsonify
from dotenv import load_dotenv, find_dotenv
from flask_cors import cross_origin, CORS

# Resources
# https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-identity.html?highlight=get_credentials_for_identity#CognitoIdentity.Client.get_credentials_for_identity
# https://www.youtube.com/watch?v=9pvygKIuCpI
# https://stackoverflow.com/questions/70551382/boto3-how-to-use-amazon-cognito-to-get-temporary-credentials-from-identity-pool
# https://redux-toolkit.js.org/rtk-query/usage/customizing-queries#automatic-re-authorization-by-extending-fetchbasequery

#  Define blueprint
bp = Blueprint('auth', __name__, url_prefix='/auth')
# enable CORS
CORS(bp)


# Load environment variables from .env file
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
COGNITO_REGION=env.get('COGNITO_REGION')
COGNITO_CLIENT_ID=env.get('COGNITO_CLIENT_ID')
COGNITO_USER_POOL_ID=env.get('COGNITO_USER_POOL_ID')
COGNITO_IDENTITY_POOL_ID=env.get('COGNITO_IDENTITY_POOL_ID')


# Initialize Cognito clients
userClient = boto3.client('cognito-idp', region_name=COGNITO_REGION)
identityClient = boto3.client('cognito-identity', region_name=COGNITO_REGION)


# Format error reponse and append status code
class AuthError(Exception):
    def __init__(self, error: Dict[str, str], status_code):
        super().__init__()
        self.error = error
        self.status_code = status_code


# Error handler
@bp.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response 


# Get auth token from header
def get_token_auth_header():
  auth = request.headers.get('Authorization', None)
  if not auth:
    raise AuthError({
      'code': 'authorization_header_missing',
      'description': 'Authorization header is expected.'
    }, 401)
  
  parts = auth.split()

  # check if the header is in the correct format
  if parts[0].lower() != 'bearer':
    raise AuthError({
      'code': 'invalid_header',
      'description': 'Authorization header must start with "Bearer".'
    }, 401)
  
  if len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
  if len(parts) > 2:
      raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must be"
                            " Bearer token"}, 401)
  # return token
  token = parts[1]
  return token

# Decorator to check if user is authenticated
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        # Check if token is valid
        
        try:
            # Get user info from token
            userInfo = userClient.get_user(
                AccessToken=token
            )
            # Add user info to request
            request.userInfo = userInfo
            return f(*args, **kwargs)
        except userClient.exceptions.NotAuthorizedException as e:
            code = e.response['Error']['Code']
            description = e.response['Error']['Message']
            raise AuthError({
                      "code": code, 
                      "description": description
                  }, 401)
                                
    return decorated

@bp.route('/', methods=['GET', 'POST'])
def hello_world():
    return 'Hello World!'

@bp.route('/private', methods=['GET'])
@requires_auth
def private():
    print(request.userInfo)
    return 'Success - private'

# Login route
@bp.route('/login', methods=['POST'])
def login():
    data = None
    if request.is_json:
        data = request.get_json()

    # initiate authentication
    response = userClient.initiate_auth(
      ClientId=COGNITO_CLIENT_ID,
      AuthFlow='USER_PASSWORD_AUTH',
      AuthParameters={
        'USERNAME': data['username'],
        'PASSWORD': data['password']
      }
    )
    access_token = response['AuthenticationResult']['AccessToken']
    refresh_token = response['AuthenticationResult']['RefreshToken']
    id_token = response['AuthenticationResult']['IdToken']

    # Retrieve identity pool credentials
    logins = 'cognito-idp.' + COGNITO_REGION + '.amazonaws.com/' + COGNITO_USER_POOL_ID
    identityId = identityClient.get_id(
        IdentityPoolId=COGNITO_IDENTITY_POOL_ID,
        Logins={
            logins: id_token
        }
    )['IdentityId']

    aws_cred = identityClient.get_credentials_for_identity(
        IdentityId=identityId,
        Logins={
            logins: id_token
        }
    )['Credentials']

    # retrieve user data
    user_data = userClient.get_user(AccessToken=access_token)

    # get email from user data
    email = None
    for attribute in user_data['UserAttributes']:
        if attribute['Name'] == 'email':
            email = attribute['Value']
            break

    # return user data json
    return {
        'access_token': access_token,
        'email': email
    }

# Signup route
@bp.route('/signup', methods=['POST'])
def signup():
    data = None
    if request.is_json:
        data = request.get_json()


    response = userClient.sign_up(
      ClientId=COGNITO_CLIENT_ID,
      Username=data['username'],
      Password=data['password'],
    )

    return response

# Signout route
@bp.route('/signout', methods=['POST'])
def signout():
  data = None
  if request.is_json:
      data = request.get_json()

  response = userClient.global_sign_out(
    AccessToken=data['access_token']
  )

  return response

# Confirm signup route
@bp.route('/confirm', methods=['POST'])
def confirm():
    data = None
    if request.is_json:
        data = request.get_json()

    response = userClient.confirm_sign_up(
      ClientId=COGNITO_CLIENT_ID,
      Username=data['username'],
      ConfirmationCode=data['confirm_code'],
    )
    return response

# Resend signup confirmation code route
@bp.route('/resend', methods=['POST'])
def resend():
    data = None
    if request.is_json:
        data = request.get_json()

    response = userClient.resend_confirmation_code(
      ClientId=COGNITO_CLIENT_ID,
      Username=data['username']
    )
    return response

#Get user attributes route
@bp.route('/user', methods=['POST'])
def user():

    response = userClient.get_user(
      AccessToken=data['access_token']
    )

    print('user response: ', response)

    attr_sub = None
    for attr in response['UserAttributes']:
        if attr['Name'] == 'sub':
            attr_sub = attr['Value']
            break

    return response




# Forgot password route
@bp.route('/forgot_password', methods=['GET'])
def forgot_password():
    data = None
    if request.is_json:
        data = request.get_json()

    response = userClient.forgot_password(
      ClientId=COGNITO_CLIENT_ID,
      Username=data['username']
    )
    return response