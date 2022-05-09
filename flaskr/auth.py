import base64
from curses import meta
import hmac
from os import environ as env
from typing import Dict
from functools import wraps

import requests
import boto3
from flask import Blueprint, request, jsonify, make_response, session
from dotenv import load_dotenv, find_dotenv
from flask_cors import cross_origin, CORS

# Resources
# https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-identity.html?highlight=get_credentials_for_identity#CognitoIdentity.Client.get_credentials_for_identity
# https://www.youtube.com/watch?v=9pvygKIuCpI
# https://stackoverflow.com/questions/70551382/boto3-how-to-use-amazon-cognito-to-get-temporary-credentials-from-identity-pool
# https://redux-toolkit.js.org/rtk-query/usage/customizing-queries#automatic-re-authorization-by-extending-fetchbasequery

#  Define blueprint
bp = Blueprint('auth', __name__, url_prefix='/api/auth')
# enable CORS
CORS(bp)

# Load environment variables from .env file
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
COGNITO_REGION=env.get('COGNITO_REGION')
COGNITO_CLIENT_ID=env.get('COGNITO_GOOGLE_CLIENT_ID')
COGNITO_CLIENT_SECRET=env.get('COGNITO_CLIENT_SECRET')
COGNITO_USER_POOL_ID=env.get('COGNITO_USER_POOL_ID')
COGNITO_IDENTITY_POOL_ID=env.get('COGNITO_IDENTITY_POOL_ID')
SECRET_KEY=env.get('SECRET_KEY')

# Set session secret
bp.secret_key = SECRET_KEY

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

# Get user attributes from Cognito response
def get_user_attr(user_data):
    email = None
    for attribute in user_data['UserAttributes']:
        if attribute['Name'] == 'email':
            email = attribute['Value']
            break

    return {
      'email': email
    }

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

# Get secret hash
def get_secret_hash(username):
    message = username + COGNITO_CLIENT_ID
    dig = hmac.new(bytearray(COGNITO_CLIENT_SECRET, 'utf-8'), msg=message.encode('utf-8'), digestmod='sha256').digest()
    return base64.b64encode(dig).decode()

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

        # handle other errors
        except Exception as e:
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
    return {'message': 'Success - private'}


# Login route
@bp.route('/signin', methods=['POST'])
def signin():
    # Validate request data
    data = None
    if request.is_json:
        data = request.get_json()

    secret_hash = get_secret_hash(data['email'])

    # initiate authentication
    response = userClient.initiate_auth(
      ClientId=COGNITO_CLIENT_ID,
      AuthFlow='USER_PASSWORD_AUTH',
      AuthParameters={
        'USERNAME': data['email'],
        'PASSWORD': data['password'],
        'SECRET_HASH': secret_hash
      }
    )

    access_token = response['AuthenticationResult']['AccessToken']
    refresh_token = response['AuthenticationResult']['RefreshToken']

    # retrieve user data
    user_data = userClient.get_user(AccessToken=access_token)

    # create user object from user data
    user = get_user_attr(user_data)

    # set refresh token cookie
    session['refresh_token'] = refresh_token

    # return user data json
    return {
        'token': access_token,
        'user': user
    }


# Signup route
@bp.route('/signup', methods=['POST'])
def signup():
    # Validate request data
    data = None
    if request.is_json:
        data = request.get_json()

    secret_hash = get_secret_hash(data['email'])

    # Signup user
    try:
        response = userClient.sign_up(
          ClientId=COGNITO_CLIENT_ID,
          SecretHash=secret_hash,
          Username=data['email'],
          Password=data['password'],
        )
    except Exception as e:
        code = e.response['Error']['Code']
        description = e.response['Error']['Message']
        raise AuthError({
                  "code": code, 
                  "description": description
              }, 401)

    return response;
    

# Confirm signup route
@bp.route('/confirm', methods=['POST'])
def confirm():
    data = None
    if request.is_json:
        data = request.get_json()
    
    secret_hash = get_secret_hash(data['email'])

    response = userClient.confirm_sign_up(
      ClientId=COGNITO_CLIENT_ID,
      SecretHash=secret_hash,
      Username=data['email'],
      ConfirmationCode=data['confirm_code'],
    )

    return response

# Resend signup confirmation code route
@bp.route('/resend', methods=['POST'])
def resend():
    data = None
    if request.is_json:
        data = request.get_json()
    
    secret_hash = get_secret_hash(data['email'])

    response = userClient.resend_confirmation_code(
      ClientId=COGNITO_CLIENT_ID,
      SecretHash=secret_hash,
      Username=data['email']
    )
    return response


# Signout route
@bp.route('/signout', methods=['POST'])
def signout():
  access_token = get_token_auth_header()

  # Signout user
  response = userClient.global_sign_out(
    AccessToken=access_token
  )

  # Remove refresh token cookie
  session.pop('refresh_token', None)

  # send response
  return response

@bp.route('/current_session', methods=['GET'])
def current_session():
    # Get refresh token from cookie
    try:
      refreshToken = session['refresh_token']
    except Exception as e:
        raise AuthError({
                  "code": "session_expired", 
                  "description": "session not found"
              }, 401)

    # Refresh tokens
    response = userClient.initiate_auth(
      ClientId=COGNITO_CLIENT_ID,
      AuthFlow='REFRESH_TOKEN',
      AuthParameters={
        'REFRESH_TOKEN': refreshToken,
        'SECRET_HASH': COGNITO_CLIENT_SECRET
      }
    )

    accessToken = response['AuthenticationResult']['AccessToken']

    # retrieve user data
    user_data = userClient.get_user(AccessToken=accessToken)
    print(user_data)

    # create user object from user data
    user = get_user_attr(user_data)

    # return user data json
    return {
        'token': accessToken,
        'user': user
    }


#Get user attributes route
@bp.route('/user', methods=['GET'])
@requires_auth
def user():
    user = get_user_attr(request.userInfo)

    return {
      "user": user
    }


@bp.route('/refresh', methods=['GET'])
def refresh():
    # Get refresh token from cookie
    refreshToken = session['refresh_token']
    if refreshToken is None:
        raise AuthError({
            'code': 'invalid_request',
            'description': 'Refresh token not found'
        }, 401)

    # Refresh tokens
    response = userClient.initiate_auth(
      ClientId=COGNITO_CLIENT_ID,
      AuthFlow='REFRESH_TOKEN',
      AuthParameters={
        'REFRESH_TOKEN': refreshToken,
        'SECRET_HASH': COGNITO_CLIENT_SECRET
      }
    )

    accessToken = response['AuthenticationResult']['AccessToken']

    # Return access token
    return {
      "token": accessToken
    }


@bp.route('/token', methods=['POST'])
def token():
    # get code from body
    code = request.get_json()['code']
    client_id = COGNITO_CLIENT_ID
    client_secret = COGNITO_CLIENT_SECRET
    callback_uri = 'http://localhost:4040/signin'
    cognito_app_url = 'https://homeuudemo.auth.us-east-1.amazoncognito.com'

    token_url = f"{cognito_app_url}/oauth2/token"
    auth = requests.auth.HTTPBasicAuth(client_id, client_secret)

    params = {
      'grant_type': 'authorization_code',
      'client_id': client_id,
      'code': code,
      'redirect_uri': callback_uri
    }

    response = requests.post(token_url, auth=auth, data=params)

    refresh_token = response.json().get('refresh_token')
    access_token = response.json().get('access_token')

    # retrieve user data
    user_data = userClient.get_user(AccessToken=access_token)
    print(user_data)

    # create user object from user data
    user = get_user_attr(user_data)

    # set refresh token cookie
    session['refresh_token'] = refresh_token

    # return user data json
    return {
        'token': access_token,
        'user': user
    }


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

@bp.route('/users', methods=['GET'])
def users():
    users = userClient.list_users(
        UserPoolId=COGNITO_USER_POOL_ID,
        AttributesToGet=['email'],
        Filter='email = "erikguntner@gmail.com"'
    )

    return users;
