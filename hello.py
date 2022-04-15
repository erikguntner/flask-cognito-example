from flask import Flask, request
import os
import boto3
from dotenv import load_dotenv
load_dotenv()

client = boto3.client('cognito-idp', region_name=os.getenv('COGNITO_REGION'))

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def hello_world():
    data = None
    if request.is_json:
        data = request.get_json()

    print(data['message'])
    return 'Hello World!'

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = None
    if request.is_json:
        data = request.get_json()

    # initiate authentication
    response = client.initiate_auth(
      ClientId=os.getenv('COGNITO_CLIENT_ID'),
      AuthFlow='USER_PASSWORD_AUTH',
      AuthParameters={
        'USERNAME': data['username'],
        'PASSWORD': data['password']
      }
    )

    access_token = response['AuthenticationResult']['AccessToken']
    refresh_token = response['AuthenticationResult']['RefreshToken']

    # retrieve user data
    user_data = client.get_user(AccessToken=access_token)

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
@app.route('/signup', methods=['POST'])
def signup():
    data = None
    if request.is_json():
        data = request.get_json()


    response = client.sign_up(
      ClientId=os.getenv('COGNITO_CLIENT_ID'),
      Username=data['username'],
      Password=data['password'],
    )

    return response

# Signout route
@app.route('/signout', methods=['POST'])
def signout():
  data = None
  if request.is_json():
      data = request.get_json()

  response = client.global_sign_out(
    AccessToken=data['access_token']
  )

  return response

# Confirm signup route
@app.route('/confirm', methods=['POST'])
def confirm():
    data = None
    if request.is_json():
        data = request.get_json()

    response = client.confirm_sign_up(
      ClientId=os.getenv('COGNITO_CLIENT_ID'),
      Username=data['username'],
      ConfirmationCode=data['confirm_code'],
    )
    return response

# Resend signup confirmation code route
@app.route('/resend', methods=['POST'])
def resend():
    data = None
    if request.is_json():
        data = request.get_json()

    response = client.resend_confirmation_code(
      ClientId=os.getenv('COGNITO_CLIENT_ID'),
      Username=data['username']
    )
    return response

#Get user attributes route
@app.route('/user', methods=['GET'])
def user():
    data = None
    if request.is_json():
        data = request.get_json()
    

    response = client.get_user(
      AccessToken=data['access_token']
    )

    attr_sub = None
    for attr in response['UserAttributes']:
        if attr['Name'] == 'sub':
            attr_sub = attr['Value']
            break

    print(attr_sub)

    return response


# Forgot password route
@app.route('/forgot_password', methods=['GET'])
def forgot_password():
    data = None
    if request.is_json():
        data = request.get_json()

    response = client.forgot_password(
      ClientId=os.getenv('COGNITO_CLIENT_ID'),
      Username=data['username']
    )
    return response