from flask import Flask
import os
import boto3
from dotenv import load_dotenv
load_dotenv()

# Enter email you want to use for account
username = 'example@gmail.com'
# Enter passwird you want to use for account
password = '#Abc1234'
# Confirm code returned by email and used in confirm route
confirm_code = ''
# Access token returned from signup/confirm
access_token=''

client = boto3.client('cognito-idp', region_name=os.getenv('COGNITO_REGION'))

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World!'

# Login route
@app.route('/login', methods=['POST'])
def login():
    response = client.initiate_auth(
      ClientId=os.getenv('COGNITO_CLIENT_ID'),
      AuthFlow='USER_PASSWORD_AUTH',
      AuthParameters={
        'USERNAME': username,
        'PASSWORD': password
      }
    )

    print(response['AuthenticationResult']['AccessToken'])
    print(response['AuthenticationResult']['RefreshToken'])

    return response

# Signup route
@app.route('/signup', methods=['POST'])
def signup():
    response = client.sign_up(
      ClientId=os.getenv('COGNITO_CLIENT_ID'),
      Username=username,
      Password=password,
    )
    return response

# Confirm signup route
@app.route('/confirm', methods=['POST'])
def confirm():
    response = client.confirm_sign_up(
      ClientId=os.getenv('COGNITO_CLIENT_ID'),
      Username=username,
      ConfirmationCode=confirm_code,
    )
    return response

# Resend confirmation code route
@app.route('/resend', methods=['POST'])
def resend():
    response = client.resend_confirmation_code(
      ClientId=os.getenv('COGNITO_CLIENT_ID'),
      Username=username
    )
    return response

#Get user attributes route
@app.route('/user', methods=['GET'])
def user():
    response = client.get_user(
      AccessToken=access_token
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
    response = client.forgot_password(
      ClientId=os.getenv('COGNITO_CLIENT_ID'),
      Username=username
    )
    return response