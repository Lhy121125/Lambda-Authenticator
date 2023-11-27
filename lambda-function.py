import json
import jwt
from jwt.exceptions import DecodeError, ExpiredSignatureError, InvalidTokenError

def decode_jwt(token):
    try:
        # Decode the token without verification
        decoded_payload = jwt.decode(token, options={"verify_signature": False})
        return decoded_payload
    except (DecodeError, ExpiredSignatureError, InvalidTokenError) as e:
        print("JWT decoding error:", str(e))
        return None

def lambda_handler(event, context):
    print('*************** The event is: ***************')
    print(event)

    auth_token = event.get('authorizationToken', None)
    
    auth = 'Deny' 
    message = "Access denied: Email not authorized."
    
    # Decode the JWT token
    decoded_jwt = decode_jwt(auth_token)
    if decoded_jwt is None:
        auth = 'Deny'
        message = "Authentication failed: Token could not be decoded."
    else:
        # Extract the email from the payload
        email = decoded_jwt.get('email', '')
        
        # List of allowed emails
        allowed_emails = [
            'cs4206@columbia.edu',
            'hl3648@columbia.edu',
            'ly2555@columbia.edu',
            'qw2324@columbia.edu',
            'dz2506@columbia.edu'
        ]
        
        if email in allowed_emails:
            auth = 'Allow'
            message = "Access granted."
        else:
            auth = 'Deny'
            message = "Access denied: Email not authorized."
    
    authResponse = {
        "principalId": "user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Resource": ["arn:aws:execute-api:us-east-2:149601685977:l914fjxkj3/*/*"],
                "Effect": auth
            }]
        },
        "context": {
            "message": message
        }
    }
    
    return authResponse
