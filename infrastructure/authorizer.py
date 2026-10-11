import json
import jwt
from jwt import PyJWKClient
import os

COGNITO_USER_POOL_ID = os.environ["COGNITO_USER_POOL_ID"]
COGNITO_REGION = os.environ["COGNITO_REGION"]
COGNITO_ISSUER = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"

JWKS_CLIENT = PyJWKClient(f"{COGNITO_ISSUER}/.well-known/jwks.json")

def verify_jwt(token):
    """Verify JWT Token"""
    signing_key = JWKS_CLIENT.get_signing_key_from_jwt(token)
    return jwt.decode(token, signing_key.key, algorithms=["RS256"], issuer=COGNITO_ISSUER, options={"verify_aud": False})

def api_resource_arn(method_arn):
    """Policy for the whole API, so a cached result works for every route"""
    return method_arn.split("/")[0] + "/*"

def lambda_handler(event, context):
    """Lambda Authorizer"""
    try:
        authorization_token = event.get("authorizationToken", "")
        if authorization_token.startswith("Bearer "):
            token = authorization_token.split("Bearer ")[1]
        else:
            raise ValueError("Authorization token format is incorrect")
        
        claims = verify_jwt(token)

        return {
            "principalId": claims["sub"],
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": "Allow",
                        "Resource": api_resource_arn(event["methodArn"])
                    }
                ]
            },
            "context": claims
        }
    except Exception as e:
        print(f"Authorization failed: {str(e)}")
        return {
            "principalId": "unauthorized",
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": "Deny",
                        "Resource": api_resource_arn(event["methodArn"])
                    }
                ]
            }
        }