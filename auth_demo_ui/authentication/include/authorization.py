from .utils import get_current_time
from .http_error import handle_status

import os, requests, json

def get_authorization():
    http_authorization = {}
    http_authorization_header = {}
    http_authorization['request'] = {}
    datetime_now = get_current_time()
    http_authorization['requestTime'] = datetime_now
    http_authorization['request']['clientId'] = os.environ.get('CLIENT_ID')
    http_authorization['request']['secretKey'] = os.environ.get('SECRET_KEY')
    http_authorization['request']['appId'] = os.environ.get('APP_ID')
    http_autorization_request_body = json.dumps(http_authorization)
    http_authorization_header['content-type'] = 'application/json'

    response = requests.post(os.environ.get('ID_AUTH_MANAGER'), data=http_autorization_request_body, verify=False, headers=http_authorization_header)

    if response.status_code <= 599 and response.status_code >= 400:
        error_message = {
            "Error": response.status_code,
            "Error Message": handle_status(response.status_code)
        }

        return error_message

    return response.headers['authorization']