from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings

from authentication.include.authorization import get_authorization
from authentication.include.base64 import base64_url_safe_string
from authentication.include.crypto import symmetric_encrypt, asymmetric_encrypt
from authentication.include.http_error import handle_status
from authentication.include.signature import create_signature
from authentication.include.utils import print_hex_binary, get_current_time, get_thumbprint, decrypt_response, get_environment, create_transaction_id

import json, requests, secrets, warnings

warnings.filterwarnings("ignore")

base_path = settings.BASE_DIR
env = get_environment()

individual_id_type_value = {
    'PCN': 'VID',
    'AlyasPSN': 'VID',
}

otp_transactions = {}
transaction_id_length = 10

def index(request):
    return render(request, 'authenticate.html')

@require_http_methods(["POST"])
def requestOTP(request):
    try:
        base_url = env('BASE_URL')
        misp_license_key = env('TSP_LICENSE_KEY')
        partner_id = env('PARTNER_ID')
        partner_api_key = env('API_KEY')
        version = env('VERSION')
        value = json.loads(request.body)
        transaction_id = f'{create_transaction_id(transaction_id_length)}'

        print(f'Request: {value}\n')
        
        errors = []
            
        if not value['otp_channel']:
            errors.append({'error': 'OTP channel is required'})
        
        if not value['individual_id']:
            errors.append({'error': 'Individual ID is required'})
        
        if not value['individual_id_type']:
            errors.append({'error': 'Individual ID Type is required'})

        if errors:
            return JsonResponse(errors, safe=False)
        
        otp_transactions[value['individual_id']] = transaction_id
        
        partner_private_key_location = f'{base_path}/authentication/keys/{partner_id}/{partner_id}-partner-private-key.pem'
        otp_url = f'{base_url}/idauthentication/v1/otp/{misp_license_key}/{partner_id}/{partner_api_key}'
        
        otp_request = {}
        otp_request_header = {}
        otp_request['id'] = 'philsys.identity.otp'
        otp_request['version'] = version
        otp_request['transactionID'] = transaction_id
        otp_request['requestTime'] = get_current_time()
        otp_request['individualId'] = str(value['individual_id'])
        otp_request['individualIdType'] = individual_id_type_value[value['individual_id_type']]
        otp_request['otpChannel'] = value['otp_channel']
        
        otp_request_header['signature'] = create_signature(json.dumps(otp_request), partner_private_key_location)
        otp_request_header['authorization'] = get_authorization()
        otp_request_header['Content-type'] = "application/json"

        if(isinstance(otp_request_header['authorization'], dict)):
            return JsonResponse(otp_request_header['authorization'])
        
        print(f'OTP Request URL:\n{otp_url}\n')
        print(f'OTP Request Header:\n{str(json.dumps(otp_request_header))}\n')
        print(f'OTP Request Body:\n{str(json.dumps(otp_request))}\n')
        
        response = requests.post(otp_url, data=json.dumps(otp_request), headers=otp_request_header, verify=False)
        
        # print(f'OTP Response:\n{str(response.json())}\n')
        
        if response.status_code == 200 and not response.json()["errors"]:
            result = decrypt_response(response)
            return JsonResponse(result)
        elif response.status_code <= 599 and response.status_code >= 400:
            response = {
                "error_code": response.status_code,
                "error_message": handle_status(response.status_code)
            }
        else:
            response = json.loads(str(response.json()).replace('\'', '"').replace('None', '"None"'))
        return JsonResponse(response)
    except Exception as e:
        print(f'An error has encountered: {e}')
        return JsonResponse({'error': 'An error occured. Please try again.'})

@require_http_methods(["POST"])
def authenticate(request):
    try:
        http_request_body = {}
        http_request_header = {}
        http_request_body['requestedAuth'] = {}
        http_request_body['request'] = {}
        http_request_body_request = {}

        value = json.loads(request.body)   
        transaction_id = otp_transactions.get(value['individual_id'], None) if bool(value['otp_value']) else create_transaction_id(transaction_id_length)

        print(f"Request Body: {request.body}\n\n")
        print(f"Request Method: {request.method}\n")
        print(f"Value: {value}\n")

        partner_id = env('PARTNER_ID')
        base_url = env('BASE_URL')
        version = env('VERSION')
        IDA_certificate_location = f'{base_path}/authentication/keys/{partner_id}/{partner_id}-IDAcertificate.cer'
        partner_private_key_location = f'{base_path}/authentication/keys/{partner_id}/{partner_id}-partner-private-key.pem'
        
        auth_url = base_url + '/idauthentication/v1/' + ('kyc/' if value['is_ekyc'] else 'auth/') + env('TSP_LICENSE_KEY') + '/' + env('PARTNER_ID') + '/' + env('API_KEY')
        datetime_now = get_current_time()
        
        errors = []
        
        if not value['individual_id']:
            errors.append({'error': 'Individual ID is required'})
        
        if not value['individual_id_type']:
            errors.append({'error': 'Individual ID Type is required'})
            
        if value['is_ekyc'] in (None, ''):
            errors.append({'error': 'is_ekyc is required'})
        
        if not value['otp_value'] and not value['demo_value'] and not value['bio_value']:
            errors.append({'error': 'Individual information is required'})
            
        if bool(value['otp_value']):
            if not transaction_id:
                errors.append({'error': 'OTP request is required.'})
            else:
                del otp_transactions[value['individual_id']]

        if errors:
            return JsonResponse(errors, safe=False)
        
        http_request_body['id'] = 'philsys.identity.kyc' if value['is_ekyc'] else 'philsys.identity.auth'
        http_request_body['version'] = version
        http_request_body['requestTime'] = datetime_now
        http_request_body['env'] = env('ENV')
        http_request_body['domainUri'] = base_url
        http_request_body['transactionID'] = transaction_id
        http_request_body['requestedAuth']['otp'] = bool(value['otp_value'])
        http_request_body['requestedAuth']['demo'] = bool(value['demo_value'])
        http_request_body['requestedAuth']['bio'] = bool(value['bio_value'])
        http_request_body['consentObtained'] = True
        http_request_body['individualId'] = value['individual_id']
        http_request_body['individualIdType'] = individual_id_type_value[value['individual_id_type']]
        
        http_request_body_request['timestamp'] = datetime_now
        http_request_body_request['otp'] = None
        http_request_body_request['demographics'] = None
        http_request_body_request['biometrics'] = None
        
        if(bool(value['otp_value'])):
            http_request_body_request['otp'] = value['otp_value']
        if(bool(value['demo_value'])):
            http_request_body_request['demographics'] = value['demo_value']
        if(bool(value['bio_value'])):
            http_request_body_request['biometrics'] = value['bio_value']
            
        # request
        authentication_request_request = json.dumps(http_request_body_request)
        authentication_request_request = str(authentication_request_request)

        print(f"Authentication Request: {authentication_request_request}\n")
        
        AES_SECRET_KEY = secrets.token_bytes(32)
        
        http_request_body['request'] = symmetric_encrypt(authentication_request_request, AES_SECRET_KEY)
        http_request_body['request'] = base64_url_safe_string(http_request_body['request'])
        
        # requestSessionKey
        ida_certificate = open(IDA_certificate_location).read()
        ida_certificate_bytes = bytes(ida_certificate, "utf-8")
        request_session_key = asymmetric_encrypt(AES_SECRET_KEY, ida_certificate_bytes)
        http_request_body['requestSessionKey'] = base64_url_safe_string(request_session_key)

        # requestHMAC
        request_HMAC = print_hex_binary(authentication_request_request)
        http_request_body['requestHMAC'] = symmetric_encrypt(request_HMAC, AES_SECRET_KEY)
        http_request_body['requestHMAC'] = base64_url_safe_string(http_request_body['requestHMAC'])
        
        # thumbprint
        http_request_body['thumbprint'] = get_thumbprint(IDA_certificate_location)

        # signature header
        http_request_header['signature'] = create_signature(json.dumps(http_request_body), partner_private_key_location)
        
        # authorization header
        http_request_header['authorization'] = get_authorization()
        
        # content-type header
        http_request_header['content-type'] = "application/json"

        if(isinstance(http_request_header['authorization'], dict)):
            print(http_request_header['authorization'])
            return JsonResponse(http_request_header['authorization'])
        
        print(f'Authentication Request URL:\n{auth_url}\n')
        print(f'Authentication Request Header:\n{http_request_header}\n')
        print(f'Authentication Request Body:\n{http_request_body}\n')

        response = requests.post(auth_url, headers=http_request_header, data=json.dumps(http_request_body), verify=False)

        if response.status_code == 200 and not response.json()["errors"]:
            result = decrypt_response(response)
            return JsonResponse(result)
        elif response.status_code <= 599 and response.status_code >= 400:
            response = {
                "error_code": response.status_code,
                "error_message": handle_status(response.status_code)
            }
        else:
            response = json.loads(str(response.json()).replace('\'', '"').replace('None', '"None"'))

        return JsonResponse(response)
    except Exception as e:
        print(f'An error has encountered: {e}')
        return JsonResponse({'error': 'An error occured. Please try again.'})