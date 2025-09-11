from datetime import datetime, timezone
from django.conf import settings

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from decouple import Config, RepositoryEnv

from authentication.include.base64 import base64_url_decode
from authentication.include.crypto import symmetric_decrypt, asymmetric_decrypt

import os, hashlib, binascii

base_path = settings.BASE_DIR

def get_environment():
    ENV = os.getenv("DJANGO_ENV")
    ENV_FILE = base_path / (f".env.{ENV}" if ENV else ".env")

    if not ENV_FILE.exists():
        raise FileNotFoundError(f"❌ {ENV_FILE} not found")

    return Config(RepositoryEnv(str(ENV_FILE)))

def print_hex_binary(data):
    data = data.encode("utf-8")
    hasher = hashlib.sha256()
    hasher.update(data)
    hasher = hasher.digest()
    
    return binascii.hexlify(hasher).upper().decode('ascii')

def get_current_time():
    t = datetime.now(timezone.utc)
    t = t.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    return t

def get_thumbprint(fname):
    with open(fname, "rb") as cert_file:
        cert_data = cert_file.read()
        
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    thumbprint = cert.fingerprint(hashes.SHA256())
    
    return thumbprint.hex()

def decrypt_response(response):
    result = {}
    env = get_environment()
    
    partner_id = env('PARTNER_ID')
    
    partner_private_key = open(f'{base_path}/authentication/keys/{partner_id}/{partner_id}-partner-private-key.pem').read()
    partner_private_key_bytes = bytes(partner_private_key, "utf-8")
    
    response_session_key_encrypted = base64_url_decode(response.json()["responseSessionKey"])
    response_encrypted = base64_url_decode(response.json()["response"])
    
    result["response_session_key"] = asymmetric_decrypt(response_session_key_encrypted, partner_private_key_bytes)
    
    result["response"] = symmetric_decrypt(response_encrypted, result["response_session_key"])
    
    return result["response"]