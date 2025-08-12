from Crypto.Cipher import AES

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import secrets, json

def symmetric_encrypt(message, key):
    nonce = secrets.token_bytes(16)
    
    message = message.encode('utf-8')
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    
    return ciphertext + tag + nonce
    
def symmetric_decrypt(encrypted_data, key):    
    block_size = 16
    tag_size = 16

    nonce = encrypted_data[-block_size:]
    tag = encrypted_data[:-block_size][-block_size:]
    encrypted_kyc_data = encrypted_data[:-(block_size + tag_size)]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(encrypted_kyc_data, tag)
        
    response_map = json.loads(decrypted_data)
    
    return response_map

def asymmetric_encrypt(data: bytes, public_key_pem: bytes) -> bytes:
    certificate = x509.load_pem_x509_certificate(public_key_pem, default_backend())
    public_key = certificate.public_key()

    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_data

def asymmetric_decrypt(encrypted_data: bytes, private_key_pem: bytes) -> bytes:
    private_key = load_pem_private_key(
        private_key_pem,
        password=None,
    )
    
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted_data