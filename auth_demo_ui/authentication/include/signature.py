from authlib.jose import JsonWebSignature
from django.conf import settings
from .utils import get_environment

base_path = settings.BASE_DIR

env = get_environment()

individual_id_type = {
    'PCN': 'VID',
    'AlyasPSN': 'VID',
}

def create_signature(request, key_location):
    partner_id = env('PARTNER_ID')
    partner_private_key = open(key_location).read()
    signed_certificate = open(f'{base_path}/authentication/keys/{partner_id}/{partner_id}-signedcertificate.cer').read()
    signed_certificate = signed_certificate.replace("\n", "").replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")

    jws = JsonWebSignature()
    jwt = jws.serialize_compact({'x5c': [f'{signed_certificate}'],'alg': 'RS256'}, request, partner_private_key).decode()
    jwt = jwt.split(".")
    jwt = f"{jwt[0]}..{jwt[2]}"

    return jwt