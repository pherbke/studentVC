import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from flask import jsonify


def pem_to_jwk(pem_key, key_type="public"):
    # Load PEM key from string
    if isinstance(pem_key, str):
        pem_key = serialization.load_pem_public_key(
            pem_key.encode(), default_backend())
    public_key = pem_key

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        # Extract EC public key components (x, y)
        numbers = public_key.public_numbers()
        jwk = {
            "kty": "EC",
            "crv": "P-256",  # Assuming prime256v1 curve
            "x": numbers.x,
            "y": numbers.y,
            "alg": "ES256",
            "use": key_type,
        }
        return jwk
    else:
        raise ValueError("Unsupported key type")
