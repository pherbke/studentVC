from flask import Flask, request, redirect, jsonify
import jwt
import random
import string
from .offer import generate_nonce
from ..models import VC_AuthorizationCode
from .. import db
import logging

logger = logging.getLogger(__name__)


def resolve_direct_post(state, id_jwt):
    # Extract the authorization code from the ID token
    if id_jwt:
        try:
            decoded_id_token = jwt.decode(
                id_jwt, options={"verify_signature": False})
            iss = decoded_id_token.get("iss")
            holder_public_key = did_to_key(iss)
            decoded_id_token = jwt.decode(
                id_jwt, holder_public_key, algorithms=["ES256"], verify=True)

            if not iss:
                return jsonify({"error": "Issuer (iss) not found in id_token"}), 400

            # Generate a new authorization code
            authorization_code = generate_nonce(8)

            # Retrieve the entry from the database or create a new one
            authorization_code_entry = VC_AuthorizationCode.query.filter_by(
                client_id=iss).first()

            if authorization_code_entry:
                logger.info(
                    f"Entry found for client_id, updating the authorization code to {authorization_code}")
                # If an entry exists, update the authorization code
                authorization_code_entry.auth_code = authorization_code
                db.session.commit()  # Commit the changes to the database
            else:
                logger.info("No entry found for client_id, creating a new one")
                # If no entry exists, create a new one
                new_entry = VC_AuthorizationCode(
                    client_id=iss,
                    auth_code=authorization_code,
                    code_challenge=request.json.get("code_challenge"),
                    issuer_state=request.json.get("issuer_state")
                )
                db.session.add(new_entry)
                db.session.commit()  # Commit the new entry to the database

            # Construct the redirect URL
            redirect_url = f"openid://redirect?code={authorization_code}&state={state}"
            print(f"Redirect URL: {redirect_url}")

            # Redirect the user with the new authorization code
            return redirect(redirect_url, code=302)

        except jwt.DecodeError as e:
            print("Error decoding JWT")
            logger.error(f"Error decoding JWT {e}")
            return jsonify({"error": "Invalid JWT"}), 422

    else:
        print("Error: id_token is missing")
        return jsonify({"error": "id_token is required"}), 422


def did_to_key(did):
    """
    Converts a DID:key into a usable PEM-encoded public key for JWT decoding.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import base58
    # Remove the DID prefix
    if not did.startswith('did:key:z'):
        raise ValueError("Invalid DID format")
    base58_key = did[9:]  # Strip "did:key:z"

    # Decode the base58-encoded key
    try:
        multicodec_key = base58.b58decode(base58_key)
    except:
        raise ValueError("Public Key is not base58 encoded")

    # Verify and strip the multicodec prefix (P-256 -> 0x1200)
    if multicodec_key[:2] != b'\x12\x00':
        raise ValueError("Unsupported key type")
    raw_key_material = multicodec_key[2:]

    # Reconstruct the public key
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),  # P-256 curve
            raw_key_material
        )
    except:
        raise ValueError("Invalid public key material")

    # Serialize the public key to PEM format
    pem_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_key
