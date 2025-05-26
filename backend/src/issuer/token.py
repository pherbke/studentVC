import requests
from flask import request, jsonify
from flask import current_app as app
import logging
import jwt
from datetime import datetime
from ..models import VC_Token
import hashlib
import base64
import random
import string
from ..models import VC_AuthorizationCode
from cryptography.hazmat.primitives import serialization
from .offer import generate_nonce
from .. import db
import time

logger = logging.getLogger(__name__)


def authenticate_token(f):
    def wrapper(*args, **kwargs):
        # Extract the Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Unauthorized"}), 401

        # Extract the token from the header
        token = auth_header.split(" ")[1] if " " in auth_header else None
        if not token:
            return jsonify({"error": "Token not provided"}), 401

        # Verify the token with the external server
        try:
            server_url = app.config["SERVER_URL"]
            response = requests.post(
                f"{server_url}/verifyAccessToken",
                json={"token": token},
                headers={"Content-Type": "application/json"},
                timeout=10  # Add a reasonable timeout
            )
            if response.status_code != 200:
                return jsonify({"error": response.text}), 401

            # Log the response from the verification server
            result = response.text
            logger.info(f"Token verification response: {result}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error verifying token: {e}")
            return jsonify({"error": "Token verification failed"}), 500

        # Proceed to the next function if the token is valid
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def verify_token(data, publicKey):
    token = data.get("token")
    if not token:
        return jsonify({"error": "Token is required"}), 400

    # Decode the token using the public key and check expiration

    logger.info(f"Verifying token: {token} with public key: {publicKey}")
    try:
        decoded = jwt.decode(token, publicKey, algorithms=["ES256"])
    except jwt.ExpiredSignatureError as e:
        return jsonify({"error": f"Token has expired {e}"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Invalid token {e}"}), 401

    # Query the database for the access token
    access_token = VC_Token.query.filter_by(token=token).first()

    if not access_token:
        return jsonify({"error": "Token not found"}), 401

    # Check if the token is expired
    if access_token.expires_at and access_token.expires_at < datetime.utcnow():
        return jsonify({"error": "Token has expired"}), 401

    # If token is valid and not expired
    return jsonify({"message": "Token is valid"}), 200


def base64UrlEncodeSha256(input_str):
    # Hash the code_verifier and return it in base64url format
    sha256_hash = hashlib.sha256(input_str.encode()).digest()
    return base64.urlsafe_b64encode(sha256_hash).decode().strip("=")


def generate_access_token(client_id, credential_identifier, private_key):
    """
    Generate a JWT access token.
    """
    # Define the payload
    payload = {
        "client_id": client_id,
        "credential_identifier": credential_identifier,
        "iat": int(time.time()),  # Issued at
        "exp": int(time.time()) + 3600,  # Expiration (1 hour)
        "sub": client_id  # TODO: what are you?? should probably internal ID?
    }

    # Define the header
    headers = {
        "alg": "ES256",  # Elliptic curve signing algorithm
        "typ": "JWT"     # Token type
    }

    # Generate the JWT token
    access_token = jwt.encode(payload, private_key,
                              algorithm="ES256", headers=headers)
    return access_token


def verify_and_generate_token(request_json, private_key):
    client_id = request_json.get("client_id")
    code = request_json.get("code")
    code_verifier = request_json.get("code_verifier")
    grant_type = request_json.get("grant_type")
    user_pin = request_json.get("user_pin")
    pre_authorized_code = request_json.get("pre-authorized_code")

    credential_identifier = None

    if grant_type == "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        logger.info(f"Pre-authorized code flow: {pre_authorized_code}")

        # Check if the user PIN is correct
        if user_pin != "1234":
            print("Invalid pin:", user_pin)
            logger.error(f"Invalid pin: {user_pin}")
            return jsonify({"error": "Invalid pin"}), 400

        credential_identifier = pre_authorized_code

    elif grant_type == "authorization_code":
        logger.info(f"Authorization code flow: {code}")

        # Compute the code_verifier hash
        code_verifier_hash = base64UrlEncodeSha256(code_verifier)

        # Fetch the authorization code session from the database
        authorization_code_entry = VC_AuthorizationCode.query.filter_by(
            client_id=client_id).first()

        if not authorization_code_entry:
            return jsonify({"error": "Authorization code session not found"}), 400

        # Validate the code and code_verifier
        if code != authorization_code_entry.auth_code or code_verifier_hash != authorization_code_entry.code_challenge:
            if code != authorization_code_entry.auth_code:
                logger.info(
                    f"Invalid authorization code: {code} != {authorization_code_entry.auth_code}")
            if code_verifier_hash != authorization_code_entry.code_challenge:
                logger.info(
                    f"Invalid code verifier: {code_verifier_hash} != {authorization_code_entry.code_challenge}")
            return jsonify({"error": "Client could not be verified"}), 400

        credential_identifier = authorization_code_entry.issuer_state

    if credential_identifier is None:
        logger.error(
            f"Invalid grant type or parameters {authorization_code_entry}")
        return jsonify({"error": "Invalid grant type or parameters"}), 400

    # Generate the access token
    access_token = generate_access_token(
        client_id, credential_identifier, private_key)

    # Store the access token
    new_token = VC_Token()
    new_token.token = access_token
    db.session.add(new_token)
    db.session.commit()

    print("Generated access token:", access_token)

    # Respond with the access token and additional information
    return jsonify({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 86400,
        "c_nonce": generate_nonce(16),
        "c_nonce_expires_in": 86400,
    })
