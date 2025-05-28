import requests
import urllib3
from flask import request, jsonify
from flask import current_app as app
import logging
import jwt
from datetime import datetime, timezone

# Disable SSL warnings for internal token verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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

        # Verify the token locally using JWT verification (NO MORE HTTP REQUESTS!)
        try:
            from .key_generator import load_or_generate_keys
            from ..models import VC_Token
            
            # Load the public key for verification
            public_key, _ = load_or_generate_keys()
            
            # Decode and verify the JWT token
            try:
                decoded = jwt.decode(token, public_key, algorithms=["ES256"])
                logger.info(f"✅ Token decoded successfully: {decoded.get('sub', 'unknown')}")
            except jwt.ExpiredSignatureError:
                logger.warning("❌ Token has expired")
                return jsonify({"error": "Token has expired"}), 401
            except jwt.InvalidTokenError as e:
                logger.warning(f"❌ Invalid token: {e}")
                return jsonify({"error": "Invalid token"}), 401

            # Check if the token exists in the database and is still valid
            access_token = VC_Token.query.filter_by(token=token).first()
            if not access_token:
                logger.warning("❌ Token not found in database")
                return jsonify({"error": "Token not found"}), 401

            # Check if the token is expired
            if access_token.expires_at:
                current_time = datetime.now(timezone.utc)
                expires_at = access_token.expires_at
                
                # If expires_at is naive, make it UTC-aware
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                    
                if expires_at < current_time:
                    logger.warning("❌ Token expired in database")
                    return jsonify({"error": "Token has expired"}), 401

            logger.info("✅ Token verification successful - proceeding with request")
            # Token is valid, proceed with the request
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"❌ Token verification failed: {e}")
            return jsonify({"error": "Token verification failed"}), 500

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
    if access_token.expires_at:
        # Ensure both datetimes are timezone-aware for comparison
        current_time = datetime.now(timezone.utc)
        expires_at = access_token.expires_at
        
        # If expires_at is naive, make it UTC-aware
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
            
        if expires_at < current_time:
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
    import time
    start_time = time.time()
    
    try:
        logger.info(f"🎫 [TOKEN-VERIFY] Starting token verification and generation")
        logger.info(f"🎫 [TOKEN-VERIFY] Request data received: {request_json}")
        
        client_id = request_json.get("client_id")
        code = request_json.get("code")
        code_verifier = request_json.get("code_verifier")
        grant_type = request_json.get("grant_type")
        user_pin = request_json.get("user_pin")
        pre_authorized_code = request_json.get("pre-authorized_code")
        
        logger.info(f"🎫 [TOKEN-VERIFY] Parsed parameters:")
        logger.info(f"🎫 [TOKEN-VERIFY] - client_id: {client_id}")
        logger.info(f"🎫 [TOKEN-VERIFY] - grant_type: {grant_type}")
        logger.info(f"🎫 [TOKEN-VERIFY] - code present: {bool(code)}")
        logger.info(f"🎫 [TOKEN-VERIFY] - code_verifier present: {bool(code_verifier)}")
        logger.info(f"🎫 [TOKEN-VERIFY] - user_pin present: {bool(user_pin)}")
        logger.info(f"🎫 [TOKEN-VERIFY] - pre_authorized_code present: {bool(pre_authorized_code)}")

        credential_identifier = None

        if grant_type == "urn:ietf:params:oauth:grant-type:pre-authorized_code":
            logger.info(f"🎫 [TOKEN-VERIFY] Processing pre-authorized code flow")
            logger.info(f"🎫 [TOKEN-VERIFY] Pre-authorized code: {pre_authorized_code}")

            # Check if the user PIN is correct
            if user_pin != "1234":
                logger.error(f"🎫 [TOKEN-VERIFY] ❌ Invalid PIN provided: {user_pin} (expected: 1234)")
                return jsonify({"error": "Invalid pin"}), 400
            
            logger.info(f"🎫 [TOKEN-VERIFY] ✅ PIN validation successful")
            credential_identifier = pre_authorized_code

        elif grant_type == "authorization_code":
            logger.info(f"🎫 [TOKEN-VERIFY] Processing authorization code flow")
            logger.info(f"🎫 [TOKEN-VERIFY] Authorization code: {code}")

            # Compute the code_verifier hash
            code_verifier_hash = base64UrlEncodeSha256(code_verifier)
            logger.info(f"🎫 [TOKEN-VERIFY] Code verifier hash: {code_verifier_hash}")

            # Fetch the authorization code session from the database
            logger.info(f"🎫 [TOKEN-VERIFY] Querying database for client_id: {client_id}")
            authorization_code_entry = VC_AuthorizationCode.query.filter_by(
                client_id=client_id).first()

            if not authorization_code_entry:
                logger.error(f"🎫 [TOKEN-VERIFY] ❌ Authorization code session not found for client_id: {client_id}")
                return jsonify({"error": "Authorization code session not found"}), 400
            
            logger.info(f"🎫 [TOKEN-VERIFY] ✅ Authorization code entry found")
            logger.info(f"🎫 [TOKEN-VERIFY] Expected auth code: {authorization_code_entry.auth_code}")
            logger.info(f"🎫 [TOKEN-VERIFY] Expected code challenge: {authorization_code_entry.code_challenge}")

            # Validate the code and code_verifier
            if code != authorization_code_entry.auth_code or code_verifier_hash != authorization_code_entry.code_challenge:
                if code != authorization_code_entry.auth_code:
                    logger.error(f"🎫 [TOKEN-VERIFY] ❌ Invalid authorization code: {code} != {authorization_code_entry.auth_code}")
                if code_verifier_hash != authorization_code_entry.code_challenge:
                    logger.error(f"🎫 [TOKEN-VERIFY] ❌ Invalid code verifier: {code_verifier_hash} != {authorization_code_entry.code_challenge}")
                return jsonify({"error": "Client could not be verified"}), 400
            
            logger.info(f"🎫 [TOKEN-VERIFY] ✅ Authorization code and verifier validation successful")
            credential_identifier = authorization_code_entry.issuer_state
        else:
            logger.error(f"🎫 [TOKEN-VERIFY] ❌ Unknown grant type: {grant_type}")

        if credential_identifier is None:
            logger.error(f"🎫 [TOKEN-VERIFY] ❌ Could not determine credential identifier")
            logger.error(f"🎫 [TOKEN-VERIFY] Grant type: {grant_type}, Authorization entry: {authorization_code_entry if 'authorization_code_entry' in locals() else 'None'}")
            return jsonify({"error": "Invalid grant type or parameters"}), 400
        
        logger.info(f"🎫 [TOKEN-VERIFY] ✅ Credential identifier resolved: {credential_identifier}")

        # Generate the access token
        logger.info(f"🎫 [TOKEN-VERIFY] Generating access token...")
        access_token = generate_access_token(client_id, credential_identifier, private_key)
        
        if not access_token:
            logger.error(f"🎫 [TOKEN-VERIFY] ❌ Failed to generate access token")
            return jsonify({"error": "Failed to generate access token"}), 500
        
        logger.info(f"🎫 [TOKEN-VERIFY] ✅ Access token generated successfully")
        logger.info(f"🎫 [TOKEN-VERIFY] Token preview: {access_token[:30]}...")

        # Store the access token
        logger.info(f"🎫 [TOKEN-VERIFY] Storing access token in database...")
        new_token = VC_Token()
        new_token.token = access_token
        db.session.add(new_token)
        db.session.commit()
        logger.info(f"🎫 [TOKEN-VERIFY] ✅ Access token stored in database")

        # Generate nonce
        c_nonce = generate_nonce(16)
        logger.info(f"🎫 [TOKEN-VERIFY] Generated c_nonce: {c_nonce}")

        duration_ms = int((time.time() - start_time) * 1000)
        logger.info(f"🎫 [TOKEN-VERIFY] ✅ Token generation completed successfully (duration: {duration_ms}ms)")

        # Respond with the access token and additional information
        response = {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 86400,
            "c_nonce": c_nonce,
            "c_nonce_expires_in": 86400,
        }
        
        logger.info(f"🎫 [TOKEN-VERIFY] Final response structure: {list(response.keys())}")
        return jsonify(response)
        
    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.error(f"🎫 [TOKEN-VERIFY] ❌ Token generation failed (duration: {duration_ms}ms)")
        logger.error(f"🎫 [TOKEN-VERIFY] Error details: {type(e).__name__}: {str(e)}", exc_info=True)
        
        return jsonify({"error": "Internal server error in token generation"}), 500
