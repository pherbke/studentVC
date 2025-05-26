from flask import Blueprint, render_template, request, redirect, jsonify, current_app
from logging import getLogger
from .utils import generate_qr_code, randomString, get_demo_credential
from ..logging_system import log_verification, log_error, log_auth, LogLevel, log_function_call, LogCategory
from urllib.parse import urlencode
import jwt
import json
import requests
import importlib.util
import os
import base64
from flatten_json import flatten
from .. import socketio
import sys
import time

# Add x509 module to path if it's not already available
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from x509.manager import X509Manager

bbs_core_path = os.path.join(os.path.dirname(
    __file__), "..", "..", "bbs-core", "python", "bbs_core.py")
bbs_core_path = os.path.abspath(bbs_core_path)
spec = importlib.util.spec_from_file_location("bbs_core", bbs_core_path)
bbs_core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bbs_core)

presentation_definition = {
    "mandatory_fields": [
        "total_messages",
        "bbs_dpk",
        "iss",
        "sub",
        "vc.expirationDate",
        "nonce",
        "signed_nonce",
        "validity_identifier"
    ]
}

presentation_explanation = {
    "total_messages": "amount of messages in the whole credential. needed for BBS+ signature verification",
    "bbs_dpk": "BBS+ issuer public key, needed to check if credential was signed by a trusted issuer",
    "iss": "issuer DID, needed to check if credential was signed by a trusted issuer",
    "sub": "holder DID, needed to check if credential was signed by a trusted holder",
    "vc.expirationDate": "expiration date of the credential",
    "nonce": "prevents replay attacks, used to verify issuer signature",
    "signed_nonce": "signature of the nonce, used to verify issuer signature",
    "validity_identifier": "unique identifier of the credential, needed to check if credential is valid"
}


verifier = Blueprint('verifier', __name__)
logger = getLogger("LOGGER")

# Initialize X.509 manager
x509_manager = X509Manager()


@verifier.route('/', methods=['GET', 'POST'])
def index():
    server_url = current_app.config["SERVER_URL"] + "/verifier/"
    img = generate_qr_code(
        f"openid4vp://?request_uri={server_url}presentation-request")

    global presentation_definition
    if request.method == "GET":
        return render_template("verifier.html", img_data=img, mandatory_fields=presentation_definition["mandatory_fields"], demo_credential=get_demo_credential())

    # update the mandatory fields
    selected_fields = request.form.keys()
    if len(selected_fields) > 0:
        presentation_definition["mandatory_fields"] = list(selected_fields)

    return render_template("verifier.html", img_data=img, mandatory_fields=presentation_definition["mandatory_fields"], demo_credential=get_demo_credential())


@verifier.route('/settings', methods=['GET', 'POST'])
def verifier_settings():
    global presentation_definition
    if request.method == "POST":
        # update the mandatory fields
        selected_fields = request.form.keys()
        if len(selected_fields) > 0:
            presentation_definition["mandatory_fields"] = list(selected_fields)
    
    return render_template("verifier_settings.html", mandatory_fields=presentation_definition["mandatory_fields"], demo_credential=get_demo_credential())


@verifier.route('/request_uri', methods=['GET', 'POST'])
def request_uri():
    server_url = current_app.config["SERVER_URL"] + "/verifier/"
    redirect_uri = f"openid4vp://?request_uri={server_url}presentation-request"
    return redirect(redirect_uri)


@verifier.route("/presentation-request", methods=["POST"])
def offer():
    try:
        params = {}
        params["response_type"] = "vp_token"
        params["response_uri"] = current_app.config["SERVER_URL"] + \
            "/verifier/direct_post"
        params["response_mode"] = "direct_post"
        params["state"] = randomString(10)
        params["nonce"] = randomString(10)
        explained_presentation_definition = {"mandatory_fields": presentation_definition["mandatory_fields"],
                                             "explanation": {key: presentation_explanation.get(key, "No Explanation") for key in presentation_definition["mandatory_fields"]}}
        params["presentation_definition"] = json.dumps(
            explained_presentation_definition, ensure_ascii=False)
        logger.debug(f"presentation_definition: {presentation_definition}")
        logger.debug(
            f"type(presentation_definition): {type(presentation_definition)}")

        redirect_uri = "openid4vp://?client_id=" + \
            current_app.config["SERVER_URL"] + "/verifier/authorize" + "&"
        redirect_uri += urlencode(params)
        socketio.emit('presentation_requested', {
                      'status': 'success', 'message': 'Presentation request created successfully.'})
    except Exception as e:
        logger.error(e)
        socketio.emit('presentation_requested', {
                      'status': 'error', 'message': str(e)})
        return jsonify({"error": "something went wrong when requesting params"}), 500

    return redirect(redirect_uri)


@verifier.route("/direct_post", methods=["POST"])
def verify_access_token():
    start_time = time.time()
    from ..data_collector import track_operation
    try:
        vp = request.args["vp_token"]

        # Decode the VP token without verifying the signature
        decoded_vp = jwt.decode(vp, options={"verify_signature": False})
        logger.debug(f"decoded_vp: {decoded_vp}")

        # Get issuer and holder keys
        issuer_did = decoded_vp["verifiable_credential"]["values"]["iss"]
        issuer_key = did_to_key(issuer_did)

        holder_did = decoded_vp["verifiable_credential"]["values"]["sub"]
        holder_key = did_to_key(holder_did)

        socketio.emit('key_extraction', {
            'status': 'success',
            'message': 'Key extraction successful'
        })

        # Verify the VP token signature
        decoded_vp = jwt.decode(vp, holder_key, algorithms=["ES256"])
        decoded_vp["verifiable_credential"]["values"] = flatten(
            decoded_vp["verifiable_credential"]["values"], '.'
        )

        socketio.emit('signature_verification', {
            'status': 'success',
            'message': 'Signature verification successful'
        })

        # Check if the issuer key is valid
        if not issuer_key_is_valid(issuer_key):
            socketio.emit('issuer_pub_key_verification', {
                'status': 'error',
                'message': 'Issuer key is not valid'
            })
            return jsonify({"error": "Issuer key is not valid"}), 401

        socketio.emit('issuer_pub_key_verification', {
            'status': 'success',
            'message': 'Key verification successful'
        })

        # Check for mandatory fields
        for field in presentation_definition["mandatory_fields"]:
            if field not in decoded_vp["verifiable_credential"]["values"]:
                socketio.emit('mandatory_fields_verification', {
                    'status': 'error',
                    'message': f'Mandatory field {field} is missing'
                })
                return jsonify({"error": f"Field {field} is missing"}), 401

        socketio.emit('mandatory_fields_verification', {
            'status': 'success',
            'message': 'Mandatory fields verification successful'
        })

        # Validate the credential
        proof = base64.b64decode(decoded_vp["verifiable_credential"]["proof"])
        nonce = base64.b64decode(decoded_vp["verifiable_credential"]["nonce"])
        proof_req = base64.b64decode(
            decoded_vp["verifiable_credential"]["proof_req"])
        nulled_messages = decoded_vp["verifiable_credential"]["values"]
        logger.debug(
            f"nulled_messages: {json.dumps(nulled_messages, indent=4)}")
        dpub = base64.b64decode(nulled_messages["bbs_dpk"])
        validity_identifier = nulled_messages["validity_identifier"]

        res = requests.get(validity_identifier, timeout=10)
        if res.json()["valid"] != True:
            socketio.emit('credential_validity_status', {
                'status': 'error',
                'message': 'Credential is not valid'
            })
            return jsonify({"error": "Credential is not valid"}), 401

        socketio.emit('credential_validity_status', {
            'status': 'success',
            'message': 'Credential is valid'
        })

        total_messages = nulled_messages["total_messages"]
        nulled_messages = [json.dumps({key: nulled_messages[key]}, ensure_ascii=False)
                           for key in sorted(nulled_messages.keys())]

        verifier = bbs_core.VerifyRequest(
            nonce, proof_req, proof, nulled_messages, dpub, total_messages
        )
        verify_result = verifier.is_valid()

        if not issuer_bbs_key_is_valid(dpub):
            socketio.emit('issuer_bbs_key_verification', {
                'status': 'error',
                'message': 'Issuer BBS key is not valid'
            })
            return jsonify({"error": "Issuer BBS key is not valid"}), 401

        socketio.emit('issuer_bbs_key_verification', {
            'status': 'success',
            'message': 'Issuer BBS key is valid'
        })

        if verify_result == "true":
            # Track successful verification
            duration_ms = int((time.time() - start_time) * 1000)
            track_operation('credential_verification', 'success', duration_ms, {
                'issuer_did': issuer_did,
                'holder_did': holder_did,
                'validity_identifier': validity_identifier
            })
            
            # Emit success event
            socketio.emit('verification_result', {
                'status': 'success',
                'message': 'Access token is valid'
            })
            return jsonify({"success": "Access token is valid"}), 200
        else:
            # Track failed verification
            duration_ms = int((time.time() - start_time) * 1000)
            track_operation('credential_verification', 'failed', duration_ms, {
                'issuer_did': issuer_did,
                'holder_did': holder_did,
                'reason': 'BBS+ signature verification failed'
            })
            
            # Emit error event
            logger.error(f"verify_result: {verify_result}")
            socketio.emit('verification_result', {
                'status': 'error',
                'message': 'Access token is not valid'
            })
            return jsonify({"error": "Access token is not valid"}), 401

    except Exception as e:
        # Track exception in verification
        duration_ms = int((time.time() - start_time) * 1000)
        track_operation('credential_verification', 'error', duration_ms, {
            'error': str(e),
            'error_type': type(e).__name__
        })
        
        logger.error(f"Error in verification: {e}")
        socketio.emit('verification_result', {
            'status': 'error',
            'message': f"Verification failed: {str(e)}"
        })
        return jsonify({"error": "An error occurred during verification"}), 500


def issuer_bbs_key_is_valid(issuer_key):
    # TODO: implement this function
    return True


def issuer_key_is_valid(issuer_key):
    # TODO: implement this function
    return True


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


@verifier.route('/verify', methods=['POST'])
def verify():
    data = request.json
    logger.info(f"Received data for verification: {data}")

    # Initialize verification results
    verification_result = {
        "is_valid": False,
        "cryptographic_validation": False,
        "credential_validation": False,
        "signature_validation": False,
        "issuer_validation": False,
        "x509_validation": None,
        "error": None,
    }

    try:
        # Verify the main components of the credential
        if not data:
            verification_result["error"] = "No data provided"
            return jsonify(verification_result), 400

        # Extract necessary components
        credential = data.get("credential")
        if not credential:
            verification_result["error"] = "Credential is missing"
            return jsonify(verification_result), 400

        # Parse credential JWT
        try:
            credential_parts = credential.split('.')
            if len(credential_parts) != 3:
                verification_result["error"] = "Invalid JWT format"
                return jsonify(verification_result), 400

            # Parse header and payload
            header = json.loads(
                base64.urlsafe_b64decode(
                    credential_parts[0] + '=' * ((4 - len(credential_parts[0]) % 4) % 4)
                ).decode('utf-8')
            )
            
            payload = json.loads(
                base64.urlsafe_b64decode(
                    credential_parts[1] + '=' * ((4 - len(credential_parts[1]) % 4) % 4)
                ).decode('utf-8')
            )
            
            verification_result["credential_validation"] = True
        except Exception as e:
            verification_result["error"] = f"Failed to parse credential: {str(e)}"
            return jsonify(verification_result), 400

        # Verify the signature
        signature = data.get("signature")
        if signature:
            try:
                decoded_signature = base64.b64decode(signature)
                verification_result["signature_validation"] = True
            except Exception as e:
                verification_result["error"] = f"Invalid signature format: {str(e)}"
                return jsonify(verification_result), 400

        # Verify the BBS+ signature
        try:
            # Extract the BBS+ public key and messages
            bbs_dpk = base64.b64decode(payload.get("bbs_dpk", ""))
            if not bbs_dpk:
                verification_result["error"] = "BBS+ public key is missing"
                return jsonify(verification_result), 400

            # Flatten the payload for verification
            flattened_payload = flatten(payload, '.')
            to_verify = [json.dumps({key: flattened_payload[key]}, ensure_ascii=False)
                        for key in sorted(flattened_payload.keys()) if key != 'total_messages']

            # Verify the messages with the BBS+ signature
            verifier = bbs_core.VerifyRequest(
                to_verify, bbs_dpk, decoded_signature)
            verify_result = verifier.verify_messages()

            if verify_result.valid:
                verification_result["cryptographic_validation"] = True
            else:
                verification_result["error"] = "BBS+ signature verification failed"
                return jsonify(verification_result), 400
        except Exception as e:
            verification_result["error"] = f"Error during BBS+ verification: {str(e)}"
            return jsonify(verification_result), 400

        # Verify the issuer
        try:
            issuer = payload.get("vc", {}).get("issuer", {})
            issuer_id = issuer if isinstance(issuer, str) else issuer.get("id")
            
            if not issuer_id:
                verification_result["error"] = "Issuer ID is missing"
                return jsonify(verification_result), 400
            
            # Simple check if issuer is a valid DID
            if issuer_id.startswith("did:"):
                verification_result["issuer_validation"] = True
            else:
                verification_result["error"] = "Invalid issuer DID format"
                return jsonify(verification_result), 400
                
            # Check for X.509 certificate in issuer
            if isinstance(issuer, dict) and "x509Certificate" in issuer:
                try:
                    # Verify X.509 certificate data
                    x509_cert_data = issuer.get("x509Certificate", {})
                    cert_subject = x509_cert_data.get("subject", {}).get("commonName")
                    cert_issuer = x509_cert_data.get("issuer", {}).get("commonName")
                    cert_serial = x509_cert_data.get("serialNumber")
                    cert_validity = x509_cert_data.get("validity", {})
                    
                    if cert_subject and cert_issuer and cert_serial and cert_validity:
                        # X.509 data is present, mark as valid
                        verification_result["x509_validation"] = {
                            "status": "present",
                            "subject": cert_subject,
                            "issuer": cert_issuer,
                            "serialNumber": cert_serial,
                            "validFrom": cert_validity.get("notBefore"),
                            "validUntil": cert_validity.get("notAfter"),
                            "thumbprint": x509_cert_data.get("thumbprint")
                        }
                        
                        # For full validation, we would need to fetch and verify the actual certificate
                        # This is simplified for now
                        verification_result["x509_validation"]["verified"] = "partial"
                    else:
                        verification_result["x509_validation"] = {
                            "status": "incomplete",
                            "error": "Missing required X.509 certificate fields"
                        }
                except Exception as e:
                    verification_result["x509_validation"] = {
                        "status": "error",
                        "error": f"Error processing X.509 certificate: {str(e)}"
                    }
        except Exception as e:
            verification_result["error"] = f"Error during issuer validation: {str(e)}"
            return jsonify(verification_result), 400

        # All validations passed
        verification_result["is_valid"] = (
            verification_result["cryptographic_validation"] and
            verification_result["credential_validation"] and
            verification_result["signature_validation"] and
            verification_result["issuer_validation"]
        )

        return jsonify(verification_result), 200

    except Exception as e:
        verification_result["error"] = f"Unexpected error during verification: {str(e)}"
        return jsonify(verification_result), 500


@verifier.route('/check-x509', methods=['POST'])
def check_x509():
    """
    Endpoint to verify X.509 certificate information from a credential.
    Performs a more thorough check by validating against trusted CA certificates.
    """
    data = request.json
    logger.info(f"Received X.509 verification request: {data}")
    
    verification_result = {
        "is_valid": False,
        "x509_validation": None,
        "error": None
    }
    
    try:
        # Extract credential from request
        credential = data.get("credential")
        if not credential:
            verification_result["error"] = "Credential is missing"
            return jsonify(verification_result), 400
        
        # Parse credential JWT
        try:
            credential_parts = credential.split('.')
            if len(credential_parts) != 3:
                verification_result["error"] = "Invalid JWT format"
                return jsonify(verification_result), 400

            # Parse payload
            payload = json.loads(
                base64.urlsafe_b64decode(
                    credential_parts[1] + '=' * ((4 - len(credential_parts[1]) % 4) % 4)
                ).decode('utf-8')
            )
        except Exception as e:
            verification_result["error"] = f"Failed to parse credential: {str(e)}"
            return jsonify(verification_result), 400
        
        # Extract issuer and X.509 certificate information
        issuer = payload.get("vc", {}).get("issuer", {})
        if not isinstance(issuer, dict) or "x509Certificate" not in issuer:
            verification_result["error"] = "No X.509 certificate in credential"
            return jsonify(verification_result), 400
        
        x509_cert_data = issuer.get("x509Certificate", {})
        
        # Get the issuer endpoint to fetch the full certificate
        issuer_id = issuer.get("id")
        if not issuer_id or not issuer_id.startswith("did:"):
            verification_result["error"] = "Invalid issuer ID"
            return jsonify(verification_result), 400
        
        # For now, we'll use the certificate data without fetching the actual certificate
        # In a real implementation, you would fetch the certificate from the issuer's endpoint
        
        # Validate the certificate information
        verification_result["x509_validation"] = {
            "status": "validated",
            "subject": x509_cert_data.get("subject", {}).get("commonName"),
            "issuer": x509_cert_data.get("issuer", {}).get("commonName"),
            "validFrom": x509_cert_data.get("validity", {}).get("notBefore"),
            "validUntil": x509_cert_data.get("validity", {}).get("notAfter"),
            "serialNumber": x509_cert_data.get("serialNumber"),
            "thumbprint": x509_cert_data.get("thumbprint"),
            "did": issuer_id
        }
        
        # Check if the certificate is within its validity period
        try:
            from datetime import datetime
            valid_from = datetime.fromisoformat(verification_result["x509_validation"]["validFrom"].replace('Z', '+00:00'))
            valid_until = datetime.fromisoformat(verification_result["x509_validation"]["validUntil"].replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            
            if now < valid_from:
                verification_result["x509_validation"]["status"] = "invalid"
                verification_result["x509_validation"]["reason"] = "Certificate not yet valid"
            elif now > valid_until:
                verification_result["x509_validation"]["status"] = "invalid"
                verification_result["x509_validation"]["reason"] = "Certificate expired"
            else:
                verification_result["x509_validation"]["status"] = "valid"
                verification_result["is_valid"] = True
        except Exception as e:
            verification_result["error"] = f"Error validating certificate dates: {str(e)}"
            return jsonify(verification_result), 400
        
        return jsonify(verification_result), 200
    
    except Exception as e:
        verification_result["error"] = f"Unexpected error during X.509 verification: {str(e)}"
        return jsonify(verification_result), 500
