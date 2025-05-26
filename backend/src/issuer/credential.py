from flask import request, jsonify, current_app
import jwt
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from ..models import VC_Offer, VC_validity
from .offer import generate_nonce
import logging
from flask import current_app as app
from ..logging_system import log_issuance, log_error, LogLevel, log_function_call, LogCategory
from flatten_json import flatten
import json
import os
import importlib.util
import base64
from .utils import get_placeholders
from ..models import VC_validity
from .. import db
import sys
import time

# Add x509 module to path if it's not already available
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from x509.manager import X509Manager
from ..validate.status_list import generate_credential_status

logo, profile = get_placeholders()

bbs_core_path = os.path.join(os.path.dirname(
    __file__), "..", "..", "bbs-core", "python", "bbs_core.py")
bbs_core_path = os.path.abspath(bbs_core_path)
spec = importlib.util.spec_from_file_location("bbs_core", bbs_core_path)
bbs_core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bbs_core)

logger = logging.getLogger(__name__)


@log_function_call(LogCategory.ISSUANCE, include_args=False)
def generate_credential(auth_header, public_key, private_key, issuer_did, issuer_kid, bbs_dpk, bbs_secret, issuer_cert=None):
    start_time = time.time()
    from ..data_collector import track_operation
    try:
        if not auth_header:
            log_error("Missing authorization header in credential generation", 
                     level=LogLevel.WARNING, 
                     operation="generate_credential")
            return jsonify({"error": "Authorization header is missing"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = jwt.decode(token, public_key, algorithms=["ES256"])
        credential_identifier = decoded_token.get("credential_identifier")

        if not credential_identifier:
            log_error("Missing credential identifier in token", 
                     level=LogLevel.WARNING, 
                     operation="generate_credential",
                     token_decoded=True)
            return jsonify({"error": "Credential identifier is missing"}), 400
    except jwt.DecodeError as e:
        log_error("JWT token decode error in credential generation", 
                 error=e,
                 level=LogLevel.ERROR, 
                 operation="generate_credential")
        return jsonify({"error": "Invalid JWT token"}), 401
    except Exception as e:
        log_error("Unexpected error in credential generation authentication", 
                 error=e,
                 level=LogLevel.ERROR, 
                 operation="generate_credential")
        return jsonify({"error": "Authentication failed"}), 500

    try:
        logger.debug(f"offer_uuid: {credential_identifier}")
        log_issuance("Starting credential generation", 
                    level=LogLevel.INFO,
                    credential_identifier=credential_identifier,
                    operation="generate_credential")
        
        credential_data = VC_Offer.query.filter_by(
            uuid=credential_identifier).first()
        credential_subject = get_credential_data(credential_data)
        # Create the Verifiable Credential payload
        uniqID = f"urn:uuid:{str(uuid4())}"
        log_issuance("Creating credential payload", 
                    level=LogLevel.INFO,
                    credential_identifier=credential_identifier,
                    credential_id=uniqID,
                    operation="payload_creation")
        
        payload = get_payload(issuer_did, decoded_token,
                              credential_subject, uniqID, issuer_cert)

        nonce = generate_nonce(20)
        payload["nonce"] = nonce
        payload["signed_nonce"] = jwt.encode(
            {"nonce": nonce}, private_key, algorithm="ES256")
        payload["bbs_dpk"] = base64.b64encode(bbs_dpk).decode('utf-8')
        
        # Generate a unique identifier for credential status
        unique_id = generate_nonce(50)
        
        # Generate credential status
        credential_status = generate_credential_status(unique_id)
        log_issuance("Generated credential status", 
                    level=LogLevel.INFO,
                    credential_identifier=credential_identifier,
                    credential_id=uniqID,
                    status_id=unique_id,
                    operation="status_generation")
        
        # Add credential status to the payload if not already present
        if "credentialStatus" not in payload["vc"]:
            payload["vc"]["credentialStatus"] = credential_status
        
        # Add the credential status URL
        payload["validity_identifier"] = credential_status["id"]
        
        logger.debug(f"Payload: {payload}")

        flattened_payload = flatten(payload, '.')
        flattened_payload["total_messages"] = len(flattened_payload.keys()) + 1
        payload["total_messages"] = len(flattened_payload.keys())
        to_sign = [json.dumps({key: flattened_payload[key]}, ensure_ascii=False)
                   for key in sorted(flattened_payload.keys())]
        logger.debug(f"to_sign: {json.dumps(to_sign, indent=4)}")
        log_issuance("Starting BBS+ signature generation", 
                    level=LogLevel.INFO,
                    credential_identifier=credential_identifier,
                    credential_id=uniqID,
                    message_count=len(to_sign),
                    operation="bbs_signing")
        
        signer = bbs_core.SignRequest(to_sign, bbs_dpk, bbs_secret)
        sign_result = signer.sign_messages()
        
        log_issuance("BBS+ signature generated successfully", 
                    level=LogLevel.INFO,
                    credential_identifier=credential_identifier,
                    credential_id=uniqID,
                    operation="bbs_signing_complete")

        signature_bytes = base64.b64encode(sign_result.signature).decode()

        # Additional headers
        additional_headers = {
            "kid": issuer_kid,
            "alg": "ES256",
            "typ": "JWT",
        }

        # Create a VC_validity entry with status_index
        status_list_index = int(credential_status["statusListIndex"])
        vc_validity = VC_validity(
            identifier=unique_id, 
            credential_data=payload, 
            validity=True, 
            status="active",
            status_index=status_list_index
        )
        db.session.add(vc_validity)
        db.session.commit()
        
        log_issuance("Credential validity record stored", 
                    level=LogLevel.INFO,
                    credential_identifier=credential_identifier,
                    credential_id=uniqID,
                    status_id=unique_id,
                    status_index=status_list_index,
                    operation="validity_storage")

        # Generate the VC JWT
        vc_jwt = jwt.encode(payload, private_key,
                            algorithm="ES256", headers=additional_headers)
        c_nonce = generate_nonce(10)
        c_nonce_expires_in = 86400  # 24 hours

        # Send the response with the VC JWT and nonce
        log_issuance("Credential generated and issued successfully", 
                    level=LogLevel.INFO,
                    credential_identifier=credential_identifier,
                    credential_id=uniqID,
                    status_id=unique_id,
                    format="bbs+_vc",
                    operation="credential_issued")
        
        # Track successful operation
        duration_ms = int((time.time() - start_time) * 1000)
        track_operation('credential_issuance', 'success', duration_ms, {
            'credential_id': uniqID,
            'credential_identifier': credential_identifier,
            'format': 'bbs+_vc'
        })
        
        return jsonify({
            "format": "bbs+_vc",
            "credential": vc_jwt,
            "signature": signature_bytes,
            "c_nonce": c_nonce,
            "c_nonce_expires_in": c_nonce_expires_in,
        }), 200
        
    except Exception as e:
        # Track failed operation
        duration_ms = int((time.time() - start_time) * 1000)
        track_operation('credential_issuance', 'failed', duration_ms, {
            'error': str(e),
            'credential_identifier': credential_identifier if 'credential_identifier' in locals() else None
        })
        
        log_error("Critical error during credential generation", 
                 error=e,
                 level=LogLevel.CRITICAL, 
                 credential_identifier=credential_identifier if 'credential_identifier' in locals() else None,
                 credential_id=uniqID if 'uniqID' in locals() else None,
                 operation="generate_credential")
        return jsonify({"error": "Internal server error during credential generation"}), 500


@log_function_call(LogCategory.ISSUANCE, include_args=False)
def get_payload(issuer_did, decoded_token, credential_subject, uniqID, issuer_cert=None):
    payload = {
        "iat": int(datetime.now(tz=timezone.utc).timestamp()) - 60,
        "iss": issuer_did,
        "sub": decoded_token.get("sub", ""),
        # 1 hour expiration
        "exp": int(datetime.now(tz=timezone.utc).timestamp()) + 60 * 60,
        "nbf": int(datetime.now(tz=timezone.utc).timestamp()),
        "jti": uniqID,
        "vc": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
                "https://w3id.org/vc/status-list/2021/v1"
            ],
            "type": [
                "VerifiableCredential",
                "VerifiableAttestation",
                "StudentIDCard"
            ],
            "id": uniqID,
            "issuer": {
                "id": issuer_did,
                "name": "Technical University of Berlin"
            },
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "validFrom": datetime.now(timezone.utc).isoformat(),
            "credentialSubject": credential_subject,
            "credentialSchema": {
                "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v3/schemas/zDpWGUBenmqXzurskry9Nsk6vq2R8thh9VSeoRqguoyMD",
                "type": "FullJsonSchemaValidator2021"
            },
            "expirationDate": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    }
    
    # Add X.509 certificate information if available
    if issuer_cert:
        try:
            # Create a temporary X509Manager to get certificate info
            x509_manager = X509Manager()
            cert_info = x509_manager.get_certificate_info(issuer_cert)
            
            # Add certificate information to the VC
            payload["vc"]["issuer"] = {
                "id": issuer_did,
                "name": cert_info["subject"]["common_name"] or "Technical University of Berlin",
                "x509Certificate": {
                    "subject": {
                        "commonName": cert_info["subject"]["common_name"],
                        "organization": cert_info["subject"]["organization"]
                    },
                    "issuer": {
                        "commonName": cert_info["issuer"]["common_name"],
                        "organization": cert_info["issuer"]["organization"]
                    },
                    "serialNumber": cert_info["serial_number"],
                    "validity": {
                        "notBefore": cert_info["validity"]["not_before"].isoformat(),
                        "notAfter": cert_info["validity"]["not_after"].isoformat()
                    },
                    "thumbprint": cert_info["thumbprint"],
                    "thumbprintAlgorithm": "SHA-256"
                }
            }
        except Exception as e:
            logger.warning(f"Error adding X.509 certificate to credential: {str(e)}")
            log_error("Failed to add X.509 certificate information to credential", 
                     error=e,
                     level=LogLevel.WARNING,
                     credential_id=uniqID,
                     operation="x509_integration")

    return payload


@log_function_call(LogCategory.ISSUANCE, include_args=False)
def get_credential_data(credential_data):
    credential_data = credential_data.credential_data if credential_data else None
    logger.debug(f"Credential Data: {credential_data}")
    if not credential_data:
        log_issuance("Using default credential data (no stored data found)", 
                    level=LogLevel.INFO,
                    operation="credential_data_fallback")
        return {
            "firstName": "Maxi" + f"{str(generate_nonce(5))}",
            "lastName": "Musterfrau" + f"{str(generate_nonce(5))}",
            "issuanceCount": "1",
            "image": profile,
            "studentId": f"{str(generate_nonce(5))}",
            "studentIdPrefix": "654321",
            "theme": {
                "name": "Technische Universität Berlin",
                "icon": logo,
                "bgColorCard": "C40D1E",
                "bgColorSectionTop": "C40D1E",
                "bgColorSectionBot": "FFFFFF",
                "fgColorTitle": "FFFFFF"
            }
        }

    return credential_data


@log_function_call(LogCategory.ISSUANCE, include_args=False)
def resolve_credential_offer(id):
    offer = VC_Offer.query.filter_by(uuid=id).first()

    # Initialize variables
    iss_state = None
    pre_auth_code = None
    credential_data = None

    if offer:
        logger.debug(f"Offer: {offer.uuid}")
        log_issuance("Credential offer found and resolved", 
                    level=LogLevel.INFO,
                    credential_identifier=id,
                    offer_uuid=offer.uuid,
                    operation="offer_resolution")
        
        iss_state = offer.issuer_state
        pre_auth_code = offer.pre_authorized_code
        credential_data = offer.credential_data

        logger.info(f"Credential Data: {credential_data}")

        if iss_state:
            # You can implement logic to store the offer in the database if needed
            pass

        if pre_auth_code:
            # You can implement logic to store the offer in the database if needed
            pass

    logger.info(f"State: {iss_state}, Pre-Auth Code: {pre_auth_code}")
    
    if not offer:
        log_issuance("Credential offer not found, using default response", 
                    level=LogLevel.WARNING,
                    credential_identifier=id,
                    operation="offer_not_found")

    # Prepare the response
    response = {
        "credential_issuer": app.config["SERVER_URL"],
        "credentials": credential_data.get('type', ["UniversityDegreeCredential"]) if credential_data else ["UniversityDegreeCredential"],
        "grants": {
            "authorization_code": {
                # Generate a new UUID if no issuer_state
                "issuer_state": iss_state or str(uuid4()),
            }
        }
    }

    return jsonify(response), 200
