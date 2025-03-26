from flask import Blueprint, render_template, request, redirect, jsonify, current_app
from logging import getLogger
from .utils import generate_qr_code, randomString, get_demo_credential
from urllib.parse import urlencode
import jwt
import json
import requests
import importlib.util
import os
import base64
from flatten_json import flatten
from .. import socketio

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

        res = requests.get(validity_identifier, verify=False)
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
            # Emit success event
            socketio.emit('verification_result', {
                'status': 'success',
                'message': 'Access token is valid'
            })
            return jsonify({"success": "Access token is valid"}), 200
        else:
            # Emit error event
            logger.error(f"verify_result: {verify_result}")
            socketio.emit('verification_result', {
                'status': 'error',
                'message': 'Access token is not valid'
            })
            return jsonify({"error": "Access token is not valid"}), 401

    except Exception as e:
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
    assert did.startswith('did:key:z'), "Invalid DID format"
    base58_key = did[9:]  # Strip "did:key:z"

    # Decode the base58-encoded key
    try:
        multicodec_key = base58.b58decode(base58_key)
    except:
        raise ValueError("Public Key is not base58 encoded")

    # Verify and strip the multicodec prefix (P-256 -> 0x1200)
    assert multicodec_key[:2] == b'\x12\x00', "Unsupported key type"
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
