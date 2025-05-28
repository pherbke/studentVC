from flask import Flask, request, redirect, jsonify
import jwt
import uuid
import logging
from flask import current_app as app
from ..models import VC_AuthorizationCode
from .. import db

logger = logging.getLogger(__name__)


def resolve_authorization_request(request_args, private_key):
    response_type = request_args.get("response_type")
    scope = request_args.get("scope")
    state = request_args.get("state")
    client_id = request_args.get("client_id")
    authorization_details = request_args.get("authorization_details")
    redirect_uri = request_args.get("redirect_uri")
    nonce = request_args.get("nonce")
    code_challenge = request_args.get("code_challenge")
    code_challenge_method = request_args.get("code_challenge_method")
    client_metadata = request_args.get("client_metadata")
    issuer_state = request_args.get("issuer_state")

    # Validate required parameters
    if not client_id:
        return "Client id is missing", 400

    if not redirect_uri:  # TODO: this is supposed to be optional???
        return "Missing redirect URI", 400

    if response_type != "code":
        return "Unsupported response type", 400

    if code_challenge_method != "S256":
        return "Invalid code challenge method", 400

    # Store authorization code details in the map
    logger.info(
        f"Storing authorization code details {client_id}, {issuer_state}")
    new_auth_code = VC_AuthorizationCode(
        client_id=client_id,
        code_challenge=code_challenge,
        issuer_state=issuer_state,
    )
    db.session.add(new_auth_code)
    db.session.commit()

    # Define the response parameters
    responseType = "id_token"
    responseMode = "direct_post"
    serverUrl = app.config["SERVER_URL"]
    redirectURI = f"{serverUrl}/direct_post"

    # Construct the JWT payload
    payload = {
        "iss": serverUrl,
        "aud": client_id,
        "nonce": nonce,
        "state": state,
        "client_id": client_id,
        "response_uri": client_id,
        "response_mode": responseMode,
        "response_type": responseType,
        "scope": "openid",
        "code_challenge": code_challenge,
        "issuer_state": issuer_state,
    }

    # JWT Header
    header = {
        "typ": "jwt",
        "alg": "ES256",
        "kid": "did:ebsi:zrZZyoQVrgwpV1QZmRUHNPz#sig-key",  # TODO: Your kid here
    }

    # Sign the JWT
    requestJar = jwt.encode(payload, private_key,
                            algorithm="ES256", headers=header)

    # Construct the redirect URL with query parameters
    redirectUrl = f"{redirect_uri}?state={state}&client_id={client_id}&redirect_uri={redirectURI}&response_type={responseType}&response_mode={responseMode}&scope=openid&nonce={nonce}&request={requestJar}"

    # Redirect to the client’s redirect URI
    return redirect(redirectUrl, code=302)
