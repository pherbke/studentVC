from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app
from flask_login import login_required
from logging import getLogger
from flask_login import login_required
from .key_generator import load_or_generate_keys, generate_did, generate_kid, load_or_generate_bbs_keys
from .offer import get_offer_url
from .token import authenticate_token, verify_token, verify_and_generate_token
from .credential import generate_credential, resolve_credential_offer
from .well_known import openid_credential_issuer, openid_configuration
from .jwks import pem_to_jwk
from .authorization import resolve_authorization_request
from .direct_post import resolve_direct_post
from .qr_codes import generate_qr_code
from .utils import preprocess_image, get_placeholders

placeholder_logo, placeholder_profile = get_placeholders()

issuer = Blueprint('issuer', __name__)
logger = getLogger("LOGGER")

private_key = None
public_key = None
jwks = None
issuer_did = None
issuer_kid = None
bbs_dpk = None
bbs_secret = None


@issuer.route('/issuer', methods=['GET', 'POST'])
def index():
    initialize_keys()
    if request.method == "GET":
        return render_template("issuer.html", img_data=None)

    # Process the form data
    credential_data = request.form.to_dict()
    logger.info(f"Received form data form: {credential_data}")
    logger.info(f"Received form data files: {request.files}")

    profile_image = request.files.get('image')
    if profile_image:
        logger.info(f"Received profile image:")
        img = preprocess_image(profile_image, (561, 722))
        credential_data['image'] = img
    else:
        credential_data['image'] = placeholder_profile

    theme_icon_image = request.files.get('theme[icon]')
    if theme_icon_image:
        logger.info(f"Received theme icon image:")
        img = preprocess_image(
            theme_icon_image, (762, 152), keep_aspect_ratio=True)
        credential_data['theme[icon]'] = img
    else:
        credential_data['theme[icon]'] = placeholder_logo

        # Manually group the theme-related data
    theme_data = {
        "name": credential_data.get('theme[name]'),
        "icon": credential_data.get('theme[icon]'),
        "bgColorCard": credential_data.get('theme[bgColorCard]'),
        "bgColorSectionTop": credential_data.get('theme[bgColorSectionTop]'),
        "bgColorSectionBot": credential_data.get('theme[bgColorSectionBot]'),
        "fgColorTitle": credential_data.get('theme[fgColorTitle]')
    }

    # Create the full credential object
    full_credential_data = {
        "firstName": credential_data.get('firstName'),
        "lastName": credential_data.get('lastName'),
        "issuanceCount": "1",
        "image": credential_data.get('image'),
        "studentId": credential_data.get('studentId'),
        "studentIdPrefix": credential_data.get('studentIdPrefix'),
        "theme": theme_data
    }

    # Now you can use full_credential_data as needed
    link = get_offer_url(full_credential_data)
    logger.info(f"Generated QR code link: {link}")
    img = generate_qr_code(link)

    return render_template("issuer.html", img_data=img)


@issuer.route("/offer", methods=["POST"])
def offer():
    initialize_keys()
    # Generate the credential offer URI
    logger.info("Received request to generate credential offer")

    # check if the request has a json
    # if request.json:
    #     logger.info(f"Received credential data: {request.json}")
    #     return redirect(get_offer_url(request.json))
    return redirect(get_offer_url(None))


def initialize_keys():
    global private_key, public_key, jwks, issuer_did, issuer_kid, bbs_dpk, bbs_secret
    if not private_key or not public_key or not bbs_dpk or not bbs_secret:
        bbs_secret, bbs_dpk = load_or_generate_bbs_keys()
        private_key, public_key = load_or_generate_keys()
        issuer_did = generate_did(public_key)
        issuer_kid = generate_kid(issuer_did)
    if not jwks:
        jwks = pem_to_jwk(public_key, "public")
    # return jsonify({"credential_offer": credential_offer_uri}), 200


@issuer.route("/verifyAccessToken", methods=["POST"])
def verify_access_token():
    logger.info(f"Received token verification request:")
    data = request.get_json()
    logger.info(f"Received token verification request: {data}")
    return verify_token(data, public_key)


@issuer.route("/credential", methods=["POST"])
@authenticate_token
def create_credential():
    logger.info("Received request to create a credential")
    auth_header = request.headers.get("Authorization")
    logger.info(f"Received credential request with auth header: {auth_header}")
    return generate_credential(auth_header, public_key, private_key, issuer_did, issuer_kid, bbs_dpk, bbs_secret)


@issuer.route("/.well-known/openid-credential-issuer", methods=["GET"])
def get_credential_issuer_metadata():
    logger.info("Received request for credential issuer metadata")
    return openid_credential_issuer()


@issuer.route("/.well-known/openid-configuration", methods=["GET"])
def get_openid_configuration():
    logger.info("Received request for openid configuration")
    return openid_configuration()


@issuer.route("/credential-offer/<Uid>", methods=["GET"])
def get_credential_offer(Uid):
    logger.info(f"Received request for credential offer with Uid: {Uid}")
    return resolve_credential_offer(Uid)


@issuer.route("/jwks", methods=["GET"])
def get_jwks():
    logger.info("Received request for JWKS")
    keys = [
        {**jwks, "kid": "did:ebsi:zrZZyoQVrgwpV1QZmRUHNPz#sig-key", "use": "sig"},
        {**jwks, "kid": "did:ebsi:zrZZyoQVrgwpV1QZmRUHNPz#authentication-key",
            "use": "keyAgreement"}
    ]

    return jsonify({"keys": keys}), 200


@issuer.route("/authorize", methods=["GET"])
def authorize():
    logger.info("Received authorization request")
    return resolve_authorization_request(request.args, private_key)


@issuer.route("/direct_post", methods=["POST"])
def direct_post():
    logger.info("Received direct post request")
    state = request.args.get("state")
    id_jwt = request.args.get("id_token")
    logger.info(
        f"Received direct post request with state: {state} and id_token: {id_jwt}")
    return resolve_direct_post(state, id_jwt)


@issuer.route('/token', methods=['POST'])
def token():
    logger.info("Received token request")
    request_json = request.args
    logger.info(f"Received token request: {request_json}")
    return verify_and_generate_token(request_json, private_key)
