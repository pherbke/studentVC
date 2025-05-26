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
import os
import sys

# Add x509 module to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from x509.manager import X509Manager

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
x509_manager = None
issuer_cert = None


@issuer.route('/issuer', methods=['GET', 'POST'])
def index():
    initialize_keys()
    if request.method == "GET":
        return render_template("issuer.html", img_data=None, debug_info=None)

    # Check if this is a form submission that should generate a QR code
    # Only generate QR code if we have meaningful form data
    credential_data = request.form.to_dict()
    logger.info(f"Received form data form: {credential_data}")
    logger.info(f"Received form data files: {request.files}")

    # Check if this request has actual credential data (not empty form)
    # Always generate QR code if ANY form data is provided (including placeholders)
    has_any_data = bool(credential_data and any(v for v in credential_data.values() if v))
    
    # Only skip QR generation if completely empty form submission
    if not has_any_data and not request.files:
        logger.info("Empty form submission - not generating QR code")
        return render_template("issuer.html", img_data=None, debug_info=None)

    # Check if this is a demo submission (detected by specific demo names)
    is_demo_submission = (
        credential_data.get('firstName') in ['Max', 'Anna', 'Lukas', 'Emma', 'Felix', 'Lena', 'Tom', 'Julia', 'Ben', 'Sarah'] and
        credential_data.get('lastName') in ['Müller', 'Schmidt', 'Weber', 'Fischer', 'Meyer', 'Wagner', 'Koch', 'Richter', 'Klein', 'Wolf']
    )
    
    profile_image = request.files.get('image')
    if profile_image:
        logger.info(f"Received profile image:")
        img = preprocess_image(profile_image, (561, 722))
        credential_data['image'] = img
    elif is_demo_submission:
        # Use the demo profile image for demo submissions
        demo_image_path = os.path.join(current_app.static_folder, 'profile.jpg')
        if os.path.exists(demo_image_path):
            logger.info(f"Using demo profile image for demo submission")
            from io import BytesIO
            with open(demo_image_path, 'rb') as f:
                file_content = f.read()
            
            # Create a file-like object that preprocess_image can handle
            from werkzeug.datastructures import FileStorage
            demo_file = FileStorage(
                stream=BytesIO(file_content),
                filename='profile.jpg',
                content_type='image/jpeg'
            )
            img = preprocess_image(demo_file, (561, 722))
            credential_data['image'] = img
        else:
            credential_data['image'] = placeholder_profile
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

    # Generate the offer URL and QR code efficiently
    try:
        link = get_offer_url(full_credential_data)
        logger.info(f"Generated QR code link: {link}")
        img = generate_qr_code(link)
        logger.info("QR code generated successfully")
        
        # Create debug information for the template
        debug_info = {
            "qr_url": link,
            "credential_data": full_credential_data,
            "is_demo": is_demo_submission,
            "data_type": "Demo-Daten (Zufällig generiert)" if is_demo_submission else "Eingegebene Daten"
        }
        
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        flash("Error generating QR code. Please try again.", "error")
        return render_template("issuer.html", img_data=None, debug_info=None)

    return render_template("issuer.html", img_data=img, debug_info=debug_info)


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
    global private_key, public_key, jwks, issuer_did, issuer_kid, bbs_dpk, bbs_secret, x509_manager, issuer_cert
    
    # Initialize BBS+ and EC keys if not already done
    if not private_key or not public_key or not bbs_dpk or not bbs_secret:
        bbs_secret, bbs_dpk = load_or_generate_bbs_keys()
        private_key, public_key = load_or_generate_keys()
        issuer_did = generate_did(public_key)
        issuer_kid = generate_kid(issuer_did)
    
    # Initialize JWKS
    if not jwks:
        jwks = pem_to_jwk(public_key, "public")
    
    # Initialize X.509 manager if not already done
    if not x509_manager:
        logger.info("Initializing X.509 manager")
        x509_manager = X509Manager()
        
        # Try to load issuer certificate if it exists
        issuer_cert_path = os.path.join(current_app.config['INSTANCE_FOLDER'], 'issuer.pem')
        try:
            if os.path.exists(issuer_cert_path):
                logger.info(f"Loading issuer certificate from {issuer_cert_path}")
                issuer_cert = x509_manager.load_certificate(issuer_cert_path)
                
                # Verify if certificate is valid
                is_valid, reason = x509_manager.is_certificate_valid(issuer_cert)
                if not is_valid:
                    logger.warning(f"Issuer certificate is not valid: {reason}")
                    issuer_cert = None
                else:
                    logger.info("Issuer certificate loaded successfully")
                    
                    # Create or update the certificate binding with DID
                    domain = current_app.config.get('SERVER_DOMAIN', 'example.com')
                    cert_did = x509_manager.create_did_from_certificate(
                        issuer_cert, 
                        did_method='web',
                        domain=domain
                    )
                    
                    # Verify binding
                    is_bound, reason = x509_manager.verify_certificate_did_binding(issuer_cert, issuer_did)
                    if not is_bound:
                        logger.warning(f"Certificate not correctly bound to DID: {reason}")
                    else:
                        logger.info(f"Certificate correctly bound to DID: {issuer_did}")
            else:
                logger.info(f"No issuer certificate found at {issuer_cert_path}")
        except Exception as e:
            logger.error(f"Error loading issuer certificate: {str(e)}")
            issuer_cert = None


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
    return generate_credential(auth_header, public_key, private_key, issuer_did, issuer_kid, bbs_dpk, bbs_secret, issuer_cert)


@issuer.route("/.well-known/openid-credential-issuer", methods=["GET"])
def get_credential_issuer_metadata():
    logger.info("Received request for credential issuer metadata")
    # Initialize keys to ensure X.509 certificates are loaded
    initialize_keys()
    return openid_credential_issuer(issuer_cert)


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


@issuer.route("/x509-info", methods=["GET"])
def get_x509_info():
    """
    Endpoint to retrieve X.509 certificate information for the issuer.
    """
    initialize_keys()
    
    if not issuer_cert:
        return jsonify({"error": "No X.509 certificate available for this issuer"}), 404
    
    # Use the X.509 manager to get certificate info
    global x509_manager
    cert_info = x509_manager.get_certificate_info(issuer_cert)
    
    # Create a simplified representation for the response
    response = {
        "subject": cert_info['subject'],
        "issuer": cert_info['issuer'],
        "validity": {
            "notBefore": cert_info['validity']['not_before'].isoformat(),
            "notAfter": cert_info['validity']['not_after'].isoformat()
        },
        "serialNumber": cert_info['serial_number'],
        "thumbprint": cert_info['thumbprint'],
        "binding": {
            "did": issuer_did
        }
    }
    
    return jsonify(response), 200


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
