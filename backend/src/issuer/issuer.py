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
import time

# Add x509 module to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from x509.manager import X509Manager

# Import tenant configuration for multi-tenant support
from tenant_config import tenant_config

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
        # Pass tenant context to template for proper branding
        context = tenant_config.get_template_context()
        return render_template("issuer.html", img_data=None, debug_info=None, **context)

    # Only clear QR cache if needed (performance optimization)
    # Cache clearing moved to error handling only
    
    # Check if this is a form submission that should generate a QR code
    # Only generate QR code if we have meaningful form data
    credential_data = request.form.to_dict()
    logger.info(f"Received form data form: {credential_data}")
    logger.debug(f"Received form data files: {request.files}")  # Reduce verbosity

    # Check if this request has actual credential data (not empty form)
    # Always generate QR code if ANY form data is provided (including placeholders)
    has_any_data = bool(credential_data and any(v.strip() for v in credential_data.values() if v))
    has_meaningful_files = any(f.filename for f in request.files.values() if f)
    
    # Generate QR code if we have any meaningful data or if placeholders should be used
    should_generate_qr = has_any_data or has_meaningful_files
    
    # If no meaningful data, fill with placeholder values for demo purposes
    if not should_generate_qr:
        logger.info("Empty form submission - using placeholder data for QR generation")
        credential_data.update({
            'firstName': 'Placeholder',
            'lastName': 'Student', 
            'studentId': '000000',
            'studentIdPrefix': '000000'
        })
        should_generate_qr = True

    # Check if this is a demo submission (detected by specific demo names)
    is_demo_submission = (
        credential_data.get('firstName') in ['Max', 'Anna', 'Lukas', 'Emma', 'Felix', 'Lena', 'Tom', 'Julia', 'Ben', 'Sarah'] and
        credential_data.get('lastName') in ['Müller', 'Schmidt', 'Weber', 'Fischer', 'Meyer', 'Wagner', 'Koch', 'Richter', 'Klein', 'Wolf']
    )
    
    profile_image = request.files.get('image')
    if profile_image and profile_image.filename:
        try:
            logger.info(f"Received profile image: {profile_image.filename}")
            img = preprocess_image(profile_image, (561, 722))
            credential_data['image'] = img
            logger.info("Profile image processed successfully")
        except Exception as e:
            logger.error(f"Error processing profile image: {e}")
            credential_data['image'] = placeholder_profile
    elif is_demo_submission:
        # Use the demo profile image for demo submissions
        import os
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
    if theme_icon_image and theme_icon_image.filename:
        try:
            logger.info(f"Received theme icon image: {theme_icon_image.filename}")
            img = preprocess_image(
                theme_icon_image, (762, 152), keep_aspect_ratio=True)
            credential_data['theme[icon]'] = img
            logger.info("Theme icon processed successfully")
        except Exception as e:
            logger.error(f"Error processing theme icon: {e}")
            credential_data['theme[icon]'] = placeholder_logo
    else:
        credential_data['theme[icon]'] = placeholder_logo

    # Get tenant-specific default theme values
    tenant_colors = tenant_config.get('colors')
    default_theme = {
        "name": tenant_config.get('full_name'),
        "icon": placeholder_logo,
        "bgColorCard": tenant_colors.get('primary', '#c40e20').lstrip('#'),
        "bgColorSectionTop": tenant_colors.get('primary', '#c40e20').lstrip('#'),
        "bgColorSectionBot": tenant_colors.get('background', '#ffffff').lstrip('#'),
        "fgColorTitle": tenant_colors.get('primary_text', '#ffffff').lstrip('#')
    }
    
    # Manually group the theme-related data with fallbacks to tenant defaults
    theme_data = {
        "name": credential_data.get('theme[name]') or default_theme["name"],
        "icon": credential_data.get('theme[icon]') or default_theme["icon"],
        "bgColorCard": credential_data.get('theme[bgColorCard]') or default_theme["bgColorCard"],
        "bgColorSectionTop": credential_data.get('theme[bgColorSectionTop]') or default_theme["bgColorSectionTop"],
        "bgColorSectionBot": credential_data.get('theme[bgColorSectionBot]') or default_theme["bgColorSectionBot"],
        "fgColorTitle": credential_data.get('theme[fgColorTitle]') or default_theme["fgColorTitle"]
    }
    
    logger.info(f"Using theme data: {theme_data} for tenant: {tenant_config.tenant_id}")

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
        logger.info(f"Generating QR code for credential data: {full_credential_data.get('firstName', '')} {full_credential_data.get('lastName', '')}")
        
        # Generate offer URL
        link = get_offer_url(full_credential_data)
        if not link:
            raise ValueError("Failed to generate offer URL")
        
        logger.info(f"Generated QR code link: {link}")
        
        # Validate URL before QR generation (allow OpenID credential offer URIs)
        if not link.startswith(('http://', 'https://', 'openid-credential-offer://')):
            raise ValueError(f"Invalid URL format: {link}")
        
        # Generate QR code with error handling
        img = generate_qr_code(link)
        if not img:
            raise ValueError("QR code generation returned empty result")
        
        logger.info(f"QR code generated successfully, length: {len(img)}")
        
        # Create debug information for the template (always show for all submissions)
        debug_info = {
            "qr_url": link,
            "credential_data": full_credential_data,
            "is_demo": is_demo_submission,
            "data_type": "Demo-Daten (Zufällig generiert)" if is_demo_submission else "Eingegebene Daten",
            "generation_timestamp": str(int(time.time()))
        }
        
        logger.info("QR code and debug info created successfully")
        
        # Test that the QR code data is valid base64
        try:
            import base64
            base64.b64decode(img)
        except Exception as b64_error:
            logger.error(f"Generated QR code is not valid base64: {b64_error}")
            raise ValueError("Invalid QR code data generated")
        
    except Exception as e:
        logger.error(f"Error generating QR code: {e}", exc_info=True)
        
        # Clear QR cache only on actual errors
        from .qr_codes import clear_qr_cache
        clear_qr_cache()
        
        flash(f"Error generating QR code: {str(e)}. Please try again.", "error")
        return render_template("issuer.html", img_data=None, debug_info=None, error_message=str(e))

    # Pass tenant context for consistent branding
    context = tenant_config.get_template_context()
    return render_template("issuer.html", img_data=img, debug_info=debug_info, **context)


@issuer.route('/generate_qr', methods=['POST'])
def generate_qr_endpoint():
    """
    SIMPLIFIED AJAX endpoint for QR code generation
    """
    try:
        initialize_keys()
        
        # Get form data
        credential_data = request.form.to_dict()
        request_id = credential_data.get('_timestamp', str(int(time.time())))
        logger.info(f"QR generation request {request_id} with {len(credential_data)} fields")
        
        # Ensure all required fields have values
        defaults = {
            'firstName': 'Student',
            'lastName': 'Mustermann', 
            'studentId': '123456',
            'studentIdPrefix': '654321'
        }
        
        for field, default_value in defaults.items():
            if not credential_data.get(field) or not credential_data.get(field).strip():
                credential_data[field] = default_value
        
        # Check if this is a demo submission (detected by specific demo names)
        is_demo_submission = (
            credential_data.get('firstName') in ['Max', 'Anna', 'Lukas', 'Emma', 'Felix', 'Lena', 'Tom', 'Julia', 'Ben', 'Sarah'] and
            credential_data.get('lastName') in ['Müller', 'Schmidt', 'Weber', 'Fischer', 'Meyer', 'Wagner', 'Koch', 'Richter', 'Klein', 'Wolf']
        )
        
        # Process images with robust error handling
        profile_image = request.files.get('image')
        if profile_image and profile_image.filename:
            try:
                logger.info(f"Processing profile image: {profile_image.filename}")
                img = preprocess_image(profile_image, (561, 722))
                credential_data['image'] = img
            except Exception as e:
                logger.warning(f"Profile image processing failed, using placeholder: {e}")
                credential_data['image'] = placeholder_profile
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
        if theme_icon_image and theme_icon_image.filename:
            try:
                logger.info(f"Processing theme icon: {theme_icon_image.filename}")
                img = preprocess_image(theme_icon_image, (762, 152), keep_aspect_ratio=True)
                credential_data['theme[icon]'] = img
            except Exception as e:
                logger.warning(f"Theme icon processing failed, using placeholder: {e}")
                credential_data['theme[icon]'] = placeholder_logo
        else:
            credential_data['theme[icon]'] = placeholder_logo

        # Get tenant-specific default theme values
        tenant_colors = tenant_config.get('colors')
        default_theme = {
            "name": tenant_config.get('full_name'),
            "icon": placeholder_logo,
            "bgColorCard": tenant_colors.get('primary', '#c40e20').lstrip('#'),
            "bgColorSectionTop": tenant_colors.get('primary', '#c40e20').lstrip('#'),
            "bgColorSectionBot": tenant_colors.get('background', '#ffffff').lstrip('#'),
            "fgColorTitle": tenant_colors.get('primary_text', '#ffffff').lstrip('#')
        }
        
        # Manually group the theme-related data with fallbacks to tenant defaults
        theme_data = {
            "name": credential_data.get('theme[name]') or default_theme["name"],
            "icon": credential_data.get('theme[icon]') or default_theme["icon"],
            "bgColorCard": credential_data.get('theme[bgColorCard]') or default_theme["bgColorCard"],
            "bgColorSectionTop": credential_data.get('theme[bgColorSectionTop]') or default_theme["bgColorSectionTop"],
            "bgColorSectionBot": credential_data.get('theme[bgColorSectionBot]') or default_theme["bgColorSectionBot"],
            "fgColorTitle": credential_data.get('theme[fgColorTitle]') or default_theme["fgColorTitle"]
        }
        
        logger.info(f"Using theme data for {tenant_config.tenant_id}: {theme_data['name']}")

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

        # Generate offer URL and QR code with comprehensive error handling
        logger.info(f"Generating offer URL for: {full_credential_data.get('firstName', '')} {full_credential_data.get('lastName', '')} [Tenant: {tenant_config.tenant_id}]")
        link = get_offer_url(full_credential_data)
        if not link:
            raise ValueError("Failed to generate offer URL - check server configuration")

        # Validate URL format before QR generation
        if not link.startswith(('http://', 'https://', 'openid-credential-offer://')):
            raise ValueError(f"Invalid offer URL format: {link}")

        # Generate QR code with timeout protection
        logger.info(f"Generating QR code for URL: {link[:100]}...")
        qr_image = generate_qr_code(link)
        if not qr_image:
            raise ValueError("QR code generation returned empty result")

        # Validate QR code data
        try:
            import base64
            base64.b64decode(qr_image)
        except Exception as b64_error:
            raise ValueError(f"Generated QR code is not valid base64: {b64_error}")

        # Create response with debug info
        debug_info = {
            "qr_url": link,
            "credential_data": full_credential_data,
            "is_demo": is_demo_submission,
            "generation_timestamp": str(int(time.time())),
            "tenant": tenant_config.tenant_id
        }

        logger.info(f"QR code generated for {full_credential_data.get('firstName')} {full_credential_data.get('lastName')} (request: {request_id})")
        
        return jsonify({
            "success": True,
            "qr_image": qr_image,
            "debug_info": debug_info
        })

    except Exception as e:
        request_id = request.form.get('_timestamp', 'unknown')
        
        logger.error(f"QR generation failed for request {request_id}: {str(e)}", exc_info=True)
        
        # Clear cache on errors
        try:
            from .qr_codes import clear_qr_cache
            clear_qr_cache()
        except Exception:
            pass
        
        # Simple error response
        error_message = "QR code generation failed - please try again"
        if "timeout" in str(e).lower():
            error_message = "Request timeout - please try again"
        
        return jsonify({
            "success": False,
            "error": error_message,
            "request_id": request_id
        }), 500


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
    
    # Ensure keys are initialized
    initialize_keys()
    
    return verify_token(data, public_key)


@issuer.route("/credential", methods=["POST"])
@authenticate_token
def create_credential():
    import time
    start_time = time.time()
    request_id = f"cred_{int(time.time())}_{id(request)}"
    
    try:
        logger.info(f"🔒 [WALLET-CREDENTIAL] Starting credential creation request (request: {request_id})")
        logger.info(f"🔒 Request headers: {dict(request.headers)}")
        logger.info(f"🔒 Request method: {request.method}")
        logger.info(f"🔒 Request URL: {request.url}")
        logger.info(f"🔒 Remote address: {request.remote_addr}")
        logger.info(f"🔒 Content type: {request.content_type}")
        
        auth_header = request.headers.get("Authorization")
        logger.info(f"🔒 Authorization header present: {bool(auth_header)}")
        if auth_header:
            auth_parts = auth_header.split(" ")
            logger.info(f"🔒 Auth header parts count: {len(auth_parts)}")
            if len(auth_parts) > 1:
                token_preview = auth_parts[1][:20] + "..." if len(auth_parts[1]) > 20 else auth_parts[1]
                logger.info(f"🔒 Token preview: {token_preview}")
        
        # Try to get request body for debugging and format extraction
        try:
            request_data = request.get_json() or {}
            logger.info(f"🔒 Request JSON keys: {list(request_data.keys()) if request_data else 'No JSON data'}")
            
            # Extract requested format from iOS app
            requested_format = request_data.get('format', 'bbs+_vc')  # Default to bbs+_vc
            logger.info(f"🔒 Requested credential format: {requested_format}")
            
        except Exception as json_error:
            logger.warning(f"🔒 Could not parse request JSON: {json_error}")
            requested_format = 'bbs+_vc'  # Default format
        
        # Call the generate_credential function with requested format
        result = generate_credential(auth_header, public_key, private_key, issuer_did, issuer_kid, bbs_dpk, bbs_secret, issuer_cert, requested_format)
        
        duration_ms = int((time.time() - start_time) * 1000)
        logger.info(f"✅ [WALLET-CREDENTIAL] Credential creation completed successfully (request: {request_id}, duration: {duration_ms}ms)")
        
        return result
        
    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.error(f"❌ [WALLET-CREDENTIAL] Credential creation failed (request: {request_id}, duration: {duration_ms}ms)")
        logger.error(f"❌ Error details: {type(e).__name__}: {str(e)}", exc_info=True)
        
        # Log detailed error to separate file
        try:
            import os
            error_log_path = os.path.join(current_app.config.get('INSTANCE_FOLDER', 'instance'), 'wallet_scan_errors.log')
            with open(error_log_path, 'a') as f:
                import datetime
                timestamp = datetime.datetime.now().isoformat()
                f.write(f"[{timestamp}] CREDENTIAL CREATION ERROR\n")
                f.write(f"[{timestamp}] Request ID: {request_id}\n")
                f.write(f"[{timestamp}] Error: {type(e).__name__}: {str(e)}\n")
                f.write(f"[{timestamp}] Headers: {dict(request.headers)}\n")
                try:
                    f.write(f"[{timestamp}] Body: {request.get_data(as_text=True)[:500]}\n")
                except:
                    f.write(f"[{timestamp}] Body: Could not read request body\n")
                f.write("\n")
        except:
            pass
            
        return jsonify({"error": "Internal server error in credential creation"}), 500


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
    import time
    start_time = time.time()
    request_id = f"offer_{int(time.time())}_{id(request)}"
    
    try:
        logger.info(f"🔍 [WALLET-SCAN] Starting credential offer request - Uid: {Uid} (request: {request_id})")
        logger.info(f"🔍 Request headers: {dict(request.headers)}")
        logger.info(f"🔍 Request method: {request.method}")
        logger.info(f"🔍 Request URL: {request.url}")
        logger.info(f"🔍 Remote address: {request.remote_addr}")
        
        # Call the resolve function with enhanced error handling
        result = resolve_credential_offer(Uid)
        
        duration_ms = int((time.time() - start_time) * 1000)
        logger.info(f"✅ [WALLET-SCAN] Credential offer resolved successfully - Uid: {Uid} (request: {request_id}, duration: {duration_ms}ms)")
        
        return result
        
    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.error(f"❌ [WALLET-SCAN] Credential offer failed - Uid: {Uid} (request: {request_id}, duration: {duration_ms}ms)")
        logger.error(f"❌ Error details: {type(e).__name__}: {str(e)}", exc_info=True)
        
        # Log detailed error to separate file
        try:
            import os
            error_log_path = os.path.join(current_app.config.get('INSTANCE_FOLDER', 'instance'), 'wallet_scan_errors.log')
            with open(error_log_path, 'a') as f:
                import datetime
                timestamp = datetime.datetime.now().isoformat()
                f.write(f"[{timestamp}] CREDENTIAL-OFFER ERROR - Uid: {Uid}\n")
                f.write(f"[{timestamp}] Request ID: {request_id}\n")
                f.write(f"[{timestamp}] Error: {type(e).__name__}: {str(e)}\n")
                f.write(f"[{timestamp}] Headers: {dict(request.headers)}\n\n")
        except:
            pass
            
        return jsonify({"error": "Internal server error in credential offer"}), 500


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
    import time
    start_time = time.time()
    request_id = f"token_{int(time.time())}_{id(request)}"
    
    try:
        logger.info(f"🎫 [WALLET-TOKEN] Starting token request (request: {request_id})")
        logger.info(f"🎫 Request headers: {dict(request.headers)}")
        logger.info(f"🎫 Request method: {request.method}")
        logger.info(f"🎫 Request URL: {request.url}")
        logger.info(f"🎫 Remote address: {request.remote_addr}")
        logger.info(f"🎫 Content type: {request.content_type}")
        
        # Try to get both args and form data
        request_args = request.args.to_dict()
        request_form = request.form.to_dict()
        
        # Only try to get JSON if content type is JSON
        request_json = {}
        if request.content_type and 'application/json' in request.content_type:
            try:
                request_json = request.get_json() or {}
            except Exception as json_error:
                logger.warning(f"🎫 Could not parse JSON data: {json_error}")
        
        logger.info(f"🎫 Request args: {request_args}")
        logger.info(f"🎫 Request form: {request_form}")
        logger.info(f"🎫 Request JSON: {request_json}")
        
        # Use form data if args is empty (which is more common for token requests)
        request_data = request_form if request_form else request_args
        if not request_data and request_json:
            request_data = request_json
            
        logger.info(f"🎫 Using request data: {request_data}")
        
        # Call the token generation function
        result = verify_and_generate_token(request_data, private_key)
        
        duration_ms = int((time.time() - start_time) * 1000)
        logger.info(f"✅ [WALLET-TOKEN] Token generation completed successfully (request: {request_id}, duration: {duration_ms}ms)")
        
        return result
        
    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.error(f"❌ [WALLET-TOKEN] Token generation failed (request: {request_id}, duration: {duration_ms}ms)")
        logger.error(f"❌ Error details: {type(e).__name__}: {str(e)}", exc_info=True)
        
        # Log detailed error to separate file
        try:
            import os
            error_log_path = os.path.join(current_app.config.get('INSTANCE_FOLDER', 'instance'), 'wallet_scan_errors.log')
            with open(error_log_path, 'a') as f:
                import datetime
                timestamp = datetime.datetime.now().isoformat()
                f.write(f"[{timestamp}] TOKEN GENERATION ERROR\n")
                f.write(f"[{timestamp}] Request ID: {request_id}\n")
                f.write(f"[{timestamp}] Error: {type(e).__name__}: {str(e)}\n")
                f.write(f"[{timestamp}] Headers: {dict(request.headers)}\n")
                f.write(f"[{timestamp}] Args: {request.args.to_dict()}\n")
                f.write(f"[{timestamp}] Form: {request.form.to_dict()}\n")
                try:
                    f.write(f"[{timestamp}] JSON: {request.get_json()}\n")
                except:
                    f.write(f"[{timestamp}] JSON: Could not parse JSON\n")
                f.write("\n")
        except:
            pass
            
        return jsonify({"error": "Internal server error in token generation"}), 500
