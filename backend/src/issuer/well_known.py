from flask import jsonify
from flask import current_app as app
import sys
import os

# Add x509 module to path if it's not already available
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from x509.manager import X509Manager


def openid_credential_issuer(issuer_cert=None):
    server_url = app.config["SERVER_URL"]
    metadata = {
        "credential_issuer": server_url,
        "authorization_server": server_url,
        "credential_endpoint": f"{server_url}/credential",
        "jwks_uri": f"{server_url}/jwks",
        "credential_response_encryption": {
            "alg_values_supported": ["ECDH-ES"],
            "enc_values_supported": ["A128GCM"],
            "encryption_required": False,
        },
        "display": [
            {
                "name": "Technical University of Berlin",
                "locale": "en-US",
                "logo": {
                    "url": "https://logowik.com/content/uploads/images/technischen-universitat-berlin1469.jpg",
                },
            }
        ],
        "credentials_supported": [
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "UniversityDegreeCredential",
                    "CTWalletSamePreAuthorisedInTime",
                    "CTWalletSameAuthorisedInTime",
                ],
                "cryptographic_binding_methods_supported": [
                    "DID"
                ],
                "cryptographic_suites_supported": [
                    "ES256",
                    "ES256K"
                ],
                "display": [
                    {
                        "name": "EU Diploma",
                        "locale": "en-US",
                        "description": "This is the official EBSI VC Diploma",
                        "background_color": "#3B6F6D",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "uri": "https://dutchblockchaincoalition.org/assets/images/icons/Logo-DBC.png",
                            "alt_text": "An orange block shape, with the text Dutch Blockchain Coalition next to it, portraying the logo of the Dutch Blockchain Coalition."
                        },
                        "background_image": {
                            "uri": "https://i.ibb.co/CHqjxrJ/dbc-card-hig-res.png",
                            "alt_text": "Connected open cubes in blue with one orange cube as a background of the card"
                        }
                    }
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation"
                },
                "credentialSubject": {
                    "givenNames": {
                        "display": [
                            {"name": "First Name", "locale": "en-US"},
                            {"name": "Vorname", "locale": "de-DE"},
                        ]
                    },
                    "familyName": {
                        "display": [
                            {"name": "Family Name", "locale": "en-US"},
                            {"name": "Nachname", "locale": "de-DE"},
                        ]
                    },
                    "dateOfBirth": {
                        "display": [
                            {"name": "Birth Date", "locale": "en-US"},
                            {"name": "GeburtsDatum", "locale": "de-DE"},
                        ]
                    },
                    "gpa": {
                        "display": [
                            {"name": "GPA", "locale": "en-us"},
                            {"name": "Note", "locale": "de-DE"},
                        ]
                    },
                }
            }
        ],
    }
    
    # Add X.509 certificate information if available
    if issuer_cert:
        try:
            # Create a temporary X509Manager to get certificate info
            x509_manager = X509Manager()
            cert_info = x509_manager.get_certificate_info(issuer_cert)
            
            # Add X.509 certificate information to the metadata
            metadata["x509_certificate"] = {
                "subject": {
                    "common_name": cert_info["subject"]["common_name"],
                    "organization": cert_info["subject"]["organization"]
                },
                "issuer": {
                    "common_name": cert_info["issuer"]["common_name"],
                    "organization": cert_info["issuer"]["organization"]
                },
                "validity": {
                    "not_before": cert_info["validity"]["not_before"].isoformat(),
                    "not_after": cert_info["validity"]["not_after"].isoformat()
                },
                "serial_number": cert_info["serial_number"],
                "thumbprint": cert_info["thumbprint"],
                "thumbprint_algorithm": "SHA-256",
                "info_endpoint": f"{server_url}/x509-info"
            }
            
            # Add certificate chain information
            metadata["credentials_supported"][0]["certificate_chain_support"] = True
            
            # Add X.509 to cryptographic binding methods
            if "X509" not in metadata["credentials_supported"][0]["cryptographic_binding_methods_supported"]:
                metadata["credentials_supported"][0]["cryptographic_binding_methods_supported"].append("X509")
                
            # Add trust framework information for the certificate authority
            if "organization" in cert_info["issuer"] and cert_info["issuer"]["organization"]:
                ca_org = cert_info["issuer"]["organization"]
                if "GÉANT" in ca_org or "GEANT" in ca_org:
                    metadata["credentials_supported"][0]["trust_framework"]["certification_authorities"] = ["GÉANT TCS"]
                elif "DFN" in ca_org:
                    metadata["credentials_supported"][0]["trust_framework"]["certification_authorities"] = ["DFN-PKI"]
                else:
                    metadata["credentials_supported"][0]["trust_framework"]["certification_authorities"] = [ca_org]
        except Exception as e:
            # Log the error but continue without X.509 info
            print(f"Error adding X.509 certificate information: {str(e)}")

    return jsonify(metadata), 200


def openid_configuration():
    server_url = app.config["SERVER_URL"]
    config = {
        "issuer": server_url,
        "authorization_endpoint": f"{server_url}/authorize",
        "token_endpoint": f"{server_url}/token",
        "jwks_uri": f"{server_url}/jwks",
        "scopes_supported": ["openid"],
        "response_types_supported": ["code", "vp_token", "id_token"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "request_object_signing_alg_values_supported": ["ES256"],
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "vp_formats_supported": {
            "jwt_vp": {
                "alg_values_supported": ["ES256"]
            },
            "jwt_vc": {
                "alg_values_supported": ["ES256"]
            }
        },
        "subject_syntax_types_supported": ["did:key", "did:ebsi", "did:web"],
        "subject_trust_frameworks_supported": ["ebsi"],
        "id_token_types_supported": [
            "subject_signed_id_token",
            "attester_signed_id_token"
        ]
    }

    return jsonify(config), 200
