"""
X.509 Certificate API Routes

This module provides API endpoints for X.509 certificate operations,
including challenge-response protocol for verifying control over both
X.509 certificates and DIDs.
"""

import os
import base64
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List, Union

from flask import Blueprint, request, jsonify, current_app
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from .manager import X509Manager
from .challenge_response import (
    generate_challenge,
    is_challenge_valid,
    verify_x509_challenge_signature,
    verify_did_challenge_signature,
    verify_dual_control
)
from .did_binding import (
    verify_certificate_did_binding,
    verify_bidirectional_linkage,
    find_did_in_certificate_san
)
from .lifecycle import (
    register_certificate_did_binding,
    is_certificate_did_binding_valid
)
from .governance import (
    process_csr_with_did_creation,
    load_did_document
)

logger = logging.getLogger(__name__)

# Create Blueprint for X.509 routes
x509_bp = Blueprint('x509', __name__, url_prefix='/x509')

# Initialize X.509 manager
x509_manager = X509Manager()

@x509_bp.route('/challenge', methods=['POST'])
def create_challenge():
    """
    Generate a new challenge for the challenge-response protocol.
    
    Returns:
        JSON with challenge_id, challenge, and expiration
    """
    try:
        # Generate a new challenge
        challenge_id, challenge = generate_challenge()
        
        # Calculate expiration time (5 minutes from now)
        expiration = (datetime.now() + timedelta(minutes=5)).isoformat()
        
        return jsonify({
            'status': 'success',
            'challenge_id': challenge_id,
            'challenge': challenge,
            'expires_at': expiration
        }), 200
    except Exception as e:
        logger.error(f"Error generating challenge: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate challenge',
            'error': str(e)
        }), 500

@x509_bp.route('/verify-control', methods=['POST'])
def verify_control():
    """
    Verify control over both X.509 certificate and DID.
    
    Request body:
    {
        "challenge_id": "...",
        "challenge": "...",
        "x509_signature": "...",
        "did_signature": "...",
        "certificate": "PEM_ENCODED_CERT",
        "did": "did:...",
        "did_public_key": "PEM_ENCODED_PUBLIC_KEY"
    }
    
    Returns:
        Success or error message
    """
    try:
        data = request.json
        
        # Validate required parameters
        required_params = [
            'challenge_id', 'challenge', 'x509_signature', 'did_signature',
            'certificate', 'did', 'did_public_key'
        ]
        for param in required_params:
            if param not in data:
                return jsonify({
                    'status': 'error',
                    'message': f'Missing required parameter: {param}'
                }), 400
        
        # Get and validate challenge
        challenge_id = data['challenge_id']
        challenge = data['challenge']
        if not is_challenge_valid(challenge_id, challenge):
            return jsonify({
                'status': 'error',
                'message': 'Invalid or expired challenge'
            }), 400
        
        # Parse certificate from PEM
        try:
            certificate = x509.load_pem_x509_certificate(
                data['certificate'].encode('utf-8'),
                default_backend()
            )
        except Exception as e:
            logger.error(f"Error parsing certificate: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Invalid certificate format',
                'error': str(e)
            }), 400
        
        # Parse DID public key from PEM
        try:
            did_public_key_pem = data['did_public_key'].encode('utf-8')
            try:
                # Try to load as RSA key first
                did_public_key = serialization.load_pem_public_key(
                    did_public_key_pem,
                    default_backend()
                )
            except Exception:
                # If RSA fails, try EC key format
                did_public_key = serialization.load_pem_public_key(
                    did_public_key_pem,
                    default_backend()
                )
        except Exception as e:
            logger.error(f"Error parsing DID public key: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Invalid DID public key format',
                'error': str(e)
            }), 400
        
        # Verify that the certificate references the provided DID
        did = data['did']
        is_valid, reason = verify_certificate_did_binding(certificate, did)
        if not is_valid:
            return jsonify({
                'status': 'error',
                'message': f'Certificate is not bound to the provided DID: {reason}'
            }), 400
        
        # Verify the signatures
        is_valid, reason = verify_dual_control(
            challenge,
            data['x509_signature'],
            data['did_signature'],
            certificate,
            did_public_key
        )
        
        if not is_valid:
            return jsonify({
                'status': 'error',
                'message': reason
            }), 400
        
        # Register the binding for lifecycle monitoring
        register_certificate_did_binding(certificate, did)
        
        return jsonify({
            'status': 'success',
            'message': 'Control over both X.509 certificate and DID verified successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in verify-control: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Verification failed',
            'error': str(e)
        }), 500

@x509_bp.route('/verify-binding', methods=['POST'])
def verify_binding():
    """
    Verify bidirectional binding between X.509 certificate and DID.
    
    Request body:
    {
        "certificate": "PEM_ENCODED_CERT",
        "did": "did:...",
        "did_document": { ... }  // Optional
    }
    
    Returns:
        Success or error message
    """
    try:
        data = request.json
        
        # Validate required parameters
        if 'certificate' not in data or 'did' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing required parameters: certificate and did'
            }), 400
        
        # Parse certificate from PEM
        try:
            certificate = x509.load_pem_x509_certificate(
                data['certificate'].encode('utf-8'),
                default_backend()
            )
        except Exception as e:
            logger.error(f"Error parsing certificate: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Invalid certificate format',
                'error': str(e)
            }), 400
        
        # Get DID and optional DID document
        did = data['did']
        did_document = data.get('did_document')
        
        # Verify bidirectional linkage
        is_valid, reason = verify_bidirectional_linkage(certificate, did, did_document)
        
        if not is_valid:
            return jsonify({
                'status': 'error',
                'message': f'Binding verification failed: {reason}'
            }), 400
        
        return jsonify({
            'status': 'success',
            'message': reason
        }), 200
        
    except Exception as e:
        logger.error(f"Error in verify-binding: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Binding verification failed',
            'error': str(e)
        }), 500

@x509_bp.route('/create-from-csr', methods=['POST'])
def create_from_csr():
    """
    Create a certificate and DID document from a CSR.
    
    This implements the CA-assisted DID creation from CSR key material
    as described in HAVID §7.3.
    
    Request body:
    {
        "csr": "PEM_ENCODED_CSR",
        "did_method": "web",  // or "key"
        "domain": "example.com",  // Required for did:web
        "validity_days": 365  // Optional
    }
    
    Returns:
        Certificate and DID document information
    """
    try:
        data = request.json
        
        # Validate required parameters
        if 'csr' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing required parameter: csr'
            }), 400
        
        # Get CSR and DID method
        csr_data = data['csr']
        did_method = data.get('did_method', 'web')
        
        # Validate DID method
        if did_method not in ['web', 'key']:
            return jsonify({
                'status': 'error',
                'message': f'Unsupported DID method: {did_method}'
            }), 400
        
        # Check for domain if did:web
        domain = data.get('domain')
        if did_method == 'web' and not domain:
            return jsonify({
                'status': 'error',
                'message': 'Domain is required for did:web method'
            }), 400
        
        # Get CA certificate and key paths from config
        ca_cert_path = current_app.config.get('CA_CERT_PATH')
        ca_key_path = current_app.config.get('CA_KEY_PATH')
        ca_key_password = current_app.config.get('CA_KEY_PASSWORD')
        
        if not ca_cert_path or not ca_key_path:
            return jsonify({
                'status': 'error',
                'message': 'CA certificate or private key path not configured'
            }), 500
        
        # Check if files exist
        if not os.path.exists(ca_cert_path):
            return jsonify({
                'status': 'error',
                'message': 'CA certificate file not found'
            }), 500
        
        if not os.path.exists(ca_key_path):
            return jsonify({
                'status': 'error',
                'message': 'CA private key file not found'
            }), 500
        
        # Get validity period
        validity_days = data.get('validity_days', 365)
        
        # Process CSR with DID creation
        cert, did_document, cert_path, did_doc_path = process_csr_with_did_creation(
            csr_data,
            ca_cert_path,
            ca_key_path,
            ca_key_password,
            did_method,
            domain,
            validity_days
        )
        
        # Get certificate info
        cert_info = x509_manager.get_certificate_info(cert)
        
        # Format response
        return jsonify({
            'status': 'success',
            'message': 'Certificate and DID document created successfully',
            'certificate': {
                'subject': cert_info['subject'],
                'issuer': cert_info['issuer'],
                'serial_number': cert_info['serial_number'],
                'not_before': cert_info['validity']['not_before'].isoformat(),
                'not_after': cert_info['validity']['not_after'].isoformat(),
                'thumbprint': cert_info['thumbprint'],
                'pem': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            },
            'did': did_document['id'],
            'did_document': did_document
        }), 200
        
    except Exception as e:
        logger.error(f"Error creating from CSR: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to create certificate and DID document',
            'error': str(e)
        }), 500

@x509_bp.route('/did-document/<path:did>', methods=['GET'])
def get_did_document(did):
    """
    Get the DID document for a DID.
    
    Args:
        did: DID to get document for
        
    Returns:
        DID document or error message
    """
    try:
        # Normalize DID format
        if not did.startswith('did:'):
            did = f"did:{did}"
        
        # Load DID document
        did_document = load_did_document(did)
        
        if not did_document:
            return jsonify({
                'status': 'error',
                'message': f'DID document not found for DID: {did}'
            }), 404
        
        return jsonify({
            'status': 'success',
            'did': did,
            'did_document': did_document
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving DID document: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve DID document',
            'error': str(e)
        }), 500 