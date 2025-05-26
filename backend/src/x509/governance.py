"""
X.509 Certificate Governance

This module implements CA-assisted DID creation from Certificate Signing Request (CSR)
key material as specified in HAVID §7.3.

This enables a Certificate Authority to create a corresponding DID document using the 
same keypair as the certificate during X.509 issuance. The certificate references 
the DID in SubjectAlternativeName, and the DID document includes the certificate in 
verificationMethod.
"""

import os
import json
import uuid
import base64
import logging
from typing import Dict, Any, Optional, Tuple, List, Union
from datetime import datetime

from cryptography import x509
from cryptography.x509 import CertificateSigningRequest, NameOID, SubjectAlternativeName
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils

from .certificate import get_certificate_info, save_certificate
from .did_binding import (
    add_did_to_certificate_san,
    find_did_in_certificate_san,
    add_x509_verification_method_to_did_document,
    create_did_web_from_certificate,
    create_did_key_from_certificate
)

logger = logging.getLogger(__name__)

# Directory for storing generated DID documents
DID_DOCUMENT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    'instance',
    'did_documents'
)

def ensure_did_document_dir():
    """Ensure the DID document directory exists."""
    os.makedirs(DID_DOCUMENT_DIR, exist_ok=True)

def extract_public_key_from_csr(csr: CertificateSigningRequest) -> Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]:
    """
    Extract the public key from a Certificate Signing Request.
    
    Args:
        csr: Certificate Signing Request
        
    Returns:
        Public key object
    """
    return csr.public_key()

def create_did_from_csr(
    csr: CertificateSigningRequest,
    did_method: str = 'web',
    domain: Optional[str] = None,
    path: Optional[str] = None
) -> str:
    """
    Create a DID from a Certificate Signing Request.
    
    Args:
        csr: Certificate Signing Request
        did_method: DID method to use ('web' or 'key')
        domain: Domain for did:web (required for did:web)
        path: Optional path for did:web
        
    Returns:
        DID string
    """
    # For a CSR, we need to create a temporary certificate-like structure
    # to use with our existing DID creation functions
    public_key = extract_public_key_from_csr(csr)
    
    if did_method == 'key':
        # For did:key, we can generate directly from the public key
        key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_hash = hashes.Hash(hashes.SHA256())
        key_hash.update(key_der)
        key_digest = key_hash.finalize()
        
        # Create multicodec prefix based on key type
        if isinstance(public_key, rsa.RSAPublicKey):
            multicodec_prefix = b'\x00\x24'  # RSA prefix
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            curve_name = public_key.curve.name
            if curve_name == 'secp256k1':
                multicodec_prefix = b'\xe7\x01'
            elif curve_name == 'secp256r1':  # P-256
                multicodec_prefix = b'\x80\x24'
            elif curve_name == 'ed25519':
                multicodec_prefix = b'\xed\x01'
            else:
                raise ValueError(f"Unsupported curve for did:key: {curve_name}")
        else:
            raise ValueError(f"Unsupported key type for did:key: {type(public_key).__name__}")
        
        # Encode as multibase
        multibase_encoded = base64.b32encode(multicodec_prefix + key_digest).decode('ascii')
        return f"did:key:z{multibase_encoded.lower().rstrip('=')}"
    
    elif did_method == 'web':
        if not domain:
            raise ValueError("Domain is required for did:web")
        
        # For did:web, extract information from the CSR subject
        try:
            common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, ValueError):
            # Use domain if no CN available
            common_name = domain
        
        # Normalize domain
        identifier = common_name or domain
        if identifier.startswith('https://'):
            identifier = identifier[8:]
        elif identifier.startswith('http://'):
            identifier = identifier[7:]
        
        # Remove trailing slash if present
        if identifier.endswith('/'):
            identifier = identifier[:-1]
        
        # Encode as per did:web spec
        parts = [identifier]
        if path:
            if path.startswith('/'):
                path = path[1:]
            parts.extend([p for p in path.split('/') if p])
        
        encoded_parts = [p.replace(':', '%3A').replace('%', '%25') for p in parts]
        did = f"did:web:{':'.join(encoded_parts)}"
        return did
    
    else:
        raise ValueError(f"Unsupported DID method: {did_method}")

def create_certificate_with_did(
    csr: CertificateSigningRequest,
    ca_cert: x509.Certificate,
    ca_private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    did: str,
    serial_number: Optional[int] = None,
    validity_days: int = 365
) -> x509.Certificate:
    """
    Create a certificate from a CSR with DID embedded in SubjectAltName.
    
    Args:
        csr: Certificate Signing Request
        ca_cert: CA certificate for signing
        ca_private_key: CA private key
        did: DID to include in the certificate
        serial_number: Optional serial number (random if not provided)
        validity_days: Validity period in days
        
    Returns:
        X.509 certificate with DID in SubjectAltName
    """
    from datetime import datetime, timedelta
    import os
    
    # Use CSR subject
    subject = csr.subject
    
    # Generate serial number if not provided
    if serial_number is None:
        serial_number = int.from_bytes(os.urandom(16), byteorder='big') & 0xFFFFFFFFFFFFFFFF
    
    # Determine validity period
    now = datetime.utcnow()
    valid_from = now
    valid_to = now + timedelta(days=validity_days)
    
    # Start building the certificate
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        serial_number
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    )
    
    # Add the DID to SubjectAlternativeName
    builder = add_did_to_certificate_san(builder, did)
    
    # Add basic constraints extension
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    
    # Add key usage extension
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    
    # Add extended key usage
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION
        ]),
        critical=False
    )
    
    # Create and sign the certificate
    if isinstance(ca_private_key, rsa.RSAPrivateKey):
        cert = builder.sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256()
        )
    elif isinstance(ca_private_key, ec.EllipticCurvePrivateKey):
        cert = builder.sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256()
        )
    else:
        raise ValueError(f"Unsupported private key type: {type(ca_private_key).__name__}")
    
    return cert

def create_did_document_from_csr(
    csr: CertificateSigningRequest,
    did: str
) -> Dict[str, Any]:
    """
    Create a DID document from a CSR.
    
    Args:
        csr: Certificate Signing Request
        did: DID for the document
        
    Returns:
        DID document as a dictionary
    """
    public_key = extract_public_key_from_csr(csr)
    
    # Generate verification method ID
    verification_id = f"{did}#keys-1"
    
    # Create basic DID document
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": did,
        "verificationMethod": [],
        "authentication": [],
        "assertionMethod": []
    }
    
    # Add verification method based on key type
    if isinstance(public_key, rsa.RSAPublicKey):
        jwk = {
            "kty": "RSA",
            "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(
                (public_key.public_numbers().e.bit_length() + 7) // 8, 'big'
            )).decode('utf-8').rstrip('='),
            "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(
                (public_key.public_numbers().n.bit_length() + 7) // 8, 'big'
            )).decode('utf-8').rstrip('=')
        }
        
        verification_method = {
            "id": verification_id,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": jwk
        }
        
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        # For EC keys, we need to determine the curve
        curve = public_key.curve.name
        if curve == 'secp256r1':  # P-256
            crv = "P-256"
        elif curve == 'secp384r1':  # P-384
            crv = "P-384"
        elif curve == 'secp521r1':  # P-521
            crv = "P-521"
        elif curve == 'secp256k1':
            crv = "secp256k1"
        else:
            raise ValueError(f"Unsupported curve: {curve}")
        
        # Extract x and y coordinates
        point = public_key.public_numbers()
        x = point.x.to_bytes((point.curve.key_size + 7) // 8, byteorder='big')
        y = point.y.to_bytes((point.curve.key_size + 7) // 8, byteorder='big')
        
        jwk = {
            "kty": "EC",
            "crv": crv,
            "x": base64.urlsafe_b64encode(x).decode('utf-8').rstrip('='),
            "y": base64.urlsafe_b64encode(y).decode('utf-8').rstrip('=')
        }
        
        verification_method = {
            "id": verification_id,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": jwk
        }
    
    else:
        raise ValueError(f"Unsupported key type: {type(public_key).__name__}")
    
    # Add verification method to the document
    did_document["verificationMethod"].append(verification_method)
    did_document["authentication"].append(verification_id)
    did_document["assertionMethod"].append(verification_id)
    
    return did_document

def add_certificate_to_did_document(
    did_document: Dict[str, Any],
    cert: x509.Certificate
) -> Dict[str, Any]:
    """
    Add a certificate as a verification method to a DID document.
    
    Args:
        did_document: DID document to update
        cert: X.509 certificate to add
        
    Returns:
        Updated DID document
    """
    did = did_document["id"]
    verification_method_id = f"{did}#cert-1"
    
    return add_x509_verification_method_to_did_document(
        did_document,
        cert,
        verification_method_id
    )

def save_did_document(did_document: Dict[str, Any]) -> str:
    """
    Save a DID document to the filesystem.
    
    Args:
        did_document: DID document to save
        
    Returns:
        Path to the saved document
    """
    ensure_did_document_dir()
    
    did = did_document["id"]
    # Sanitize DID for filename
    filename = did.replace(":", "_").replace("/", "_") + ".json"
    filepath = os.path.join(DID_DOCUMENT_DIR, filename)
    
    with open(filepath, 'w') as f:
        json.dump(did_document, f, indent=2)
    
    logger.info(f"Saved DID document for {did} to {filepath}")
    return filepath

def process_csr_with_did_creation(
    csr_data: str,
    ca_cert_path: str,
    ca_key_path: str,
    ca_key_password: Optional[str] = None,
    did_method: str = 'web',
    domain: Optional[str] = None,
    validity_days: int = 365
) -> Tuple[x509.Certificate, Dict[str, Any], str, str]:
    """
    Process a CSR with DID creation, creating both a certificate with the DID in SAN
    and a DID document with the certificate as a verification method.
    
    Args:
        csr_data: PEM-encoded CSR data
        ca_cert_path: Path to CA certificate
        ca_key_path: Path to CA private key
        ca_key_password: Optional password for CA private key
        did_method: DID method to use ('web' or 'key')
        domain: Domain for did:web (required for did:web)
        validity_days: Validity period in days
        
    Returns:
        Tuple of (certificate, did_document, cert_path, did_doc_path)
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    
    # Load CSR
    csr = x509.load_pem_x509_csr(csr_data.encode('utf-8'))
    
    # Load CA certificate
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    # Load CA private key
    with open(ca_key_path, 'rb') as f:
        ca_key_data = f.read()
        
    if ca_key_password:
        ca_private_key = load_pem_private_key(
            ca_key_data,
            password=ca_key_password.encode('utf-8')
        )
    else:
        ca_private_key = load_pem_private_key(
            ca_key_data,
            password=None
        )
    
    # Create DID from CSR
    did = create_did_from_csr(csr, did_method, domain)
    
    # Create certificate with DID in SAN
    cert = create_certificate_with_did(
        csr,
        ca_cert,
        ca_private_key,
        did,
        validity_days=validity_days
    )
    
    # Create DID document
    did_document = create_did_document_from_csr(csr, did)
    
    # Add certificate to DID document
    did_document = add_certificate_to_did_document(did_document, cert)
    
    # Save certificate
    subject_cn = None
    try:
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        subject_cn = did
    
    cert_filename = f"{subject_cn.replace(':', '_').replace('.', '_').replace('/', '_')}_{uuid.uuid4().hex[:8]}.pem"
    cert_path = save_certificate(cert, cert_filename)
    
    # Save DID document
    did_doc_path = save_did_document(did_document)
    
    return cert, did_document, cert_path, did_doc_path

def get_did_document_path(did: str) -> str:
    """
    Get the path to a DID document for a given DID.
    
    Args:
        did: DID to lookup
        
    Returns:
        Path to the DID document
    """
    ensure_did_document_dir()
    
    # Sanitize DID for filename
    filename = did.replace(":", "_").replace("/", "_") + ".json"
    return os.path.join(DID_DOCUMENT_DIR, filename)

def load_did_document(did: str) -> Optional[Dict[str, Any]]:
    """
    Load a DID document from the filesystem.
    
    Args:
        did: DID to load document for
        
    Returns:
        DID document as a dictionary or None if not found
    """
    path = get_did_document_path(did)
    
    if not os.path.exists(path):
        return None
    
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading DID document for {did}: {str(e)}")
        return None 