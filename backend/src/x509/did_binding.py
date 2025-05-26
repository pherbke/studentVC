"""
Functions for binding DIDs to X.509 certificates.

This module provides functions for establishing and verifying the bidirectional
linkage between X.509 certificates and DIDs, as specified in the HAVID 
(High Assurance Verifiable Identifiers) specification.
"""

import json
import base64
import logging
import hashlib
from typing import Dict, Any, Optional, List, Tuple, Union

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ObjectIdentifier, UniformResourceIdentifier, Certificate, Extension, ExtensionNotFound
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from .certificate import get_certificate_info, get_certificate_thumbprint

logger = logging.getLogger(__name__)

# Define the OID for the DID Subject Alternative Name
# Using Private Enterprise Number namespace for example
DID_SAN_OID = ObjectIdentifier("1.2.840.113556.1.8.1")

def create_did_web_from_certificate(cert: x509.Certificate, domain: str, path: Optional[str] = None) -> str:
    """
    Create a did:web identifier from an X.509 certificate.
    
    Args:
        cert: X.509 certificate
        domain: Domain name for the did:web
        path: Optional path component
        
    Returns:
        did:web identifier string
    """
    # Extract subject info (CommonName or SubjectAltName)
    common_name = None
    try:
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        # If CommonName is not available, try to use DNS SAN if available
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for san in san_ext.value:
                if isinstance(san, x509.DNSName):
                    common_name = san.value
                    break
        except x509.ExtensionNotFound:
            pass
    
    # Use domain if no suitable identifier found in certificate
    identifier = common_name or domain
    
    # Normalize domain
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
        # Remove leading slash if present
        if path.startswith('/'):
            path = path[1:]
        # Split path and encode each component
        parts.extend([p for p in path.split('/') if p])
    
    encoded_parts = [p.replace(':', '%3A').replace('%', '%25') for p in parts]
    did = f"did:web:{':'.join(encoded_parts)}"
    
    return did

def create_did_key_from_certificate(cert: x509.Certificate) -> str:
    """
    Create a did:key identifier from an X.509 certificate's public key.
    
    Args:
        cert: X.509 certificate
        
    Returns:
        did:key identifier string or None if not supported
        
    Note:
        This is a simplified implementation and may not handle all key types.
        Only supports RSA and EC keys currently.
    """
    public_key = cert.public_key()
    key_type = type(public_key).__name__
    
    if key_type == 'RSAPublicKey':
        # For RSA keys, use a key fingerprint approach
        key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_hash = hashlib.sha256(key_der).digest()
        multicodec_prefix = b'\x00\x24'  # RSA prefix
        multibase_encoded = base64.b32encode(multicodec_prefix + key_hash).decode('ascii')
        return f"did:key:z{multibase_encoded.lower().rstrip('=')}"
    
    elif key_type == 'EllipticCurvePublicKey':
        # For EC keys, try to determine the curve
        key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        curve_name = public_key.curve.name
        
        # Simplified prefix determination (expand for more curves)
        if curve_name == 'secp256k1':
            multicodec_prefix = b'\xe7\x01'
        elif curve_name == 'secp256r1':  # P-256
            multicodec_prefix = b'\x80\x24'
        elif curve_name == 'ed25519':
            multicodec_prefix = b'\xed\x01'
        else:
            logger.warning(f"Unsupported curve for did:key: {curve_name}")
            return None
        
        key_hash = hashlib.sha256(key_der).digest()
        multibase_encoded = base64.b32encode(multicodec_prefix + key_hash).decode('ascii')
        return f"did:key:z{multibase_encoded.lower().rstrip('=')}"
    
    else:
        logger.warning(f"Unsupported key type for did:key: {key_type}")
        return None

def create_certificate_metadata_for_did(
    cert: x509.Certificate, 
    did: str, 
    include_pem: bool = False
) -> Dict[str, Any]:
    """
    Create metadata linking a certificate to a DID.
    
    Args:
        cert: X.509 certificate
        did: DID identifier
        include_pem: Whether to include the full certificate PEM
        
    Returns:
        Dictionary with certificate metadata
    """
    cert_info = get_certificate_info(cert)
    
    metadata = {
        "did": did,
        "certificate": {
            "subject": cert_info['subject'],
            "issuer": cert_info['issuer'],
            "serialNumber": cert_info['serial_number'],
            "validity": {
                "notBefore": cert_info['validity']['not_before'].isoformat(),
                "notAfter": cert_info['validity']['not_after'].isoformat()
            },
            "thumbprint": cert_info['thumbprint'],
            "thumbprintAlgorithm": "SHA-256"
        }
    }
    
    if include_pem:
        metadata["certificate"]["pem"] = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    return metadata

def verify_certificate_did_binding(cert: x509.Certificate, did: str) -> Tuple[bool, str]:
    """
    Verify if a certificate is correctly bound to a DID.
    
    Args:
        cert: X.509 certificate
        did: DID to verify
        
    Returns:
        Tuple of (is_valid, reason)
    """
    if did.startswith("did:web:"):
        # For did:web, validate domain against certificate's CN or SAN
        domain_parts = did[9:].split(':')  # Remove "did:web:" prefix
        domain = domain_parts[0].replace('%3A', ':').replace('%25', '%')
        
        # Check if domain matches certificate's CN or SAN
        common_name = None
        alt_names = []
        
        try:
            common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, ValueError):
            pass
        
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for san in san_ext.value:
                if isinstance(san, x509.DNSName):
                    alt_names.append(san.value)
        except x509.ExtensionNotFound:
            pass
        
        # Check domain against CN and SANs
        if domain == common_name or domain in alt_names:
            return True, "Certificate domain matches DID"
        
        return False, "Certificate domain does not match DID"
    
    elif did.startswith("did:key:"):
        # For did:key, regenerate the DID from the certificate and compare
        generated_did = create_did_key_from_certificate(cert)
        
        if generated_did and generated_did == did:
            return True, "Certificate public key matches DID"
        
        return False, "Certificate public key does not match DID"
    
    elif did.startswith("did:shac:"):
        # For did:shac, we would need a custom implementation based on your SHAC spec
        # This is a placeholder - implement according to your SHAC specs
        logger.warning("did:shac verification not fully implemented")
        return False, "did:shac verification not implemented"
    
    return False, f"Unsupported DID method: {did.split(':')[1] if ':' in did else 'unknown'}"

def add_x509_verification_method_to_did_document(
    did_document: Dict[str, Any],
    certificate: x509.Certificate,
    verification_method_id: str,
    ca_certificates: List[x509.Certificate] = None
) -> Dict[str, Any]:
    """
    Add an X.509 certificate as a verification method to a DID document.
    
    Args:
        did_document: The DID document to modify
        certificate: The X.509 certificate to add
        verification_method_id: The ID to assign to the verification method
        ca_certificates: Optional list of CA certificates to include in the chain
        
    Returns:
        The updated DID document
    """
    # Make a copy of the DID document to avoid modifying the original
    updated_did_document = did_document.copy()
    
    # Ensure the X.509 context is included
    if "@context" not in updated_did_document:
        updated_did_document["@context"] = []
    
    if isinstance(updated_did_document["@context"], list):
        # Add the X.509 context if not already present
        if "https://w3id.org/security/suites/x509-2021/v1" not in updated_did_document["@context"]:
            updated_did_document["@context"].append("https://w3id.org/security/suites/x509-2021/v1")
        
        # Add the x509CertificateChain context if not already present
        x509_chain_context_found = False
        for ctx in updated_did_document["@context"]:
            if isinstance(ctx, dict) and "x509CertificateChain" in ctx:
                x509_chain_context_found = True
                break
        
        if not x509_chain_context_found:
            updated_did_document["@context"].append({
                "x509CertificateChain": "https://w3id.org/security#x509CertificateChain"
            })
    
    # Ensure verificationMethod array exists
    if "verificationMethod" not in updated_did_document:
        updated_did_document["verificationMethod"] = []
    
    # Convert certificate to base64-encoded DER format
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    cert_b64 = base64.b64encode(cert_der).decode('ascii')
    
    # Create the certificate chain array
    cert_chain = [cert_b64]
    
    # Add CA certificates to the chain if provided
    if ca_certificates:
        for ca_cert in ca_certificates:
            ca_cert_der = ca_cert.public_bytes(serialization.Encoding.DER)
            ca_cert_b64 = base64.b64encode(ca_cert_der).decode('ascii')
            cert_chain.append(ca_cert_b64)
    
    # Extract the public key from the certificate
    public_key = certificate.public_key()
    
    # Get the key type
    key_type = None
    if isinstance(public_key, rsa.RSAPublicKey):
        key_type = "RsaVerificationKey2018"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        # Check the curve
        if isinstance(public_key.curve, ec.SECP256R1):
            key_type = "EcdsaSecp256r1VerificationKey2019"
        elif isinstance(public_key.curve, ec.SECP384R1):
            key_type = "EcdsaSecp384r1VerificationKey2019"
        else:
            key_type = "EcdsaVerificationKey2019"
    else:
        key_type = "X509VerificationKey2018"
    
    # Convert the public key to multibase format
    key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_b64 = base64.b64encode(key_der).decode('ascii')
    multibase_key = f"z{key_b64}"  # Simple multibase encoding with 'z' prefix
    
    # Create the verification method
    verification_method = {
        "id": verification_method_id,
        "type": key_type,
        "controller": updated_did_document["id"],
        "publicKeyMultibase": multibase_key,
        "x509CertificateChain": cert_chain
    }
    
    # Add the verification method to the DID document
    updated_did_document["verificationMethod"].append(verification_method)
    
    return updated_did_document

# New functions for HAVID compliance

def add_did_to_certificate_san(
    builder: x509.CertificateBuilder, 
    did: str
) -> x509.CertificateBuilder:
    """
    Add a DID to a certificate's SubjectAlternativeName extension.
    
    Args:
        builder: The certificate builder to modify
        did: The DID to add to the certificate
        
    Returns:
        The updated certificate builder
    """
    # Check if SAN extension already exists
    san_oid = ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    existing_san = None
    
    # Extensions in the builder are stored as a list of extension objects
    for extension in builder._extensions:
        if extension.oid == san_oid:
            existing_san = extension
            break
    
    if existing_san:
        # Get existing values
        existing_san_value = existing_san.value
        existing_names = existing_san_value.get_values_for_type(x509.UniformResourceIdentifier)
        
        # Create a new SAN with existing names plus the DID
        san = x509.SubjectAlternativeName(
            existing_names + [x509.UniformResourceIdentifier(did)]
        )
        
        # Remove the existing SAN extension by creating a new extensions list
        new_extensions = []
        for extension in builder._extensions:
            if extension.oid != san_oid:
                new_extensions.append(extension)
        builder._extensions = new_extensions
    else:
        # If no SAN exists, create a new one with just the DID
        san = x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(did)
        ])
    
    # Add the new SAN extension
    builder = builder.add_extension(
        san,
        critical=False
    )
    
    return builder

def find_did_in_certificate_san(certificate: Certificate) -> Optional[str]:
    """
    Find a DID in a certificate's SubjectAlternativeName extension.
    
    Args:
        certificate: The certificate to search
        
    Returns:
        The DID if found, None otherwise
    """
    try:
        san = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        
        # Find the first URI that starts with "did:"
        for uri in uris:
            if uri.startswith("did:"):
                return uri
                
    except ExtensionNotFound:
        return None
    
    return None

def extract_did_from_certificate(certificate: Certificate) -> Optional[str]:
    """
    Extract a DID from a certificate. Alias for find_did_in_certificate_san.
    
    Args:
        certificate: The certificate to search
        
    Returns:
        The DID if found, None otherwise
    """
    return find_did_in_certificate_san(certificate)

def verify_certificate_did_binding(
    certificate: Certificate, 
    did: str
) -> bool:
    """
    Verify that a certificate contains a specific DID in its SubjectAlternativeName.
    
    Args:
        certificate: The certificate to check
        did: The DID to verify
        
    Returns:
        True if the certificate contains the DID, False otherwise
    """
    found_did = find_did_in_certificate_san(certificate)
    return found_did == did

def find_x509_verification_methods(did_document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Find X.509 verification methods in a DID document.
    
    Args:
        did_document: The DID document to search
        
    Returns:
        A list of X.509 verification methods
    """
    if "verificationMethod" not in did_document:
        return []
    
    x509_methods = []
    
    for method in did_document["verificationMethod"]:
        # Check for different X.509-related verification method types
        method_type = method.get("type", "")
        
        # Check for various X.509 certificate types or presence of X.509 certificate chain
        if (method_type in ["X509Certificate2021", "X509Certificate2018", "X509VerificationKey2018"] or 
            "certificateChain" in method or 
            "x509CertificateChain" in method):
            x509_methods.append(method)
    
    return x509_methods

def verify_bidirectional_linkage(
    certificate: Certificate, 
    did_document: Dict[str, Any]
) -> bool:
    """
    Verify the bidirectional linkage between a certificate and a DID document.
    
    The linkage is valid if:
    1. The certificate contains the DID in its SubjectAlternativeName
    2. The DID document contains the certificate as a verification method
    
    Args:
        certificate: The certificate to check
        did_document: The DID document to check
        
    Returns:
        True if the linkage is valid, False otherwise
    """
    # Check if the certificate contains the DID
    found_did = find_did_in_certificate_san(certificate)
    if not found_did or found_did != did_document.get("id"):
        return False
    
    # Check if the DID document contains the certificate
    x509_methods = find_x509_verification_methods(did_document)
    if not x509_methods:
        return False
    
    # Convert certificate to various formats for comparison
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    cert_b64 = base64.b64encode(cert_der).decode('ascii')
    cert_fingerprint = certificate.fingerprint(certificate.signature_hash_algorithm).hex()
    
    # Check if any of the verification methods contains this certificate
    for method in x509_methods:
        # Check for certificateChain (PEM format)
        if "certificateChain" in method:
            chain_data = method["certificateChain"]
            
            if isinstance(chain_data, str) and chain_data == cert_pem:
                return True
            
            # Try to parse as base64-encoded DER if it's not PEM
            try:
                if isinstance(chain_data, str) and not chain_data.startswith("-----BEGIN CERTIFICATE-----"):
                    if chain_data == cert_b64:
                        return True
            except:
                pass
        
        # Check for x509CertificateChain (array of base64-encoded DER)
        if "x509CertificateChain" in method:
            chain_data = method["x509CertificateChain"]
            
            if isinstance(chain_data, list) and chain_data:
                # Check if the end-entity certificate (first in the chain) matches
                if chain_data[0] == cert_b64:
                    return True
            
            # Handle string format for backward compatibility
            elif isinstance(chain_data, str) and chain_data == cert_b64:
                return True
    
    return False

def create_did_from_cert(
    certificate: Certificate, 
    method: str = "web", 
    domain: Optional[str] = None
) -> str:
    """
    Create a DID from a certificate's public key.
    
    Args:
        certificate: The certificate to use
        method: The DID method (web, key, etc.)
        domain: The domain to use for did:web (required if method is 'web')
        
    Returns:
        The created DID
    """
    if method == "web":
        if not domain:
            raise ValueError("Domain is required for did:web method")
        
        # Create a did:web identifier using the domain and a fingerprint of the certificate
        fingerprint = certificate.fingerprint(algorithm=certificate.signature_hash_algorithm).hex()
        return f"did:web:{domain}:cert:{fingerprint[:8]}"
    
    elif method == "key":
        # Create a did:key identifier from the public key
        public_key = certificate.public_key()
        key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Create a simple multibase encoding (in a real implementation, 
        # this would use proper multibase/multicodec encoding)
        key_b64 = base64.b64encode(key_bytes).decode('ascii')[:16]
        
        # Create the did:key identifier
        return f"did:key:z{key_b64}"
    
    else:
        raise ValueError(f"Unsupported DID method: {method}") 