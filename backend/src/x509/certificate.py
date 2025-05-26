"""
X.509 Certificate Loading and Validation

This module provides functions to load, parse, and validate X.509 certificates.
"""

import os
import datetime
import logging
import urllib.request
import tempfile
import hashlib
from typing import List, Dict, Any, Optional, Tuple, Union

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)

# Define common paths and settings
CERT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'instance', 'certs')
CA_DIR = os.path.join(CERT_DIR, 'ca')
CRL_DIR = os.path.join(CERT_DIR, 'crl')  # Directory for cached CRLs

# Ensure certificate directories exist
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(CA_DIR, exist_ok=True)
os.makedirs(CRL_DIR, exist_ok=True)

# Set a reasonable timeout for network operations
NETWORK_TIMEOUT = 10  # seconds

def load_certificate(cert_path: str) -> x509.Certificate:
    """
    Load an X.509 certificate from a file.
    
    Args:
        cert_path: Path to the certificate file (PEM format)
        
    Returns:
        x509.Certificate object
        
    Raises:
        FileNotFoundError: If the certificate file doesn't exist
        ValueError: If the certificate cannot be parsed
    """
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        return x509.load_pem_x509_certificate(cert_data, default_backend())
    except FileNotFoundError:
        logger.error(f"Certificate file not found: {cert_path}")
        raise
    except Exception as e:
        logger.error(f"Error loading certificate: {str(e)}")
        raise ValueError(f"Invalid certificate: {str(e)}")

def get_certificate_info(certificate: x509.Certificate) -> Dict[str, Any]:
    """
    Extract information from an X.509 certificate.
    
    Args:
        certificate: The certificate to extract information from
        
    Returns:
        A dictionary containing certificate information
    """
    # Extract subject information
    subject = {}
    subject_attrs = {
        "common_name": NameOID.COMMON_NAME,
        "organization": NameOID.ORGANIZATION_NAME,
        "organizational_unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "country": NameOID.COUNTRY_NAME,
        "state": NameOID.STATE_OR_PROVINCE_NAME,
        "locality": NameOID.LOCALITY_NAME,
        "email": NameOID.EMAIL_ADDRESS
    }
    
    for attr_name, oid in subject_attrs.items():
        attrs = certificate.subject.get_attributes_for_oid(oid)
        if attrs:
            subject[attr_name] = attrs[0].value
    
    # Extract issuer information
    issuer = {}
    for attr_name, oid in subject_attrs.items():
        attrs = certificate.issuer.get_attributes_for_oid(oid)
        if attrs:
            issuer[attr_name] = attrs[0].value
    
    # Extract validity information
    validity = {
        "not_before": certificate.not_valid_before,
        "not_after": certificate.not_valid_after
    }
    
    # Calculate certificate thumbprint (SHA-256 fingerprint)
    thumbprint = certificate.fingerprint(hashes.SHA256()).hex()
    
    # Format serial number as hexadecimal
    serial_number = format(certificate.serial_number, 'x')
    
    # Convert certificate to PEM format
    try:
        pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    except Exception:
        pem = None
    
    # Return certificate information
    info = {
        "subject": subject,
        "issuer": issuer,
        "validity": validity,
        "serial_number": serial_number,
        "thumbprint": thumbprint
    }
    
    if pem:
        info["pem"] = pem
    
    return info

def _get_name_attribute(name: x509.Name, oid: x509.ObjectIdentifier) -> Optional[str]:
    """Helper function to get a name attribute safely."""
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except (IndexError, ValueError):
        return None

def _get_extension_value(cert: x509.Certificate, extension_type) -> Optional[Any]:
    """Helper function to get an extension value safely."""
    try:
        ext = cert.extensions.get_extension_for_class(extension_type)
        return ext.value
    except x509.ExtensionNotFound:
        return None

def _get_subject_alt_names(cert: x509.Certificate) -> List[str]:
    """Helper function to extract subject alternative names."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return [str(name) for name in ext.value]
    except x509.ExtensionNotFound:
        return []

def get_certificate_thumbprint(certificate: x509.Certificate, algorithm=hashes.SHA256()) -> str:
    """
    Calculate the thumbprint (fingerprint) of a certificate.
    
    Args:
        certificate: The certificate to calculate the thumbprint for
        algorithm: The hash algorithm to use (default: SHA-256)
        
    Returns:
        The certificate thumbprint as a hexadecimal string
    """
    return certificate.fingerprint(algorithm).hex()

def is_certificate_valid(
    certificate: x509.Certificate,
    trusted_cas: Optional[List[x509.Certificate]] = None
) -> Tuple[bool, str]:
    """
    Check if a certificate is valid.
    
    Args:
        certificate: The certificate to check
        trusted_cas: Optional list of trusted CA certificates
        
    Returns:
        Tuple of (is_valid, reason)
    """
    # Check if certificate is expired
    now = datetime.datetime.now(timezone.utc)
    if now < certificate.not_valid_before:
        return False, "Certificate is not yet valid"
    if now > certificate.not_valid_after:
        return False, "Certificate is expired"
    
    # If trusted CAs are provided, check if the certificate is issued by a trusted CA
    if trusted_cas:
        # In a real implementation, this would verify the certificate chain
        # For this sample, we'll just check if the issuer matches any of the trusted CAs
        issuer_dn = certificate.issuer.rfc4514_string()
        
        for ca_cert in trusted_cas:
            ca_dn = ca_cert.subject.rfc4514_string()
            if issuer_dn == ca_dn:
                return True, "Certificate is valid and issued by a trusted CA"
        
        return False, "Certificate is not issued by a trusted CA"
    
    # If no trusted CAs are provided, just check if the certificate is self-signed
    if certificate.issuer.rfc4514_string() == certificate.subject.rfc4514_string():
        return True, "Certificate is valid (self-signed)"
    
    return True, "Certificate is valid (trust chain not verified)"

def load_trusted_cas() -> List[x509.Certificate]:
    """
    Load all trusted CA certificates from the CA directory.
    
    Returns:
        List of trusted CA certificates
    """
    trusted_cas = []
    
    try:
        for filename in os.listdir(CA_DIR):
            if filename.endswith('.pem') or filename.endswith('.crt'):
                ca_path = os.path.join(CA_DIR, filename)
                try:
                    ca_cert = load_certificate(ca_path)
                    trusted_cas.append(ca_cert)
                except Exception as e:
                    logger.warning(f"Failed to load CA certificate {filename}: {str(e)}")
    except FileNotFoundError:
        logger.warning(f"CA directory not found: {CA_DIR}")
    
    return trusted_cas

def save_certificate(certificate: x509.Certificate, file_path: str) -> bool:
    """
    Save an X.509 certificate to a file in PEM format.
    
    Args:
        certificate: The certificate to save
        file_path: The path to save the certificate to
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        
        # Write certificate to file in PEM format
        with open(file_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        return True
    except Exception as e:
        logger.error(f"Error saving certificate to {file_path}: {str(e)}")
        return False

def fetch_crl(url: str) -> Optional[x509.CertificateRevocationList]:
    """
    Fetch a CRL from the given URL.
    
    Args:
        url: URL of the CRL
        
    Returns:
        CRL object or None if fetching fails
    """
    crl_filename = os.path.join(CRL_DIR, hashlib.md5(url.encode()).hexdigest() + ".crl")
    
    try:
        # Check if we have a cached copy first
        if os.path.exists(crl_filename):
            crl_age = datetime.datetime.now() - datetime.datetime.fromtimestamp(os.path.getmtime(crl_filename))
            # If CRL is less than 1 day old, use it
            if crl_age < datetime.timedelta(days=1):
                with open(crl_filename, 'rb') as f:
                    crl_data = f.read()
                return x509.load_der_x509_crl(crl_data, default_backend())
        
        # Otherwise fetch a new copy
        logger.info(f"Fetching CRL from {url}")
        
        # Create a temporary file for downloading
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            with urllib.request.urlopen(url, timeout=NETWORK_TIMEOUT) as response:
                crl_data = response.read()
                temp_file.write(crl_data)
        
        # Try to parse as DER format first
        try:
            crl = x509.load_der_x509_crl(crl_data, default_backend())
        except ValueError:
            # If DER fails, try PEM format
            try:
                crl = x509.load_pem_x509_crl(crl_data, default_backend())
            except ValueError as e:
                logger.error(f"Failed to parse CRL: {e}")
                os.unlink(temp_file.name)
                return None
        
        # If parsing succeeded, save to cache
        os.rename(temp_file.name, crl_filename)
        return crl
    
    except Exception as e:
        logger.error(f"Error fetching CRL from {url}: {e}")
        return None

def check_cert_against_crl(cert: x509.Certificate, crl: x509.CertificateRevocationList) -> Tuple[bool, str]:
    """
    Check if a certificate is in a CRL.
    
    Args:
        cert: Certificate to check
        crl: CRL to check against
        
    Returns:
        Tuple of (is_revoked, reason)
    """
    # Check if CRL is valid
    now = datetime.datetime.now()
    if hasattr(crl, 'next_update') and crl.next_update and now > crl.next_update:
        logger.warning(f"CRL has expired, next update was {crl.next_update}")
        return False, "CRL has expired"

    # Extract the revoked certificates
    for revoked_cert in crl:
        if revoked_cert.serial_number == cert.serial_number:
            reason = "Unknown reason"
            for extension in revoked_cert.extensions:
                if extension.oid.dotted_string == "2.5.29.21":  # Reason code
                    reason = str(extension.value)
            return True, f"Certificate is revoked: {reason}"
    
    return False, "Certificate is not in CRL"

def generate_certificate_chain(subject_name: str, did: str = None) -> Tuple[List[x509.Certificate], List[Any]]:
    """
    Generate a certificate chain with a root CA, intermediate CA, and end-entity certificate.
    
    Args:
        subject_name: The subject name for the end-entity certificate
        did: Optional DID to include in the end-entity certificate's SubjectAlternativeName
    
    Returns:
        Tuple of (certificates, private_keys) where certificates are in order [end_entity, intermediate, root]
    """
    # Import here to avoid circular imports
    from cryptography.x509 import NameAttribute, Name, CertificateBuilder, SubjectAlternativeName, UniformResourceIdentifier 
    from cryptography.hazmat.primitives.asymmetric import rsa
    from .did_binding import add_did_to_certificate_san
    
    # Generate key pairs
    root_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    intermediate_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    end_entity_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create root CA certificate
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Root-CA")
    ])
    
    root_cert = x509.CertificateBuilder().subject_name(
        root_name
    ).issuer_name(
        root_name  # Self-signed
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).sign(root_key, hashes.SHA256())
    
    # Create intermediate CA certificate
    intermediate_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate-CA")
    ])
    
    intermediate_cert = x509.CertificateBuilder().subject_name(
        intermediate_name
    ).issuer_name(
        root_name  # Issued by root
    ).public_key(
        intermediate_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825)  # 5 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),  # Can only issue end-entity certs
        critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).sign(root_key, hashes.SHA256())
    
    # Create end-entity certificate
    end_entity_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name)
    ])
    
    end_entity_builder = x509.CertificateBuilder().subject_name(
        end_entity_name
    ).issuer_name(
        intermediate_name  # Issued by intermediate
    ).public_key(
        end_entity_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)  # 1 year
    )
    
    # Add DID to SubjectAlternativeName if provided
    if did:
        end_entity_builder = add_did_to_certificate_san(end_entity_builder, did)
    
    # Add extensions
    end_entity_builder = end_entity_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).add_extension(
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
    
    # Sign the end-entity certificate with the intermediate key
    end_entity_cert = end_entity_builder.sign(intermediate_key, hashes.SHA256())
    
    # Return the certificates and private keys
    # Note: The certificates are returned in order [end_entity, intermediate, root]
    certificates = [end_entity_cert, intermediate_cert, root_cert]
    private_keys = [end_entity_key, intermediate_key, root_key]
    
    return certificates, private_keys 