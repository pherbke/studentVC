"""
X.509 Certificate Trust Chain Verification

This module provides functions to verify X.509 certificate trust chains,
with specific support for GÉANT and DFN CA trust anchors.
"""

import os
import logging
import functools
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtensionOID

from .certificate import load_certificate, load_trusted_cas

logger = logging.getLogger(__name__)

# Define Trust Anchors
TRUST_ANCHORS = {
    'GEANT': {
        'name': 'GÉANT TCS',
        'issuer_cn': 'GEANT Trusted Certificate Service',
        'root_cert_filename': 'geant-tcs-root.pem',
    },
    'DFN': {
        'name': 'DFN-PKI',
        'issuer_cn': 'DFN-Verein Certification Authority',
        'root_cert_filename': 'dfn-ca-root.pem',
    }
}

# Cache for certificate validation results
# Structure: {cert_thumbprint: (is_trusted, reason, timestamp)}
_validation_cache = {}
# Cache expiration time (in seconds)
CACHE_EXPIRATION = 3600  # 1 hour

def _get_cert_cache_key(cert: x509.Certificate) -> str:
    """Generate a cache key for a certificate."""
    from .certificate import get_certificate_thumbprint
    return get_certificate_thumbprint(cert)

def _is_cache_valid(timestamp: datetime) -> bool:
    """Check if a cached entry is still valid."""
    return (datetime.now() - timestamp) < timedelta(seconds=CACHE_EXPIRATION)

def _cache_validation_result(cert: x509.Certificate, is_trusted: bool, reason: str) -> None:
    """Cache a validation result."""
    cache_key = _get_cert_cache_key(cert)
    _validation_cache[cache_key] = (is_trusted, reason, datetime.now())

def _get_cached_validation(cert: x509.Certificate) -> Optional[Tuple[bool, str]]:
    """Get a cached validation result if available and valid."""
    cache_key = _get_cert_cache_key(cert)
    if cache_key in _validation_cache:
        is_trusted, reason, timestamp = _validation_cache[cache_key]
        if _is_cache_valid(timestamp):
            logger.debug(f"Using cached validation result for {cache_key}")
            return is_trusted, reason
    return None

def verify_certificate_chain(cert: x509.Certificate, trusted_cas: List[x509.Certificate]) -> Tuple[bool, str]:
    """
    Verify a certificate against a list of trusted CAs.
    
    Args:
        cert: Certificate to verify
        trusted_cas: List of trusted CA certificates
        
    Returns:
        Tuple of (is_trusted, reason)
    """
    # Check cache first
    cached_result = _get_cached_validation(cert)
    if cached_result:
        return cached_result
    
    # Check if certificate has already expired
    now = datetime.now()
    if cert.not_valid_before > now or cert.not_valid_after < now:
        result = (False, "Certificate is not valid at current time")
        _cache_validation_result(cert, *result)
        return result
    
    # If no trusted CAs provided, we can't verify the chain
    if not trusted_cas:
        result = (False, "No trusted CA certificates provided")
        _cache_validation_result(cert, *result)
        return result
    
    # First, check if the certificate is directly issued by one of our trusted CAs
    for ca_cert in trusted_cas:
        if cert.issuer == ca_cert.subject:
            # Now verify the signature
            try:
                # Get the CA's public key
                public_key = ca_cert.public_key()
                
                # Verify the certificate's signature
                if _verify_certificate_signature(cert, public_key):
                    # Check certificate revocation if CRL or OCSP info available
                    revoked, reason = _check_revocation_status(cert)
                    if revoked:
                        result = (False, f"Certificate is revoked: {reason}")
                        _cache_validation_result(cert, *result)
                        return result
                    
                    result = (True, f"Certificate is trusted (issued by {ca_cert.subject.rfc4514_string()})")
                    _cache_validation_result(cert, *result)
                    return result
            except Exception as e:
                logger.warning(f"Error verifying certificate signature: {str(e)}")
    
    # If we got here, we need to build and verify the certificate chain
    # This is a simplified implementation - in production, you'd use a more robust solution
    
    # Try to build a chain leading to one of our trusted CAs
    chain = [cert]
    current_cert = cert
    max_chain_length = 5  # Prevent infinite loops
    
    for _ in range(max_chain_length):
        # Look for a certificate in our trusted CAs that issued the current certificate
        issuer_found = False
        
        for ca_cert in trusted_cas:
            if current_cert.issuer == ca_cert.subject:
                # Verify signature
                try:
                    public_key = ca_cert.public_key()
                    if _verify_certificate_signature(current_cert, public_key):
                        # We've found a valid issuer
                        chain.append(ca_cert)
                        
                        # If this is a self-signed certificate, we've reached the root
                        if ca_cert.issuer == ca_cert.subject:
                            # Verify the entire chain
                            result = _verify_full_chain(chain)
                            _cache_validation_result(cert, *result)
                            return result
                        
                        # Otherwise, continue up the chain
                        current_cert = ca_cert
                        issuer_found = True
                        break
                except Exception as e:
                    logger.warning(f"Error verifying certificate in chain: {str(e)}")
        
        if not issuer_found:
            result = (False, "Could not build a complete certificate chain to a trusted root")
            _cache_validation_result(cert, *result)
            return result
    
    result = (False, "Certificate chain too long or circular")
    _cache_validation_result(cert, *result)
    return result

def _verify_certificate_signature(cert: x509.Certificate, issuer_public_key) -> bool:
    """
    Verify a certificate's signature using the issuer's public key.
    
    Args:
        cert: Certificate to verify
        issuer_public_key: The public key of the issuing CA
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Determine the appropriate verification method based on the key type
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            # For RSA keys
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            return True
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            # For EC keys
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
            return True
        else:
            logger.warning(f"Unsupported public key type: {type(issuer_public_key).__name__}")
            return False
            
    except InvalidSignature:
        logger.warning("Invalid certificate signature")
        return False
    except Exception as e:
        logger.warning(f"Error verifying certificate signature: {str(e)}")
        return False

def _check_revocation_status(cert: x509.Certificate) -> Tuple[bool, str]:
    """
    Check if a certificate has been revoked via CRL or OCSP.
    
    Args:
        cert: Certificate to check
        
    Returns:
        Tuple of (is_revoked, reason)
    """
    # Cache key for revocation status
    from .certificate import get_certificate_thumbprint, fetch_crl, check_cert_against_crl
    cache_key = f"revocation_{get_certificate_thumbprint(cert)}"
    
    # Check cache first
    if cache_key in _validation_cache:
        is_revoked, reason, timestamp = _validation_cache[cache_key]
        if _is_cache_valid(timestamp):
            logger.debug(f"Using cached revocation result for {cache_key}")
            return is_revoked, reason
    
    is_revoked = False
    reason = "Not revoked"
    
    # Check for CRL Distribution Points
    try:
        crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        crl_distribution_points = crl_ext.value
        
        for dp in crl_distribution_points:
            # Check for URI type distribution points
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        crl_url = name.value
                        logger.info(f"Found CRL distribution point: {crl_url}")
                        
                        # Fetch and check the CRL
                        crl = fetch_crl(crl_url)
                        if crl:
                            is_revoked, reason = check_cert_against_crl(cert, crl)
                            if is_revoked:
                                # Cache the result and return early
                                _validation_cache[cache_key] = (is_revoked, reason, datetime.now())
                                return is_revoked, reason
    except x509.ExtensionNotFound:
        logger.debug("No CRL distribution points found")
    
    # Check for OCSP
    try:
        ocsp_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        authority_info = ocsp_ext.value
        
        for access_method in authority_info:
            if access_method.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":  # OCSP
                if isinstance(access_method.access_location, x509.UniformResourceIdentifier):
                    ocsp_url = access_method.access_location.value
                    logger.info(f"Found OCSP responder: {ocsp_url}")
                    
                    # Note: OCSP checking requires additional implementation
                    # We would need to:
                    # 1. Generate an OCSP request
                    # 2. Send it to the OCSP responder
                    # 3. Parse the response
                    
                    # Log instead of actually checking for now
                    logger.info(f"OCSP checking not fully implemented for URL: {ocsp_url}")
    except x509.ExtensionNotFound:
        logger.debug("No OCSP information found")
    
    # Cache the result
    _validation_cache[cache_key] = (is_revoked, reason, datetime.now())
    
    return is_revoked, reason

def _verify_full_chain(chain: List[x509.Certificate]) -> Tuple[bool, str]:
    """
    Verify a complete certificate chain.
    
    Args:
        chain: List of certificates, from leaf to root
        
    Returns:
        Tuple of (is_valid, reason)
    """
    if not chain:
        return False, "Empty certificate chain"
    
    # Check that we have at least two certificates (leaf + issuer)
    if len(chain) < 2:
        return False, "Incomplete certificate chain"
    
    # Verify each certificate in the chain against its issuer
    for i in range(len(chain) - 1):
        cert = chain[i]
        issuer = chain[i + 1]
        
        # Check that issuer matches
        if cert.issuer != issuer.subject:
            return False, f"Certificate issuer mismatch at position {i} in chain"
        
        # Verify signature
        if not _verify_certificate_signature(cert, issuer.public_key()):
            return False, f"Invalid signature at position {i} in chain"
        
        # Check validity period
        now = datetime.now()
        if cert.not_valid_before > now or cert.not_valid_after < now:
            return False, f"Certificate at position {i} in chain is not currently valid"
        
        # Check revocation status
        is_revoked, reason = _check_revocation_status(cert)
        if is_revoked:
            return False, f"Certificate at position {i} in chain is revoked: {reason}"
    
    # All certificates in the chain are valid
    return True, "Certificate chain is valid"

def install_trust_anchor(name: str, cert_path: str) -> bool:
    """
    Install a trust anchor certificate.
    
    Args:
        name: Name for the trust anchor
        cert_path: Path to the certificate file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Load the certificate to validate it
        cert = load_certificate(cert_path)
        
        # Define the destination filename
        if name.upper() in TRUST_ANCHORS:
            dest_filename = TRUST_ANCHORS[name.upper()]['root_cert_filename']
        else:
            # Generate a safe filename from the name
            safe_name = name.lower().replace(' ', '-')
            dest_filename = f"{safe_name}-root.pem"
        
        # Determine the destination path
        from .certificate import CA_DIR
        dest_path = os.path.join(CA_DIR, dest_filename)
        
        # Copy the certificate
        with open(cert_path, 'rb') as src_file:
            cert_data = src_file.read()
            
        with open(dest_path, 'wb') as dest_file:
            dest_file.write(cert_data)
        
        logger.info(f"Installed trust anchor: {name} at {dest_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to install trust anchor {name}: {str(e)}")
        return False

def is_from_trusted_ca(cert: x509.Certificate, ca_name: str = None) -> Tuple[bool, str]:
    """
    Check if a certificate is issued by a specific trusted CA or any trusted CA.
    
    Args:
        cert: Certificate to check
        ca_name: Optional name of the CA to check (GEANT or DFN)
        
    Returns:
        Tuple of (is_trusted, reason)
    """
    # Load all trusted CAs
    trusted_cas = load_trusted_cas()
    
    if not trusted_cas:
        return False, "No trusted CA certificates found"
    
    # If a specific CA was requested, filter the trusted CAs
    if ca_name and ca_name.upper() in TRUST_ANCHORS:
        ca_info = TRUST_ANCHORS[ca_name.upper()]
        filtered_cas = []
        
        for ca_cert in trusted_cas:
            try:
                common_name = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                if ca_info['issuer_cn'] in common_name:
                    filtered_cas.append(ca_cert)
            except (IndexError, ValueError):
                pass
        
        trusted_cas = filtered_cas
        
        if not trusted_cas:
            return False, f"No trusted CAs found for {ca_name}"
    
    # Verify the certificate chain
    return verify_certificate_chain(cert, trusted_cas) 