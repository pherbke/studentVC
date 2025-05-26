"""
X.509 Certificate Manager

Main interface for X.509 certificate operations in the StudentVC system.
This module ties together certificate loading, validation, trust chain verification,
and DID binding functionality.
"""

import os
import logging
from typing import Dict, Any, Optional, List, Tuple, Union
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .certificate import (
    load_certificate, 
    get_certificate_info, 
    is_certificate_valid,
    save_certificate,
    CERT_DIR,
    CA_DIR
)
from .did_binding import (
    create_did_web_from_certificate,
    create_did_key_from_certificate,
    create_certificate_metadata_for_did,
    verify_certificate_did_binding,
    verify_bidirectional_linkage
)
from .trust import (
    verify_certificate_chain,
    is_from_trusted_ca,
    install_trust_anchor,
    TRUST_ANCHORS
)
from .lifecycle import (
    setup_certificate_monitor,
    register_certificate_did_binding,
    find_current_binding_for_did,
    invalidate_binding_for_did,
    is_certificate_did_binding_valid
)

logger = logging.getLogger(__name__)

class X509Manager:
    """
    Manager class for X.509 certificate operations.
    """
    
    def __init__(self, config=None):
        """
        Initialize the X.509 Manager.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.cert_dir = self.config.get('CERT_DIR', CERT_DIR)
        self.ca_dir = self.config.get('CA_DIR', CA_DIR)
        
        # Ensure directories exist
        os.makedirs(self.cert_dir, exist_ok=True)
        os.makedirs(self.ca_dir, exist_ok=True)
        
        # Certificate cache to avoid repeatedly loading certificates
        # Structure: {cert_path: (certificate, timestamp)}
        self._cert_cache = {}
        # Cache expiration time (seconds)
        self._cache_expiration = self.config.get('CACHE_EXPIRATION', 3600)  # 1 hour default
        
        # Start certificate lifecycle monitoring
        self.certificate_monitor = setup_certificate_monitor(self.config)
    
    def _is_cache_valid(self, timestamp: datetime) -> bool:
        """Check if a cached entry is still valid."""
        return (datetime.now() - timestamp) < timedelta(seconds=self._cache_expiration)
    
    def clear_cache(self) -> None:
        """Clear all certificate caches."""
        self._cert_cache.clear()
        # Also clear the validation cache in the trust module
        from .trust import _validation_cache
        _validation_cache.clear()
        logger.info("X.509 certificate caches cleared")
    
    def load_certificate(self, cert_path: str) -> x509.Certificate:
        """
        Load an X.509 certificate from a file, using cache if available.
        
        Args:
            cert_path: Path to the certificate file
            
        Returns:
            x509.Certificate object
        """
        # Check cache first
        if cert_path in self._cert_cache:
            cert, timestamp = self._cert_cache[cert_path]
            if self._is_cache_valid(timestamp):
                logger.debug(f"Using cached certificate for {cert_path}")
                return cert
        
        # Load certificate and update cache
        cert = load_certificate(cert_path)
        self._cert_cache[cert_path] = (cert, datetime.now())
        return cert
    
    def save_certificate(self, cert: x509.Certificate, filename: str) -> str:
        """
        Save a certificate to the certificate directory.
        
        Args:
            cert: X.509 certificate to save
            filename: Filename for the certificate
            
        Returns:
            Full path to the saved certificate
        """
        file_path = os.path.join(self.cert_dir, filename)
        save_certificate(cert, file_path)
        # Update cache with the newly saved certificate
        self._cert_cache[file_path] = (cert, datetime.now())
        return file_path
    
    def get_certificate_info(self, cert: x509.Certificate) -> Dict[str, Any]:
        """
        Get detailed information about a certificate.
        
        Args:
            cert: X.509 certificate
            
        Returns:
            Dictionary with certificate information
        """
        return get_certificate_info(cert)
    
    def is_certificate_valid(self, cert: x509.Certificate, check_trust: bool = True) -> Tuple[bool, str]:
        """
        Check if a certificate is valid (not expired, not revoked, optionally trusted).
        
        Args:
            cert: X.509 certificate to check
            check_trust: Whether to verify trust chain (default: True)
            
        Returns:
            Tuple of (is_valid, reason)
        """
        if check_trust:
            return is_certificate_valid(cert, TRUST_ANCHORS)
        return is_certificate_valid(cert)
    
    def verify_certificate_chain(self, cert: x509.Certificate) -> Tuple[bool, str]:
        """
        Verify the certificate chain up to a trusted root.
        
        Args:
            cert: X.509 certificate to verify
            
        Returns:
            Tuple of (is_valid, reason)
        """
        return verify_certificate_chain(cert, TRUST_ANCHORS)
    
    def is_from_trusted_ca(self, cert: x509.Certificate) -> Tuple[bool, str]:
        """
        Check if a certificate is issued by a trusted CA.
        
        Args:
            cert: X.509 certificate to check
            
        Returns:
            Tuple of (is_valid, reason)
        """
        return is_from_trusted_ca(cert, TRUST_ANCHORS)
    
    def install_trust_anchor(self, cert_path: str) -> Tuple[bool, str]:
        """
        Install a new trust anchor (CA certificate).
        
        Args:
            cert_path: Path to the CA certificate
            
        Returns:
            Tuple of (success, message)
        """
        return install_trust_anchor(cert_path)
    
    def create_did_from_certificate(self, cert: x509.Certificate, did_method: str = 'web', domain: str = None, path: str = None) -> str:
        """
        Create a DID from a certificate.
        
        Args:
            cert: X.509 certificate
            did_method: DID method to use ('web' or 'key')
            domain: Domain for did:web (required for did:web)
            path: Optional path for did:web
            
        Returns:
            DID string
        """
        if did_method == 'web':
            if not domain:
                raise ValueError("Domain is required for did:web")
            return create_did_web_from_certificate(cert, domain, path)
        elif did_method == 'key':
            return create_did_key_from_certificate(cert)
        else:
            raise ValueError(f"Unsupported DID method: {did_method}")
    
    def create_certificate_metadata(self, cert: x509.Certificate, did: str, include_pem: bool = False) -> Dict[str, Any]:
        """
        Create metadata for a certificate-DID binding.
        
        Args:
            cert: X.509 certificate
            did: DID to bind to the certificate
            include_pem: Whether to include PEM-encoded certificate
            
        Returns:
            Metadata dictionary
        """
        return create_certificate_metadata_for_did(cert, did, include_pem)
    
    def verify_certificate_did_binding(self, cert: x509.Certificate, did: str) -> Tuple[bool, str]:
        """
        Verify if a certificate is correctly bound to a DID.
        
        Args:
            cert: X.509 certificate
            did: DID to verify
            
        Returns:
            Tuple of (is_valid, reason)
        """
        return verify_certificate_did_binding(cert, did)
    
    def verify_bidirectional_linkage(self, cert: x509.Certificate, did: str, 
                                    did_document: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """
        Verify bidirectional linkage between an X.509 certificate and a DID.
        
        Args:
            cert: X.509 certificate
            did: DID to verify
            did_document: Optional DID document for bidirectional verification
            
        Returns:
            Tuple of (is_valid, reason)
        """
        return verify_bidirectional_linkage(cert, did, did_document)
    
    def register_certificate_did_binding(self, cert: x509.Certificate, did: str) -> bool:
        """
        Register a certificate-DID binding for lifecycle monitoring.
        
        Args:
            cert: X.509 certificate
            did: DID to bind to the certificate
            
        Returns:
            True if registration was successful
        """
        return register_certificate_did_binding(cert, did, self.certificate_monitor)
    
    def find_current_binding_for_did(self, did: str) -> Optional[Dict[str, Any]]:
        """
        Find the current active binding for a DID.
        
        Args:
            did: DID to find
            
        Returns:
            Binding information or None if not found
        """
        return find_current_binding_for_did(did, self.certificate_monitor)
    
    def invalidate_binding_for_did(self, did: str, reason: str) -> bool:
        """
        Invalidate the current binding for a DID.
        
        Args:
            did: DID to invalidate
            reason: Reason for invalidation
            
        Returns:
            True if invalidation was successful
        """
        return invalidate_binding_for_did(did, reason, self.certificate_monitor)
    
    def stop_certificate_monitor(self) -> None:
        """Stop the certificate lifecycle monitoring."""
        if self.certificate_monitor:
            self.certificate_monitor.stop_monitoring() 