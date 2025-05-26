"""
X.509 Certificate Lifecycle Management

This module provides functionality for monitoring and managing X.509 certificate
lifecycle events, such as expiration, rekeying, and revocation, and keeping
DID bindings in sync with these events.
"""

import os
import logging
import time
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional, Set, Union
from threading import Thread, Lock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from .certificate import (
    load_certificate,
    get_certificate_info,
    is_certificate_valid,
    check_cert_against_crl
)
from .did_binding import (
    verify_certificate_did_binding,
    find_did_in_certificate_san,
    verify_bidirectional_linkage
)
from .trust import verify_certificate_chain

logger = logging.getLogger(__name__)

# Store for tracking certificate-DID bindings
# Structure: {cert_fingerprint: {did: str, last_checked: datetime, status: str}}
BINDING_STORE = {}
BINDING_STORE_LOCK = Lock()
BINDING_STORE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    'instance',
    'x509_did_bindings.json'
)

# Monitor interval in seconds
DEFAULT_MONITOR_INTERVAL = 86400  # 24 hours
# How many days before expiration to trigger a warning
DEFAULT_EXPIRY_WARNING_DAYS = 30

class CertificateMonitor:
    """
    Monitor for tracking certificate lifecycle and maintaining DID bindings.
    """
    
    def __init__(self, config=None):
        """
        Initialize the certificate monitor.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.monitor_interval = self.config.get('MONITOR_INTERVAL', DEFAULT_MONITOR_INTERVAL)
        self.expiry_warning_days = self.config.get('EXPIRY_WARNING_DAYS', DEFAULT_EXPIRY_WARNING_DAYS)
        self.cert_dir = self.config.get('CERT_DIR', os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
            'instance', 
            'certs'
        ))
        
        # Load existing binding store if available
        self._load_binding_store()
        
        # Thread for monitoring
        self._monitor_thread = None
        self._stop_monitor = False
    
    def _load_binding_store(self) -> None:
        """Load the binding store from disk if it exists."""
        global BINDING_STORE
        try:
            if os.path.exists(BINDING_STORE_PATH):
                with open(BINDING_STORE_PATH, 'r') as f:
                    store_data = json.load(f)
                
                # Convert stored timestamps back to datetime objects
                converted_store = {}
                for fingerprint, binding in store_data.items():
                    if 'last_checked' in binding:
                        binding['last_checked'] = datetime.fromisoformat(binding['last_checked'])
                    converted_store[fingerprint] = binding
                
                with BINDING_STORE_LOCK:
                    BINDING_STORE = converted_store
                logger.info(f"Loaded {len(BINDING_STORE)} certificate-DID bindings from store")
        except Exception as e:
            logger.error(f"Error loading binding store: {str(e)}")
    
    def _save_binding_store(self) -> None:
        """Save the binding store to disk."""
        try:
            # Convert datetime objects to strings for JSON serialization
            store_data = {}
            with BINDING_STORE_LOCK:
                for fingerprint, binding in BINDING_STORE.items():
                    binding_copy = binding.copy()
                    if 'last_checked' in binding_copy and isinstance(binding_copy['last_checked'], datetime):
                        binding_copy['last_checked'] = binding_copy['last_checked'].isoformat()
                    store_data[fingerprint] = binding_copy
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(BINDING_STORE_PATH), exist_ok=True)
            
            # Write to a temporary file first, then rename for atomicity
            temp_path = f"{BINDING_STORE_PATH}.tmp"
            with open(temp_path, 'w') as f:
                json.dump(store_data, f, indent=2)
            
            # Rename for atomic update
            os.replace(temp_path, BINDING_STORE_PATH)
            logger.debug(f"Saved {len(store_data)} certificate-DID bindings to store")
        except Exception as e:
            logger.error(f"Error saving binding store: {str(e)}")
    
    def register_binding(self, cert: x509.Certificate, did: str) -> None:
        """
        Register a certificate-DID binding for monitoring.
        
        Args:
            cert: X.509 certificate
            did: DID bound to the certificate
        """
        # Generate certificate fingerprint
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        
        # Get certificate info
        cert_info = get_certificate_info(cert)
        
        # Add to binding store
        with BINDING_STORE_LOCK:
            BINDING_STORE[fingerprint] = {
                'did': did,
                'issuer': cert_info['issuer'],
                'subject': cert_info['subject'],
                'serial_number': cert_info['serial_number'],
                'not_before': cert_info['validity']['not_before'].isoformat(),
                'not_after': cert_info['validity']['not_after'].isoformat(),
                'last_checked': datetime.now(),
                'status': 'active',
                'public_key_hash': hashlib.sha256(
                    cert.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                ).hexdigest()
            }
        
        logger.info(f"Registered binding between certificate {fingerprint[:8]} and DID {did}")
        self._save_binding_store()
    
    def unregister_binding(self, cert: x509.Certificate) -> None:
        """
        Unregister a certificate-DID binding.
        
        Args:
            cert: X.509 certificate
        """
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        
        with BINDING_STORE_LOCK:
            if fingerprint in BINDING_STORE:
                del BINDING_STORE[fingerprint]
                logger.info(f"Unregistered binding for certificate {fingerprint[:8]}")
                self._save_binding_store()
            else:
                logger.warning(f"No binding found for certificate {fingerprint[:8]}")
    
    def start_monitoring(self) -> None:
        """Start the certificate monitoring thread."""
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            logger.warning("Certificate monitor is already running")
            return
        
        self._stop_monitor = False
        self._monitor_thread = Thread(target=self._monitoring_loop)
        self._monitor_thread.daemon = True
        self._monitor_thread.start()
        logger.info("Certificate monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop the certificate monitoring thread."""
        if self._monitor_thread is None or not self._monitor_thread.is_alive():
            logger.warning("Certificate monitor is not running")
            return
        
        self._stop_monitor = True
        self._monitor_thread.join(timeout=10)
        if self._monitor_thread.is_alive():
            logger.warning("Certificate monitor thread did not stop cleanly")
        else:
            logger.info("Certificate monitoring stopped")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop that periodically checks all registered certificates."""
        while not self._stop_monitor:
            try:
                self._check_all_certificates()
            except Exception as e:
                logger.error(f"Error in certificate monitoring loop: {str(e)}")
            
            # Sleep for the monitor interval
            for _ in range(int(self.monitor_interval / 10)):
                if self._stop_monitor:
                    break
                time.sleep(10)
    
    def _check_all_certificates(self) -> None:
        """Check all registered certificates for lifecycle events."""
        now = datetime.now()
        expired_certs = []
        expiring_soon = []
        potentially_rekeyed = []
        
        # Copy keys to avoid modifying during iteration
        with BINDING_STORE_LOCK:
            cert_fingerprints = list(BINDING_STORE.keys())
        
        for fingerprint in cert_fingerprints:
            try:
                with BINDING_STORE_LOCK:
                    if fingerprint not in BINDING_STORE:
                        continue
                    binding = BINDING_STORE[fingerprint]
                
                # Convert ISO datetime strings to datetime objects if needed
                not_after = binding['not_after']
                if isinstance(not_after, str):
                    not_after = datetime.fromisoformat(not_after)
                
                # Check if expired
                if now > not_after:
                    expired_certs.append(fingerprint)
                    continue
                
                # Check if expiring soon
                expiry_warning_date = now + timedelta(days=self.expiry_warning_days)
                if expiry_warning_date > not_after:
                    expiring_soon.append(fingerprint)
                
                # Check for certificate path in our certificates directory
                # This assumes certificates follow a naming pattern that includes DID or fingerprint
                did = binding['did']
                cert_paths = self._find_possible_cert_paths(did, fingerprint)
                
                if not cert_paths:
                    logger.warning(f"Cannot find certificate file for binding {fingerprint[:8]}")
                    continue
                
                # Check each potential certificate file
                for cert_path in cert_paths:
                    try:
                        cert = load_certificate(cert_path)
                        
                        # Check if this is a rekeyed/renewed certificate
                        is_rekeyed = self._check_for_rekeying(cert, binding)
                        if is_rekeyed:
                            potentially_rekeyed.append((fingerprint, cert_path))
                            break
                    except Exception as e:
                        logger.warning(f"Error checking certificate at {cert_path}: {str(e)}")
            
            except Exception as e:
                logger.error(f"Error processing certificate {fingerprint[:8]}: {str(e)}")
        
        # Process expired certificates
        for fingerprint in expired_certs:
            self._handle_expired_certificate(fingerprint)
        
        # Process expiring certificates
        for fingerprint in expiring_soon:
            self._handle_expiring_certificate(fingerprint)
        
        # Process potentially rekeyed certificates
        for fingerprint, cert_path in potentially_rekeyed:
            self._handle_rekeyed_certificate(fingerprint, cert_path)
        
        # Save changes
        self._save_binding_store()
        
        # Log summary
        logger.info(f"Certificate check completed: {len(expired_certs)} expired, "
                   f"{len(expiring_soon)} expiring soon, "
                   f"{len(potentially_rekeyed)} potentially rekeyed")
    
    def _find_possible_cert_paths(self, did: str, fingerprint: str) -> List[str]:
        """Find potential certificate files based on DID or fingerprint."""
        cert_paths = []
        
        # Look in the certificate directory
        if os.path.exists(self.cert_dir):
            for filename in os.listdir(self.cert_dir):
                if not filename.endswith('.pem') and not filename.endswith('.crt'):
                    continue
                
                # Check if filename contains DID or fingerprint
                if (did and did.replace(':', '_') in filename) or fingerprint[:8] in filename:
                    cert_paths.append(os.path.join(self.cert_dir, filename))
        
        return cert_paths
    
    def _check_for_rekeying(self, cert: x509.Certificate, binding: Dict[str, Any]) -> bool:
        """
        Check if a certificate appears to be a rekeyed version of the registered one.
        
        Args:
            cert: X.509 certificate to check
            binding: Binding record from the store
            
        Returns:
            True if certificate appears to be rekeyed, False otherwise
        """
        # Check if subject and issuer match
        cert_info = get_certificate_info(cert)
        if cert_info['subject'] != binding['subject'] or cert_info['issuer'] != binding['issuer']:
            return False
        
        # Check if serial number is different (indicating a new certificate)
        if cert_info['serial_number'] == binding['serial_number']:
            return False
        
        # Check if public key has changed (the key part of rekeying)
        cert_key_hash = hashlib.sha256(
            cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()
        
        if cert_key_hash == binding['public_key_hash']:
            return False  # Same key, not rekeyed
        
        # Check if the new certificate has a later not_before date
        old_not_before = binding['not_before']
        if isinstance(old_not_before, str):
            old_not_before = datetime.fromisoformat(old_not_before)
        
        if cert_info['validity']['not_before'] <= old_not_before:
            return False  # Not a newer certificate
        
        # Extract DID from the certificate
        cert_did = find_did_in_certificate_san(cert)
        if not cert_did or cert_did != binding['did']:
            return False  # DID doesn't match
        
        # If all checks pass, this is likely a rekeyed certificate
        return True
    
    def _handle_expired_certificate(self, fingerprint: str) -> None:
        """Handle an expired certificate."""
        with BINDING_STORE_LOCK:
            if fingerprint not in BINDING_STORE:
                return
            
            binding = BINDING_STORE[fingerprint]
            if binding['status'] != 'expired':
                binding['status'] = 'expired'
                binding['last_checked'] = datetime.now()
                logger.info(f"Certificate {fingerprint[:8]} for DID {binding['did']} has expired")
    
    def _handle_expiring_certificate(self, fingerprint: str) -> None:
        """Handle a certificate that is expiring soon."""
        with BINDING_STORE_LOCK:
            if fingerprint not in BINDING_STORE:
                return
            
            binding = BINDING_STORE[fingerprint]
            if binding['status'] == 'active':
                binding['status'] = 'expiring_soon'
                binding['last_checked'] = datetime.now()
                
                # Calculate days until expiration
                not_after = binding['not_after']
                if isinstance(not_after, str):
                    not_after = datetime.fromisoformat(not_after)
                
                days_left = (not_after - datetime.now()).days
                logger.warning(f"Certificate {fingerprint[:8]} for DID {binding['did']} "
                              f"is expiring in {days_left} days")
    
    def _handle_rekeyed_certificate(self, old_fingerprint: str, new_cert_path: str) -> None:
        """
        Handle a certificate that appears to have been rekeyed.
        
        Args:
            old_fingerprint: Fingerprint of the old certificate
            new_cert_path: Path to the potentially new certificate
        """
        try:
            with BINDING_STORE_LOCK:
                if old_fingerprint not in BINDING_STORE:
                    return
                
                binding = BINDING_STORE[old_fingerprint]
                did = binding['did']
            
            # Load the new certificate
            new_cert = load_certificate(new_cert_path)
            
            # Verify the new certificate
            is_valid, reason = is_certificate_valid(new_cert)
            if not is_valid:
                logger.warning(f"New certificate for DID {did} is not valid: {reason}")
                return
            
            # Verify DID binding in the new certificate
            is_bound, reason = verify_certificate_did_binding(new_cert, did)
            if not is_bound:
                logger.warning(f"New certificate for DID {did} is not correctly bound: {reason}")
                return
            
            # All checks passed, register the new certificate
            self.register_binding(new_cert, did)
            
            # Mark the old certificate as replaced
            with BINDING_STORE_LOCK:
                if old_fingerprint in BINDING_STORE:
                    BINDING_STORE[old_fingerprint]['status'] = 'replaced'
                    BINDING_STORE[old_fingerprint]['last_checked'] = datetime.now()
            
            # Generate fingerprint for logging
            new_cert_der = new_cert.public_bytes(serialization.Encoding.DER)
            new_fingerprint = hashlib.sha256(new_cert_der).hexdigest()
            
            logger.info(f"Certificate for DID {did} has been rekeyed/renewed: "
                       f"old={old_fingerprint[:8]} -> new={new_fingerprint[:8]}")
            
        except Exception as e:
            logger.error(f"Error handling rekeyed certificate: {str(e)}")
    
    def find_binding_by_did(self, did: str) -> Optional[Dict[str, Any]]:
        """
        Find the most recent active binding for a DID.
        
        Args:
            did: DID to find
            
        Returns:
            Most recent binding record or None if not found
        """
        latest_binding = None
        latest_not_after = None
        
        with BINDING_STORE_LOCK:
            for fingerprint, binding in BINDING_STORE.items():
                if binding['did'] == did and binding['status'] in ['active', 'expiring_soon']:
                    not_after = binding['not_after']
                    if isinstance(not_after, str):
                        not_after = datetime.fromisoformat(not_after)
                    
                    if latest_not_after is None or not_after > latest_not_after:
                        latest_binding = binding.copy()
                        latest_binding['fingerprint'] = fingerprint
                        latest_not_after = not_after
        
        return latest_binding
    
    def invalidate_binding(self, fingerprint: str, reason: str) -> None:
        """
        Mark a binding as invalid.
        
        Args:
            fingerprint: Certificate fingerprint
            reason: Reason for invalidation
        """
        with BINDING_STORE_LOCK:
            if fingerprint in BINDING_STORE:
                BINDING_STORE[fingerprint]['status'] = 'invalid'
                BINDING_STORE[fingerprint]['invalid_reason'] = reason
                BINDING_STORE[fingerprint]['last_checked'] = datetime.now()
                logger.info(f"Invalidated binding for certificate {fingerprint[:8]}: {reason}")
                self._save_binding_store()
            else:
                logger.warning(f"No binding found for certificate {fingerprint[:8]}")

def setup_certificate_monitor(config=None) -> CertificateMonitor:
    """
    Set up and start a certificate monitor.
    
    Args:
        config: Optional configuration
        
    Returns:
        Running CertificateMonitor instance
    """
    monitor = CertificateMonitor(config)
    monitor.start_monitoring()
    return monitor

# API functions for lifecycle monitoring

def register_certificate_did_binding(cert: x509.Certificate, did: str, monitor: Optional[CertificateMonitor] = None) -> bool:
    """
    Register a certificate-DID binding for monitoring.
    
    Args:
        cert: X.509 certificate
        did: DID bound to the certificate
        monitor: Optional CertificateMonitor instance (will create if not provided)
        
    Returns:
        True if registration was successful
    """
    try:
        # Verify bidirectional linkage first
        is_valid, reason = verify_certificate_did_binding(cert, did)
        if not is_valid:
            logger.warning(f"Cannot register binding: {reason}")
            return False
        
        # Create monitor if not provided
        if monitor is None:
            monitor = CertificateMonitor()
        
        # Register binding
        monitor.register_binding(cert, did)
        return True
    except Exception as e:
        logger.error(f"Error registering certificate-DID binding: {str(e)}")
        return False

def find_current_binding_for_did(did: str, monitor: Optional[CertificateMonitor] = None) -> Optional[Dict[str, Any]]:
    """
    Find the current active binding for a DID.
    
    Args:
        did: DID to find
        monitor: Optional CertificateMonitor instance (will create if not provided)
        
    Returns:
        Binding information or None if not found
    """
    try:
        # Create monitor if not provided
        if monitor is None:
            monitor = CertificateMonitor()
        
        return monitor.find_binding_by_did(did)
    except Exception as e:
        logger.error(f"Error finding binding for DID {did}: {str(e)}")
        return None

def invalidate_binding_for_did(did: str, reason: str, monitor: Optional[CertificateMonitor] = None) -> bool:
    """
    Invalidate the current binding for a DID.
    
    Args:
        did: DID to invalidate
        reason: Reason for invalidation
        monitor: Optional CertificateMonitor instance (will create if not provided)
        
    Returns:
        True if invalidation was successful
    """
    try:
        # Create monitor if not provided
        if monitor is None:
            monitor = CertificateMonitor()
        
        # Find current binding
        binding = monitor.find_binding_by_did(did)
        if binding is None:
            logger.warning(f"No active binding found for DID {did}")
            return False
        
        # Invalidate binding
        monitor.invalidate_binding(binding['fingerprint'], reason)
        return True
    except Exception as e:
        logger.error(f"Error invalidating binding for DID {did}: {str(e)}")
        return False

def is_certificate_did_binding_valid(cert: x509.Certificate, did: str, did_document: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
    """
    Check if a certificate-DID binding is valid.
    
    Args:
        cert: X.509 certificate
        did: DID bound to the certificate
        did_document: Optional DID document for bidirectional verification
        
    Returns:
        Tuple of (is_valid, reason)
    """
    try:
        # Check certificate validity
        is_cert_valid, reason = is_certificate_valid(cert)
        if not is_cert_valid:
            return False, f"Certificate is not valid: {reason}"
        
        # Check bidirectional linkage
        return verify_bidirectional_linkage(cert, did, did_document)
    except Exception as e:
        logger.error(f"Error checking certificate-DID binding validity: {str(e)}")
        return False, str(e) 