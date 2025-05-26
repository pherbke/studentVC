"""
X.509 and DID Challenge-Response Protocol

This module implements a cryptographic challenge-response protocol 
for proving control over both X.509 certificates and DIDs, as specified
in HAVID §6.2.

The protocol involves:
1. Generating a random challenge
2. Signing the challenge with both the X.509 certificate's private key and the DID's private key
3. Verifying both signatures to prove dual control
"""

import os
import uuid
import base64
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional, Union
from threading import Lock

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

logger = logging.getLogger(__name__)

# Challenge cache to prevent replay attacks
# Structure: {challenge_id: {"value": str, "created_at": datetime, "expires_at": datetime}}
CHALLENGE_CACHE = {}
CHALLENGE_CACHE_LOCK = Lock()

# Default challenge validity period in seconds
DEFAULT_CHALLENGE_VALIDITY = 300  # 5 minutes

def generate_challenge(length: int = 32) -> Tuple[str, str]:
    """
    Generate a random challenge for the challenge-response protocol.
    
    Args:
        length: Length of the challenge in bytes (default: 32 bytes)
        
    Returns:
        Tuple of (challenge_id, challenge_value)
    """
    # Clean up expired challenges first
    _cleanup_expired_challenges()
    
    # Generate a random challenge
    challenge_value = base64.urlsafe_b64encode(secrets.token_bytes(length)).decode('utf-8').rstrip('=')
    challenge_id = str(uuid.uuid4())
    
    # Store in cache with expiration
    now = datetime.now()
    expires_at = now + timedelta(seconds=DEFAULT_CHALLENGE_VALIDITY)
    
    with CHALLENGE_CACHE_LOCK:
        CHALLENGE_CACHE[challenge_id] = {
            "value": challenge_value,
            "created_at": now,
            "expires_at": expires_at
        }
    
    logger.debug(f"Generated challenge {challenge_id} (expires at {expires_at})")
    return challenge_id, challenge_value

def _cleanup_expired_challenges() -> None:
    """Clean up expired challenges from the cache."""
    now = datetime.now()
    expired_ids = []
    
    with CHALLENGE_CACHE_LOCK:
        for challenge_id, challenge_data in CHALLENGE_CACHE.items():
            if challenge_data["expires_at"] < now:
                expired_ids.append(challenge_id)
        
        for challenge_id in expired_ids:
            del CHALLENGE_CACHE[challenge_id]
    
    if expired_ids:
        logger.debug(f"Cleaned up {len(expired_ids)} expired challenges")

def is_challenge_valid(challenge_id: str, challenge_value: str) -> bool:
    """
    Check if a challenge is valid and not expired.
    
    Args:
        challenge_id: ID of the challenge
        challenge_value: Challenge value to validate
        
    Returns:
        True if challenge is valid, False otherwise
    """
    _cleanup_expired_challenges()
    
    with CHALLENGE_CACHE_LOCK:
        if challenge_id not in CHALLENGE_CACHE:
            logger.warning(f"Challenge {challenge_id} not found in cache")
            return False
        
        challenge_data = CHALLENGE_CACHE[challenge_id]
        if challenge_data["value"] != challenge_value:
            logger.warning(f"Challenge value mismatch for {challenge_id}")
            return False
        
        if challenge_data["expires_at"] < datetime.now():
            logger.warning(f"Challenge {challenge_id} has expired")
            return False
    
    return True

def sign_challenge_with_x509_key(
    challenge: str, 
    private_key: Union[RSAPrivateKey, EllipticCurvePrivateKey]
) -> str:
    """
    Sign a challenge using an X.509 certificate's private key.
    
    Args:
        challenge: Challenge string to sign
        private_key: Private key to use for signing
        
    Returns:
        Base64-encoded signature
    """
    key_type = type(private_key).__name__
    challenge_bytes = challenge.encode('utf-8')
    
    if isinstance(private_key, RSAPrivateKey):
        # Use PKCS#1 v1.5 padding for RSA (widely compatible)
        signature = private_key.sign(
            challenge_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    elif isinstance(private_key, EllipticCurvePrivateKey):
        # Use ECDSA for EC keys
        signature = private_key.sign(
            challenge_bytes,
            ec.ECDSA(hashes.SHA256())
        )
    else:
        raise ValueError(f"Unsupported key type: {key_type}")
    
    # Return base64 encoded signature
    return base64.b64encode(signature).decode('utf-8')

def verify_x509_challenge_signature(
    challenge: str, 
    signature: str, 
    cert: x509.Certificate
) -> bool:
    """
    Verify a challenge signature using an X.509 certificate.
    
    Args:
        challenge: Original challenge string
        signature: Base64-encoded signature to verify
        cert: X.509 certificate containing the public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Decode signature
        signature_bytes = base64.b64decode(signature)
        challenge_bytes = challenge.encode('utf-8')
        
        # Get public key from certificate
        public_key = cert.public_key()
        
        # Verify signature based on key type
        if isinstance(public_key, RSAPublicKey):
            public_key.verify(
                signature_bytes,
                challenge_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        elif isinstance(public_key, EllipticCurvePublicKey):
            public_key.verify(
                signature_bytes,
                challenge_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            logger.warning(f"Unsupported key type: {type(public_key).__name__}")
            return False
        
        return True
    except InvalidSignature:
        logger.warning("Invalid X.509 signature")
        return False
    except Exception as e:
        logger.error(f"Error verifying X.509 signature: {str(e)}")
        return False

def sign_challenge_with_did_key(
    challenge: str, 
    private_key: Union[RSAPrivateKey, EllipticCurvePrivateKey]
) -> str:
    """
    Sign a challenge using a DID's private key. Uses same process as X.509 keys.
    
    Args:
        challenge: Challenge string to sign
        private_key: Private key to use for signing
        
    Returns:
        Base64-encoded signature
    """
    # Reuse the same signing function for consistency
    return sign_challenge_with_x509_key(challenge, private_key)

def verify_did_challenge_signature(
    challenge: str, 
    signature: str, 
    public_key: Union[RSAPublicKey, EllipticCurvePublicKey]
) -> bool:
    """
    Verify a challenge signature using a DID's public key.
    
    Args:
        challenge: Original challenge string
        signature: Base64-encoded signature to verify
        public_key: DID's public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Decode signature
        signature_bytes = base64.b64decode(signature)
        challenge_bytes = challenge.encode('utf-8')
        
        # Verify signature based on key type
        if isinstance(public_key, RSAPublicKey):
            public_key.verify(
                signature_bytes,
                challenge_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        elif isinstance(public_key, EllipticCurvePublicKey):
            public_key.verify(
                signature_bytes,
                challenge_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            logger.warning(f"Unsupported key type: {type(public_key).__name__}")
            return False
        
        return True
    except InvalidSignature:
        logger.warning("Invalid DID signature")
        return False
    except Exception as e:
        logger.error(f"Error verifying DID signature: {str(e)}")
        return False

def verify_dual_control(
    challenge: str,
    x509_signature: str,
    did_signature: str,
    cert: x509.Certificate,
    did_public_key: Union[RSAPublicKey, EllipticCurvePublicKey]
) -> Tuple[bool, str]:
    """
    Verify that the challenge was signed by both the X.509 key and the DID key,
    proving control over both identifiers.
    
    Args:
        challenge: Original challenge string
        x509_signature: Base64-encoded signature from X.509 private key
        did_signature: Base64-encoded signature from DID private key
        cert: X.509 certificate containing the public key
        did_public_key: DID public key
        
    Returns:
        Tuple of (success, reason)
    """
    # Verify X.509 signature
    x509_valid = verify_x509_challenge_signature(challenge, x509_signature, cert)
    if not x509_valid:
        return False, "X.509 signature validation failed"
    
    # Verify DID signature
    did_valid = verify_did_challenge_signature(challenge, did_signature, did_public_key)
    if not did_valid:
        return False, "DID signature validation failed"
    
    # Both signatures are valid
    return True, "Dual control verified: both X.509 and DID signatures are valid" 