"""
Tests for HAVID specification compliance features.

This file contains tests for the High Assurance Verifiable Identifiers (HAVID)
compliance features, including:
1. Bidirectional linkage between X.509 certificates and DIDs
2. Challenge-response protocol for cryptographic control verification
3. Certificate lifecycle monitoring
4. CA-assisted DID creation

These tests validate that the implementation meets the requirements
specified in the HAVID specification.
"""

import base64
import datetime
import json
import os
import pytest
import time
from unittest.mock import patch, MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import NameOID, ExtensionOID

# Import the modules to be tested
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.x509.did_binding import (
    create_did_from_cert, 
    verify_bidirectional_linkage,
    extract_did_from_certificate,
    find_x509_verification_methods
)
from src.x509.challenge_response import (
    generate_challenge,
    is_challenge_valid,
    sign_challenge_with_x509_key,
    verify_x509_challenge_signature,
    sign_challenge_with_did_key,
    verify_did_challenge_signature,
    verify_dual_control
)
from src.x509.manager import X509Manager
from src.x509.csr_processor import create_did_from_csr, add_certificate_to_did_document

class TestHAVIDCompliance:
    """Test suite for HAVID specification compliance."""

    @pytest.fixture(scope="class")
    def test_cert_with_did(self):
        """Create a test certificate with a DID in SubjectAlternativeName."""
        # Generate a private key for testing
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create a self-signed certificate with a DID in SAN
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'Test Certificate'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'StudentVC'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'test@example.com'),
        ])
        
        did = "did:web:example.com:subject:123456"
        
        san = x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(f"did:web:example.com:subject:123456"),
            x509.DNSName(u"example.com")
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            san, critical=False
        ).sign(private_key, hashes.SHA256())
        
        # Return both the certificate and private key for testing
        return {
            'certificate': cert,
            'private_key': private_key,
            'did': did
        }
    
    @pytest.fixture(scope="class")
    def did_doc_with_cert(self, test_cert_with_did):
        """Create a DID document with X.509 certificate verification methods."""
        cert = test_cert_with_did['certificate']
        did = test_cert_with_did['did']
        
        # Create a basic DID document with X.509 verification method
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_der).decode('ascii')
        
        did_doc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": did,
            "verificationMethod": [
                {
                    "id": f"{did}#x509-1",
                    "type": "X509Certificate2021",
                    "controller": did,
                    "certificateChain": cert_b64
                }
            ],
            "authentication": [
                f"{did}#x509-1"
            ]
        }
        
        return did_doc

    def test_create_did_from_cert(self, test_cert_with_did):
        """Test creating a DID from a certificate."""
        cert = test_cert_with_did['certificate']
        
        # Test with different DID methods
        did_web = create_did_from_cert(cert, "web", domain="example.com")
        did_key = create_did_from_cert(cert, "key")
        
        # Verify the DIDs are properly formatted
        assert did_web.startswith("did:web:example.com:")
        assert did_key.startswith("did:key:")
        
        # Verify the certificate's public key is incorporated into the DID
        public_key_bytes = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # For did:key, the fingerprint of the public key should be in the DID
        if isinstance(cert.public_key(), rsa.RSAPublicKey):
            assert "Rsa" in did_key
        elif isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
            assert "Ec" in did_key

    def test_extract_did_from_certificate(self, test_cert_with_did):
        """Test extracting a DID from a certificate's SubjectAlternativeName."""
        cert = test_cert_with_did['certificate']
        expected_did = test_cert_with_did['did']
        
        # Extract DID from the certificate
        did = extract_did_from_certificate(cert)
        
        # Verify the extracted DID matches the expected DID
        assert did == expected_did
    
    def test_find_x509_verification_methods(self, did_doc_with_cert):
        """Test finding X.509 verification methods in a DID document."""
        # Find X.509 verification methods in the DID document
        verification_methods = find_x509_verification_methods(did_doc_with_cert)
        
        # Verify at least one X.509 verification method was found
        assert len(verification_methods) > 0
        
        # Verify the verification method has the expected properties
        vm = verification_methods[0]
        assert vm['type'] == "X509Certificate2021"
        assert 'certificateChain' in vm
        assert vm['controller'] == did_doc_with_cert['id']
    
    def test_verify_bidirectional_linkage(self, test_cert_with_did, did_doc_with_cert):
        """Test verifying bidirectional linkage between a certificate and DID document."""
        cert = test_cert_with_did['certificate']
        
        # Verify bidirectional linkage
        is_valid = verify_bidirectional_linkage(cert, did_doc_with_cert)
        
        # Linkage should be valid
        assert is_valid is True
        
        # Test with invalid DID document (wrong DID)
        invalid_did_doc = did_doc_with_cert.copy()
        invalid_did_doc['id'] = "did:web:example.com:invalid"
        
        is_valid = verify_bidirectional_linkage(cert, invalid_did_doc)
        
        # Linkage should be invalid
        assert is_valid is False
    
    def test_generate_challenge(self):
        """Test generating a challenge for the challenge-response protocol."""
        # Generate a challenge
        challenge_id, challenge = generate_challenge()
        
        # Verify the challenge is a string of appropriate length
        assert isinstance(challenge_id, str)
        assert isinstance(challenge, str)
        assert len(challenge) >= 32  # Default length is 32 bytes
        
        # Verify challenge is valid
        assert is_challenge_valid(challenge_id, challenge) is True
        
        # Verify an invalid challenge is rejected
        assert is_challenge_valid("invalid_id", challenge) is False
        assert is_challenge_valid(challenge_id, "invalid_challenge") is False
    
    def test_challenge_expiration(self):
        """Test that challenges expire after the configured timeout."""
        # Generate a challenge
        challenge_id, challenge = generate_challenge()
        
        # Verify the challenge is valid
        assert is_challenge_valid(challenge_id, challenge) is True
        
        # Mock time.time() to return a future time beyond the challenge timeout
        with patch('time.time', return_value=time.time() + 600):  # 10 minutes in the future
            # Challenge should be expired
            assert is_challenge_valid(challenge_id, challenge) is False
    
    def test_sign_and_verify_x509_challenge(self, test_cert_with_did):
        """Test signing a challenge with an X.509 private key and verifying it."""
        cert = test_cert_with_did['certificate']
        private_key = test_cert_with_did['private_key']
        
        # Generate a challenge
        _, challenge = generate_challenge()
        
        # Sign the challenge with the X.509 private key
        signature = sign_challenge_with_x509_key(challenge, private_key)
        
        # Verify the signature is valid
        assert verify_x509_challenge_signature(challenge, signature, cert) is True
        
        # Verify an invalid signature is rejected
        assert verify_x509_challenge_signature(challenge, "invalid_signature", cert) is False
        assert verify_x509_challenge_signature("invalid_challenge", signature, cert) is False
    
    def test_sign_and_verify_did_challenge(self, test_cert_with_did):
        """Test signing a challenge with a DID private key and verifying it."""
        private_key = test_cert_with_did['private_key']
        public_key = private_key.public_key()
        
        # Generate a challenge
        _, challenge = generate_challenge()
        
        # Sign the challenge with the DID private key
        signature = sign_challenge_with_did_key(challenge, private_key)
        
        # Verify the signature is valid
        assert verify_did_challenge_signature(challenge, signature, public_key) is True
        
        # Verify an invalid signature is rejected
        assert verify_did_challenge_signature(challenge, "invalid_signature", public_key) is False
        assert verify_did_challenge_signature("invalid_challenge", signature, public_key) is False
    
    def test_verify_dual_control(self, test_cert_with_did):
        """Test verifying dual control over both X.509 and DID."""
        cert = test_cert_with_did['certificate']
        private_key = test_cert_with_did['private_key']
        public_key = private_key.public_key()
        
        # Generate a challenge
        _, challenge = generate_challenge()
        
        # Sign the challenge with both X.509 and DID private keys
        x509_signature = sign_challenge_with_x509_key(challenge, private_key)
        did_signature = sign_challenge_with_did_key(challenge, private_key)
        
        # Verify dual control
        assert verify_dual_control(
            challenge, 
            x509_signature, 
            did_signature, 
            cert, 
            public_key
        ) is True
        
        # Verify dual control fails if one signature is invalid
        assert verify_dual_control(
            challenge, 
            "invalid_signature", 
            did_signature, 
            cert, 
            public_key
        ) is False
        
        assert verify_dual_control(
            challenge, 
            x509_signature, 
            "invalid_signature", 
            cert, 
            public_key
        ) is False

    @patch('src.x509.manager.X509Manager.monitor_certificate_status')
    def test_certificate_lifecycle_monitoring(self, mock_monitor, test_cert_with_did):
        """Test certificate lifecycle monitoring."""
        cert = test_cert_with_did['certificate']
        did = test_cert_with_did['did']
        
        # Create a manager instance
        manager = X509Manager()
        
        # Register a certificate-DID binding for monitoring
        manager.register_binding(cert, did)
        
        # Verify binding was registered
        binding = manager.get_binding_for_did(did)
        assert binding is not None
        assert binding['certificate'] == cert
        assert binding['did'] == did
        
        # Trigger monitoring process
        manager.run_monitoring_cycle()
        
        # Verify the monitoring function was called
        mock_monitor.assert_called()

    @patch('src.x509.csr_processor.create_did_document')
    def test_create_did_from_csr(self, mock_create_did_doc):
        """Test creating a DID from a Certificate Signing Request."""
        # Generate a private key and CSR for testing
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'Test CSR'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'StudentVC'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'test@example.com'),
        ])
        
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).sign(private_key, hashes.SHA256())
        
        # Mock the create_did_document function
        did = "did:web:example.com:csr:123456"
        mock_create_did_doc.return_value = (did, {"id": did})
        
        # Create a DID from the CSR
        created_did, did_doc = create_did_from_csr(csr, "web", domain="example.com")
        
        # Verify the DID was created
        assert created_did == did
        assert did_doc["id"] == did
        
        # Verify the create_did_document function was called with the correct parameters
        mock_create_did_doc.assert_called_once()
        
    def test_add_certificate_to_did_document(self, test_cert_with_did):
        """Test adding a certificate to a DID document."""
        cert = test_cert_with_did['certificate']
        did = test_cert_with_did['did']
        
        # Create a basic DID document
        did_doc = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": []
        }
        
        # Add the certificate to the DID document
        updated_did_doc = add_certificate_to_did_document(did_doc, cert)
        
        # Verify the X.509 context was added
        assert "https://w3id.org/security/suites/x509-2021/v1" in updated_did_doc["@context"]
        
        # Verify a verification method was added
        assert len(updated_did_doc["verificationMethod"]) > 0
        
        # Verify the verification method has the correct properties
        vm = updated_did_doc["verificationMethod"][0]
        assert vm["type"] == "X509Certificate2021"
        assert vm["controller"] == did
        assert "certificateChain" in vm 