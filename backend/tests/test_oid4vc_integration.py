"""
Tests for OID4VC/OID4VP integration with X.509 certificates.

This file contains tests for the OpenID for Verifiable Credentials (OID4VC) and 
OpenID for Verifiable Presentations (OID4VP) integration with X.509 certificates, including:
1. Enhanced issuer metadata with X.509 certificate information
2. Dual-proof credential offers and presentations
3. X.509 metadata embedding in verifiable credentials
4. Verification of credentials using both DID and X.509 trust paths
5. Selective disclosure of certificate attributes

These tests validate that the implementation meets the requirements
for interoperable verifiable credentials using both DID and X.509 trust models.
"""

import base64
import datetime
import json
import os
import pytest
import time
import uuid
from unittest.mock import patch, MagicMock

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import NameOID

import requests

# Import the modules to be tested
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.verifier.verifier import Verifier
from src.issuer.issuer import Issuer
from src.x509.manager import X509Manager
from src.x509.did_binding import create_did_from_cert, verify_bidirectional_linkage
from src.x509.metadata import enhance_issuer_metadata, embed_x509_metadata_in_credential

class TestOID4VCIntegration:
    """Test suite for OID4VC/OID4VP integration with X.509 certificates."""

    @pytest.fixture(scope="class")
    def test_issuer_setup(self):
        """Set up a test issuer with X.509 certificate and DID."""
        # Generate a private key for testing
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'Test Issuer'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'StudentVC'),
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
        ).sign(private_key, hashes.SHA256())
        
        # Create a DID from the certificate
        did = create_did_from_cert(cert, "web", domain="example.com")
        
        # Initialize an issuer with the certificate and DID
        issuer = Issuer(did=did)
        
        # Store private key and certificate data in the issuer for testing
        issuer.private_key = private_key
        issuer.certificate = cert
        issuer.cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        return {
            'issuer': issuer,
            'certificate': cert,
            'private_key': private_key,
            'did': did
        }
    
    @pytest.fixture(scope="class")
    def test_verifier_setup(self):
        """Set up a test verifier."""
        # Initialize a verifier
        verifier = Verifier()
        
        return {
            'verifier': verifier
        }

    @patch('src.x509.metadata.get_issuer_certificate')
    def test_enhance_issuer_metadata(self, mock_get_cert, test_issuer_setup):
        """Test enhancing issuer metadata with X.509 certificate information."""
        issuer = test_issuer_setup['issuer']
        cert = test_issuer_setup['certificate']
        
        # Mock getting the issuer certificate
        mock_get_cert.return_value = cert
        
        # Create basic issuer metadata
        metadata = {
            "issuer": issuer.did,
            "credential_endpoint": "https://example.com/credentials",
            "credential_manifests": [],
            "display": {
                "name": "Test Issuer"
            }
        }
        
        # Enhance metadata with X.509 certificate information
        enhanced_metadata = enhance_issuer_metadata(metadata, issuer.did)
        
        # Verify X.509 certificate information is added
        assert "x509_certificate" in enhanced_metadata
        assert "certificate_chain" in enhanced_metadata["x509_certificate"]
        assert "subject_dn" in enhanced_metadata["x509_certificate"]
        assert "issuer_dn" in enhanced_metadata["x509_certificate"]
        
        # Verify the certificate data is correct
        cert_data = enhanced_metadata["x509_certificate"]
        assert "CN=Test Issuer" in cert_data["subject_dn"]
        assert "O=StudentVC" in cert_data["subject_dn"]
    
    def test_embed_x509_metadata_in_credential(self, test_issuer_setup):
        """Test embedding X.509 metadata in a verifiable credential."""
        issuer = test_issuer_setup['issuer']
        cert = test_issuer_setup['certificate']
        
        # Create a basic credential
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "https://example.com/credentials/1234",
            "type": ["VerifiableCredential", "StudentCredential"],
            "issuer": issuer.did,
            "issuanceDate": "2023-06-01T12:00:00Z",
            "credentialSubject": {
                "id": "did:key:subject123",
                "name": "Alice Student",
                "degree": "Computer Science"
            }
        }
        
        # Embed X.509 metadata in the credential
        credential_with_x509 = embed_x509_metadata_in_credential(credential, cert)
        
        # Verify X.509 context is added
        assert "https://w3id.org/security/suites/x509-2021/v1" in credential_with_x509["@context"]
        
        # Verify X.509 metadata is added
        assert "x509" in credential_with_x509
        assert "certificateChain" in credential_with_x509["x509"]
        
        # Verify the metadata contains the certificate data
        cert_data = cert.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_data).decode('ascii')
        assert cert_b64 in credential_with_x509["x509"]["certificateChain"]
    
    @patch('src.issuer.issuer.sign_credential')
    @patch('src.x509.metadata.embed_x509_metadata_in_credential')
    def test_dual_proof_credential_issuance(self, mock_embed, mock_sign, test_issuer_setup):
        """Test issuing a credential with dual proofs (DID and X.509)."""
        issuer = test_issuer_setup['issuer']
        cert = test_issuer_setup['certificate']
        
        # Set up mock functions
        mock_embed.return_value = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": "https://example.com/credentials/1234",
            "type": ["VerifiableCredential", "StudentCredential"],
            "issuer": issuer.did,
            "issuanceDate": "2023-06-01T12:00:00Z",
            "credentialSubject": {
                "id": "did:key:subject123",
                "name": "Alice Student",
                "degree": "Computer Science"
            },
            "x509": {
                "certificateChain": "base64encodedcert"
            }
        }
        
        mock_sign.return_value = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": "https://example.com/credentials/1234",
            "type": ["VerifiableCredential", "StudentCredential"],
            "issuer": issuer.did,
            "issuanceDate": "2023-06-01T12:00:00Z",
            "credentialSubject": {
                "id": "did:key:subject123",
                "name": "Alice Student",
                "degree": "Computer Science"
            },
            "x509": {
                "certificateChain": "base64encodedcert"
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2023-06-01T12:01:00Z",
                "verificationMethod": f"{issuer.did}#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "base64encodedsignature"
            }
        }
        
        # Create a basic credential
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "https://example.com/credentials/1234",
            "type": ["VerifiableCredential", "StudentCredential"],
            "issuer": issuer.did,
            "issuanceDate": "2023-06-01T12:00:00Z",
            "credentialSubject": {
                "id": "did:key:subject123",
                "name": "Alice Student",
                "degree": "Computer Science"
            }
        }
        
        # Issue the credential with dual proofs
        issued_credential = issuer.issue_credential_with_x509(credential, cert)
        
        # Verify the credential has X.509 metadata
        mock_embed.assert_called_once()
        
        # Verify the credential is signed
        mock_sign.assert_called_once()
        
        # Verify the returned credential has all expected elements
        assert issued_credential["proof"] is not None
        assert "x509" in issued_credential
    
    @patch('src.verifier.verifier.verify_credential')
    @patch('src.verifier.verifier.verify_x509_credential')
    def test_verify_dual_proof_credential(self, mock_verify_x509, mock_verify_did, test_verifier_setup, test_issuer_setup):
        """Test verifying a credential with dual proofs (DID and X.509)."""
        verifier = test_verifier_setup['verifier']
        issuer_did = test_issuer_setup['did']
        
        # Set up mock functions
        mock_verify_did.return_value = True
        mock_verify_x509.return_value = True
        
        # Create a credential with dual proofs
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": "https://example.com/credentials/1234",
            "type": ["VerifiableCredential", "StudentCredential"],
            "issuer": issuer_did,
            "issuanceDate": "2023-06-01T12:00:00Z",
            "credentialSubject": {
                "id": "did:key:subject123",
                "name": "Alice Student",
                "degree": "Computer Science"
            },
            "x509": {
                "certificateChain": "base64encodedcert"
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2023-06-01T12:01:00Z",
                "verificationMethod": f"{issuer_did}#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "base64encodedsignature"
            }
        }
        
        # Verify the credential
        is_valid = verifier.verify_credential_with_dual_proofs(credential)
        
        # Verify both verification methods were called
        mock_verify_did.assert_called_once()
        mock_verify_x509.assert_called_once()
        
        # Verify the credential is valid
        assert is_valid is True
        
        # Test failure if one verification method fails
        mock_verify_did.return_value = False
        mock_verify_x509.return_value = True
        
        is_valid = verifier.verify_credential_with_dual_proofs(credential)
        
        # Credential should be invalid if any proof is invalid
        assert is_valid is False
        
        # Reset mocks and test X.509 failure
        mock_verify_did.reset_mock()
        mock_verify_x509.reset_mock()
        mock_verify_did.return_value = True
        mock_verify_x509.return_value = False
        
        is_valid = verifier.verify_credential_with_dual_proofs(credential)
        
        # Credential should be invalid if any proof is invalid
        assert is_valid is False
    
    @patch('src.verifier.verifier.verify_presentation')
    @patch('src.verifier.verifier.verify_x509_presentation')
    def test_verify_dual_proof_presentation(self, mock_verify_x509, mock_verify_did, test_verifier_setup, test_issuer_setup):
        """Test verifying a presentation with dual proofs (DID and X.509)."""
        verifier = test_verifier_setup['verifier']
        issuer_did = test_issuer_setup['did']
        holder_did = "did:key:holder123"
        
        # Set up mock functions
        mock_verify_did.return_value = True
        mock_verify_x509.return_value = True
        
        # Create a credential with dual proofs
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": "https://example.com/credentials/1234",
            "type": ["VerifiableCredential", "StudentCredential"],
            "issuer": issuer_did,
            "issuanceDate": "2023-06-01T12:00:00Z",
            "credentialSubject": {
                "id": holder_did,
                "name": "Alice Student",
                "degree": "Computer Science"
            },
            "x509": {
                "certificateChain": "base64encodedcert"
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2023-06-01T12:01:00Z",
                "verificationMethod": f"{issuer_did}#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "base64encodedsignature"
            }
        }
        
        # Create a presentation with the credential
        presentation = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": [credential],
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2023-06-01T12:05:00Z",
                "verificationMethod": f"{holder_did}#key-1",
                "proofPurpose": "authentication",
                "proofValue": "base64encodedsignature",
                "challenge": "123456"
            }
        }
        
        # Verify the presentation
        is_valid = verifier.verify_presentation_with_dual_proofs(presentation, "123456")
        
        # Verify both verification methods were called
        mock_verify_did.assert_called_once()
        mock_verify_x509.assert_called_once()
        
        # Verify the presentation is valid
        assert is_valid is True
        
        # Test failure if one verification method fails
        mock_verify_did.return_value = False
        mock_verify_x509.return_value = True
        
        is_valid = verifier.verify_presentation_with_dual_proofs(presentation, "123456")
        
        # Presentation should be invalid if any proof is invalid
        assert is_valid is False
    
    def test_selective_disclosure_with_x509(self, test_issuer_setup):
        """Test selective disclosure of certificate attributes."""
        issuer = test_issuer_setup['issuer']
        cert = test_issuer_setup['certificate']
        
        # Extract certificate attributes
        subject_attrs = {
            "commonName": cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value,
            "organization": cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
        }
        
        # Create a credential with X.509 attributes
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": "https://example.com/credentials/1234",
            "type": ["VerifiableCredential", "StudentCredential"],
            "issuer": issuer.did,
            "issuanceDate": "2023-06-01T12:00:00Z",
            "credentialSubject": {
                "id": "did:key:subject123",
                "name": "Alice Student",
                "degree": "Computer Science",
                "issuerDetails": {
                    "x509": {
                        "commonName": subject_attrs["commonName"],
                        "organization": subject_attrs["organization"]
                    }
                }
            }
        }
        
        # Create a derived credential with only selected attributes
        derived_credential = issuer.create_selective_disclosure_credential(
            credential,
            ["credentialSubject.id", "credentialSubject.degree", "credentialSubject.issuerDetails.x509.commonName"]
        )
        
        # Verify only the selected attributes are included
        assert "id" in derived_credential["credentialSubject"]
        assert "degree" in derived_credential["credentialSubject"]
        assert "issuerDetails" in derived_credential["credentialSubject"]
        assert "x509" in derived_credential["credentialSubject"]["issuerDetails"]
        assert "commonName" in derived_credential["credentialSubject"]["issuerDetails"]["x509"]
        
        # Verify non-selected attributes are not included
        assert "name" not in derived_credential["credentialSubject"]
        assert "organization" not in derived_credential["credentialSubject"]["issuerDetails"]["x509"] 