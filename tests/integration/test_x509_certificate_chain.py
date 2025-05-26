#!/usr/bin/env python3
"""
X.509 Certificate Chain Tests for StudentVC

This test suite verifies the functionality of X.509 certificate chains
in the StudentVC system, focusing on certificate generation, validation,
and verification across the chain.

Author: StudentVC Team
Date: April 5, 2025
"""

import unittest
import json
import uuid
import datetime
import os
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from unittest.mock import patch, MagicMock

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Import the necessary modules
from backend.src.x509.certificate import (
    generate_certificate_chain,
    verify_certificate_chain,
    save_certificate
)
from backend.src.x509.did_binding import (
    bind_did_to_certificate,
    find_did_in_certificate_san,
    verify_bidirectional_linkage
)


class TestX509CertificateChain(unittest.TestCase):
    """Test X.509 certificate chain functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create temporary directory for certificates
        self.temp_dir = os.path.join(os.path.dirname(__file__), "temp_certs")
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Set up DIDs for testing
        self.issuer_did = "did:web:edu:tu.berlin"
        self.subject_did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        
        # Generate a certificate chain for testing
        result = generate_certificate_chain(
            root_ca_cn="TU Berlin Root CA",
            intermediate_ca_cn="TU Berlin Intermediate CA",
            end_entity_cn="TU Berlin Student",
            subject_alternative_names=[f"did:{self.issuer_did}"]
        )
        
        self.root_ca_cert = result["root_ca_cert"]
        self.intermediate_ca_cert = result["intermediate_ca_cert"]
        self.end_entity_cert = result["end_entity_cert"]
        self.root_ca_key = result["root_ca_key"]
        self.intermediate_ca_key = result["intermediate_ca_key"]
        self.end_entity_key = result["end_entity_key"]
        
        # Save certificates to files
        self.root_ca_path = os.path.join(self.temp_dir, "root_ca.pem")
        self.intermediate_ca_path = os.path.join(self.temp_dir, "intermediate_ca.pem")
        self.end_entity_path = os.path.join(self.temp_dir, "end_entity.pem")
        
        save_certificate(self.root_ca_cert, self.root_ca_path)
        save_certificate(self.intermediate_ca_cert, self.intermediate_ca_path)
        save_certificate(self.end_entity_cert, self.end_entity_path)
    
    def tearDown(self):
        """Clean up after tests"""
        # Remove certificate files
        for file in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, file))
        # Remove directory
        os.rmdir(self.temp_dir)
    
    def test_certificate_chain_generation(self):
        """Test that certificate chain generation works correctly"""
        # Verify that certificates were created
        self.assertIsNotNone(self.root_ca_cert)
        self.assertIsNotNone(self.intermediate_ca_cert)
        self.assertIsNotNone(self.end_entity_cert)
        
        # Verify certificate relationships
        # Root CA is self-signed
        self.assertEqual(
            self.root_ca_cert.subject, 
            self.root_ca_cert.issuer
        )
        
        # Intermediate CA is signed by Root CA
        self.assertEqual(
            self.root_ca_cert.subject, 
            self.intermediate_ca_cert.issuer
        )
        
        # End entity is signed by Intermediate CA
        self.assertEqual(
            self.intermediate_ca_cert.subject, 
            self.end_entity_cert.issuer
        )
        
        # Verify certificate constraints
        # Root CA should have CA:TRUE
        basic_constraints = self.root_ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertTrue(basic_constraints.value.ca)
        
        # Intermediate CA should have CA:TRUE
        basic_constraints = self.intermediate_ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertTrue(basic_constraints.value.ca)
        
        # End entity should have CA:FALSE
        basic_constraints = self.end_entity_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertFalse(basic_constraints.value.ca)
    
    def test_certificate_chain_validation(self):
        """Test certificate chain validation"""
        # Build the certificate chain
        chain = [
            self.end_entity_cert,
            self.intermediate_ca_cert,
            self.root_ca_cert
        ]
        
        # Validate the certificate chain
        result = verify_certificate_chain(chain, self.root_ca_cert)
        self.assertTrue(result["valid"])
        self.assertEqual(len(result["chain"]), 3)
    
    def test_incomplete_chain_validation(self):
        """Test validation with incomplete chain"""
        # Build an incomplete chain (missing intermediate)
        chain = [
            self.end_entity_cert,
            self.root_ca_cert
        ]
        
        # Validate the incomplete chain
        result = verify_certificate_chain(chain, self.root_ca_cert)
        self.assertFalse(result["valid"])
        self.assertIn("incomplete", result["error"].lower())
    
    def test_invalid_chain_validation(self):
        """Test validation with invalid chain"""
        # Create a different root CA
        different_ca_result = generate_certificate_chain(
            root_ca_cn="Different Root CA",
            intermediate_ca_cn="Different Intermediate CA",
            end_entity_cn="Different End Entity"
        )
        
        different_root_ca = different_ca_result["root_ca_cert"]
        
        # Build a chain with the wrong root
        chain = [
            self.end_entity_cert,
            self.intermediate_ca_cert,
            different_root_ca  # Wrong root CA
        ]
        
        # Validate the chain with the correct trust anchor
        result = verify_certificate_chain(chain, self.root_ca_cert)
        self.assertFalse(result["valid"])
    
    def test_expired_certificate_validation(self):
        """Test validation with expired certificate"""
        # Create a certificate chain with short validity
        expired_chain = generate_certificate_chain(
            root_ca_cn="Expired Root CA",
            intermediate_ca_cn="Expired Intermediate CA",
            end_entity_cn="Expired End Entity",
            root_ca_days_valid=1,
            intermediate_ca_days_valid=1,
            end_entity_days_valid=0  # Expired immediately
        )
        
        # Wait a moment to ensure it's expired
        import time
        time.sleep(1)
        
        # Build the chain
        chain = [
            expired_chain["end_entity_cert"],
            expired_chain["intermediate_ca_cert"],
            expired_chain["root_ca_cert"]
        ]
        
        # Validate the chain
        result = verify_certificate_chain(chain, expired_chain["root_ca_cert"])
        self.assertFalse(result["valid"])
        self.assertIn("expired", result["error"].lower())
    
    def test_did_binding_in_certificate(self):
        """Test that DID binding in certificates works correctly"""
        # Create a certificate with a DID in the SAN
        did_cert_result = generate_certificate_chain(
            root_ca_cn="DID Root CA",
            intermediate_ca_cn="DID Intermediate CA",
            end_entity_cn="DID End Entity",
            subject_alternative_names=[f"did:{self.issuer_did}"]
        )
        
        end_entity_cert = did_cert_result["end_entity_cert"]
        
        # Extract the DID from the certificate
        extracted_did = find_did_in_certificate_san(end_entity_cert)
        
        # Verify it matches what we put in
        self.assertEqual(extracted_did, self.issuer_did)
    
    def test_bidirectional_linkage(self):
        """Test bidirectional linkage between DID and certificate"""
        # Mock the DID document resolution
        mock_did_doc = {
            "id": self.issuer_did,
            "verificationMethod": [
                {
                    "id": f"{self.issuer_did}#key-x509-1",
                    "type": "X509Credential",
                    "controller": self.issuer_did,
                    "x509CertificateChain": [
                        self.end_entity_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                        self.intermediate_ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                        self.root_ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                    ]
                }
            ]
        }
        
        with patch('backend.src.did.resolver.resolve_did', return_value=mock_did_doc):
            # Verify bidirectional linkage
            result = verify_bidirectional_linkage(self.end_entity_cert, self.issuer_did)
            self.assertTrue(result["verified"])
            self.assertEqual(result["did"], self.issuer_did)
            self.assertEqual(result["certificate"], self.end_entity_cert)
    
    def test_certificate_chain_in_credential(self):
        """Test including a certificate chain in a verifiable credential"""
        # Create a mock credential with a certificate chain
        mock_credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "X509Credential"],
            "issuer": self.issuer_did,
            "issuanceDate": datetime.datetime.now().isoformat(),
            "credentialSubject": {
                "id": self.subject_did,
                "name": "Max Mustermann"
            },
            "proof": {
                "type": "X509Certificate2021",
                "created": datetime.datetime.now().isoformat(),
                "verificationMethod": f"{self.issuer_did}#key-x509-1",
                "proofPurpose": "assertionMethod",
                "x509CertificateChain": [
                    self.end_entity_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                    self.intermediate_ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                    self.root_ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                ]
            }
        }
        
        # Verify that the certificate chain is properly included
        self.assertEqual(len(mock_credential["proof"]["x509CertificateChain"]), 3)
        
        # Verify the first certificate in the chain contains the issuer DID
        first_cert_pem = mock_credential["proof"]["x509CertificateChain"][0]
        first_cert = x509.load_pem_x509_certificate(first_cert_pem.encode())
        
        extracted_did = find_did_in_certificate_san(first_cert)
        self.assertEqual(extracted_did, self.issuer_did)
    
    def test_certificate_revocation(self):
        """Test certificate revocation checking"""
        # This would test CRL or OCSP checking, which requires additional setup
        # For now, we'll just mock the revocation check
        
        with patch('backend.src.x509.certificate.check_certificate_revocation', return_value={"revoked": False}):
            # Verify the certificate is not revoked
            result = verify_certificate_chain([self.end_entity_cert, self.intermediate_ca_cert, self.root_ca_cert], 
                                             self.root_ca_cert, 
                                             check_revocation=True)
            self.assertTrue(result["valid"])
        
        with patch('backend.src.x509.certificate.check_certificate_revocation', return_value={"revoked": True, "reason": "keyCompromise"}):
            # Verify the certificate is revoked
            result = verify_certificate_chain([self.end_entity_cert, self.intermediate_ca_cert, self.root_ca_cert], 
                                             self.root_ca_cert, 
                                             check_revocation=True)
            self.assertFalse(result["valid"])
            self.assertIn("revoked", result["error"].lower())


if __name__ == "__main__":
    unittest.main() 