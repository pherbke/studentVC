#!/usr/bin/env python3
"""
Test X.509 and BBS+ Integration

This test suite validates the integration between X.509 certificates and BBS+ credentials
in the StudentVC system, focusing on the hybrid model where X.509 certificates
authenticate BBS+ credential issuers.

Author: StudentVC Team
Date: April 5, 2025
"""

import unittest
import json
import os
import sys
import datetime
import uuid
import base64
from unittest.mock import patch, MagicMock

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

class MockX509Certificate:
    """
    Mock implementation of an X.509 certificate
    """
    
    def __init__(self, subject_dn, issuer_dn, public_key, not_before=None, not_after=None, extensions=None):
        """Initialize certificate with core fields"""
        self.serial_number = str(uuid.uuid4().int)
        self.subject_dn = subject_dn
        self.issuer_dn = issuer_dn
        self.public_key = public_key
        
        self.not_before = not_before or datetime.datetime.now()
        self.not_after = not_after or (self.not_before + datetime.timedelta(days=365))
        
        self.extensions = extensions or []
        self.signature = "MOCK_SIGNATURE"
        self.signature_algorithm = "sha256WithRSAEncryption"
    
    def get_did_from_extensions(self):
        """Extract DID from certificate extensions"""
        for extension in self.extensions:
            if extension.get("oid") == "2.5.29.17":  # Subject Alternative Name
                for value in extension.get("value", []):
                    if value.startswith("did:"):
                        return value
        return None
    
    def verify_signature(self, issuer_public_key):
        """Verify the certificate signature (mock implementation)"""
        # In a real implementation, this would verify the signature using the issuer's public key
        return True
    
    def to_json(self):
        """Convert certificate to JSON representation"""
        return {
            "serialNumber": self.serial_number,
            "subject": self.subject_dn,
            "issuer": self.issuer_dn,
            "notBefore": self.not_before.isoformat(),
            "notAfter": self.not_after.isoformat(),
            "subjectPublicKeyInfo": {
                "algorithm": "RSA",
                "keySize": 2048,
                "publicKey": self.public_key
            },
            "extensions": self.extensions,
            "signatureAlgorithm": self.signature_algorithm,
            "signature": self.signature
        }


class MockBBSCredential:
    """
    Mock implementation of a BBS+ credential
    """
    
    def __init__(self, context=None, id=None, types=None, issuer=None, 
                 issuance_date=None, credential_subject=None, proof=None):
        """Initialize credential with core fields"""
        self.context = context or [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/bbs/v1"
        ]
        self.id = id or f"urn:uuid:{uuid.uuid4()}"
        self.types = types or ["VerifiableCredential", "UniversityDegreeCredential"]
        self.issuer = issuer or "did:example:issuer"
        self.issuance_date = issuance_date or datetime.datetime.now().isoformat()
        self.credential_subject = credential_subject or {
            "id": "did:example:subject",
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science"
            }
        }
        
        self.proof = proof or {
            "type": "BbsBlsSignature2020",
            "created": datetime.datetime.now().isoformat(),
            "verificationMethod": f"{self.issuer}#bbs-key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "mock_bbs_signature"
        }
    
    def to_json(self):
        """Convert credential to JSON representation"""
        return {
            "@context": self.context,
            "id": self.id,
            "type": self.types,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date,
            "credentialSubject": self.credential_subject,
            "proof": self.proof
        }


class MockX509KeyBinding:
    """
    Mock implementation of a key binding between X.509 and DID
    """
    
    def __init__(self, certificate, did, bbs_public_key):
        """Initialize key binding"""
        self.certificate = certificate
        self.did = did
        self.bbs_public_key = bbs_public_key
        self.binding_created = datetime.datetime.now().isoformat()
        self.binding_expires = (datetime.datetime.now() + datetime.timedelta(days=365)).isoformat()
        self.signature = "MOCK_KEY_BINDING_SIGNATURE"
    
    def verify(self):
        """Verify the key binding"""
        # In a real implementation, this would verify that the binding is valid
        # and signed by the private key corresponding to the certificate
        return True
    
    def to_json(self):
        """Convert key binding to JSON representation"""
        return {
            "certificate": self.certificate.to_json(),
            "did": self.did,
            "bbsPublicKey": self.bbs_public_key,
            "bindingCreated": self.binding_created,
            "bindingExpires": self.binding_expires,
            "signature": self.signature
        }


class MockCredentialIssuanceService:
    """
    Mock implementation of a credential issuance service
    """
    
    def __init__(self):
        """Initialize the service"""
        self.key_bindings = {}  # Maps DIDs to X.509 key bindings
        self.issued_credentials = []
    
    def register_key_binding(self, certificate, did, bbs_public_key):
        """Register a key binding between an X.509 certificate and a DID"""
        # Check if the certificate has the DID in its extensions
        cert_did = certificate.get_did_from_extensions()
        
        if cert_did and cert_did != did:
            raise ValueError(f"Certificate DID ({cert_did}) does not match provided DID ({did})")
        
        # Create the key binding
        key_binding = MockX509KeyBinding(certificate, did, bbs_public_key)
        self.key_bindings[did] = key_binding
        
        return key_binding
    
    def issue_credential(self, issuer_did, subject_did, claims, metadata=None):
        """Issue a BBS+ credential using the issuer's key binding"""
        # Check if the issuer has a registered key binding
        if issuer_did not in self.key_bindings:
            raise ValueError(f"No key binding found for issuer DID: {issuer_did}")
        
        key_binding = self.key_bindings[issuer_did]
        
        # Check if the key binding is valid
        if not key_binding.verify():
            raise ValueError("Key binding verification failed")
        
        # Check if the key binding has expired
        binding_expires = datetime.datetime.fromisoformat(key_binding.binding_expires)
        if binding_expires < datetime.datetime.now():
            raise ValueError("Key binding has expired")
        
        # Create the credential
        credential_subject = {"id": subject_did}
        credential_subject.update(claims)
        
        credential = MockBBSCredential(
            issuer=issuer_did,
            credential_subject=credential_subject,
            proof={
                "type": "BbsBlsSignature2020",
                "created": datetime.datetime.now().isoformat(),
                "verificationMethod": f"{issuer_did}#bbs-key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "mock_bbs_signature",
                "x509CertificateChain": {
                    "verificationMethod": f"{issuer_did}#x509-key-1",
                    "x509CertificateBinding": key_binding.to_json()
                }
            }
        )
        
        self.issued_credentials.append(credential)
        return credential
    
    def verify_credential(self, credential):
        """Verify a credential using X.509 chain for the issuer"""
        # Extract the issuer DID
        issuer_did = credential.issuer
        
        # Check if the credential has an X.509 certificate chain in the proof
        if "x509CertificateChain" not in credential.proof:
            raise ValueError("Credential does not have an X.509 certificate chain in the proof")
        
        # Extract the key binding
        x509_chain = credential.proof["x509CertificateChain"]
        
        if "x509CertificateBinding" not in x509_chain:
            raise ValueError("Credential does not have an X.509 certificate binding in the proof")
        
        binding_data = x509_chain["x509CertificateBinding"]
        
        # Check if the DID in the binding matches the issuer DID
        if binding_data["did"] != issuer_did:
            return False, f"Binding DID ({binding_data['did']}) does not match issuer DID ({issuer_did})"
        
        # In a real implementation, we would verify the X.509 certificate chain
        # and check that the binding signature is valid and made with the private key
        # corresponding to the X.509 certificate
        
        # For this mock, we'll just check if the binding is registered
        if issuer_did not in self.key_bindings:
            return False, f"No key binding found for issuer DID: {issuer_did}"
        
        # Check BBS+ signature (mock implementation)
        # In a real implementation, we would verify the BBS+ signature using the BBS+ public key
        
        return True, "Credential verified successfully"
    
    def create_selective_disclosure(self, credential, disclosure_frame):
        """Create a selective disclosure from a BBS+ credential"""
        # Check if the credential has a BBS+ proof
        if credential.proof["type"] != "BbsBlsSignature2020":
            raise ValueError("Credential does not have a BBS+ proof")
        
        # Extract the fields to disclose based on the frame
        disclosed_fields = {}
        for field, value in disclosure_frame.items():
            if field in credential.credential_subject:
                if isinstance(value, dict) and isinstance(credential.credential_subject[field], dict):
                    # Handle nested fields
                    disclosed_fields[field] = {}
                    for sub_field, sub_value in value.items():
                        if sub_field in credential.credential_subject[field] and sub_value:
                            disclosed_fields[field][sub_field] = credential.credential_subject[field][sub_field]
                elif value:
                    # Handle direct fields
                    disclosed_fields[field] = credential.credential_subject[field]
        
        # Create a new credential with only the disclosed fields
        disclosed_credential = MockBBSCredential(
            context=credential.context,
            id=credential.id,
            types=credential.types,
            issuer=credential.issuer,
            issuance_date=credential.issuance_date,
            credential_subject={
                "id": credential.credential_subject["id"]
            },
            proof={
                "type": "BbsBlsSignatureProof2020",
                "created": datetime.datetime.now().isoformat(),
                "verificationMethod": credential.proof["verificationMethod"],
                "proofPurpose": credential.proof["proofPurpose"],
                "nonce": str(uuid.uuid4()),
                "proofValue": "mock_bbs_selective_disclosure_proof",
                "x509CertificateChain": credential.proof.get("x509CertificateChain")
            }
        )
        
        # Add the disclosed fields
        for field, value in disclosed_fields.items():
            disclosed_credential.credential_subject[field] = value
        
        return disclosed_credential
    
    def verify_selective_disclosure(self, disclosed_credential):
        """Verify a selectively disclosed credential using X.509 chain for the issuer"""
        # Check if the credential has a BBS+ disclosure proof
        if disclosed_credential.proof["type"] != "BbsBlsSignatureProof2020":
            return False, "Credential does not have a BBS+ disclosure proof"
        
        # Check if the credential has an X.509 certificate chain in the proof
        if "x509CertificateChain" not in disclosed_credential.proof:
            return False, "Credential does not have an X.509 certificate chain in the proof"
        
        # In a real implementation, we would:
        # 1. Verify the X.509 certificate chain
        # 2. Check that the issuer's DID is bound to the certificate
        # 3. Verify the BBS+ disclosure proof using the issuer's BBS+ public key
        
        # For this mock, we'll just return success
        return True, "Selective disclosure verified successfully"


class TestX509BBSIntegration(unittest.TestCase):
    """
    Test the integration between X.509 certificates and BBS+ credentials
    """
    
    def setUp(self):
        """Set up test fixtures"""
        # Create mock X.509 certificates
        self.tu_berlin_cert = MockX509Certificate(
            "CN=TU Berlin Issuing CA,O=TU Berlin,OU=IT Services,L=Berlin,C=DE",
            "CN=StudentVC Intermediate CA,O=StudentVC Authority,OU=Certificate Authority,C=DE",
            "MOCK_TU_BERLIN_PUBLIC_KEY",
            extensions=[
                {
                    "oid": "2.5.29.17",  # Subject Alternative Name
                    "critical": False,
                    "value": ["did:web:edu:tu.berlin"]
                }
            ]
        )
        
        self.fu_berlin_cert = MockX509Certificate(
            "CN=FU Berlin Issuing CA,O=FU Berlin,OU=IT Department,L=Berlin,C=DE",
            "CN=StudentVC Intermediate CA,O=StudentVC Authority,OU=Certificate Authority,C=DE",
            "MOCK_FU_BERLIN_PUBLIC_KEY",
            extensions=[
                {
                    "oid": "2.5.29.17",  # Subject Alternative Name
                    "critical": False,
                    "value": ["did:web:edu:fu.berlin"]
                }
            ]
        )
        
        # Create DIDs
        self.tu_berlin_did = "did:web:edu:tu.berlin"
        self.fu_berlin_did = "did:web:edu:fu.berlin"
        self.student_did = "did:web:edu:tu.berlin:users:johndoe"
        
        # Create mock BBS+ keys
        self.tu_berlin_bbs_key = "MOCK_TU_BERLIN_BBS_PUBLIC_KEY"
        self.fu_berlin_bbs_key = "MOCK_FU_BERLIN_BBS_PUBLIC_KEY"
        
        # Create issuance service
        self.issuance_service = MockCredentialIssuanceService()
    
    def test_register_key_binding(self):
        """Test registering a key binding between X.509 certificate and DID"""
        # Register a key binding for TU Berlin
        key_binding = self.issuance_service.register_key_binding(
            self.tu_berlin_cert,
            self.tu_berlin_did,
            self.tu_berlin_bbs_key
        )
        
        # Check that the key binding was created correctly
        self.assertEqual(key_binding.did, self.tu_berlin_did)
        self.assertEqual(key_binding.bbs_public_key, self.tu_berlin_bbs_key)
        self.assertEqual(key_binding.certificate, self.tu_berlin_cert)
        
        # Try to register a binding with a mismatched DID
        with self.assertRaises(ValueError):
            self.issuance_service.register_key_binding(
                self.tu_berlin_cert,
                self.fu_berlin_did,  # This doesn't match the certificate's DID
                self.tu_berlin_bbs_key
            )
    
    def test_issue_credential_with_x509_binding(self):
        """Test issuing a credential with X.509 binding"""
        # Register a key binding for TU Berlin
        self.issuance_service.register_key_binding(
            self.tu_berlin_cert,
            self.tu_berlin_did,
            self.tu_berlin_bbs_key
        )
        
        # Issue a credential
        claims = {
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science",
                "university": "Technical University of Berlin",
                "graduationDate": "2023-05-15"
            },
            "name": "John Doe",
            "studentNumber": "TU-2020-12345"
        }
        
        credential = self.issuance_service.issue_credential(
            self.tu_berlin_did,
            self.student_did,
            claims
        )
        
        # Check that the credential was created correctly
        self.assertEqual(credential.issuer, self.tu_berlin_did)
        self.assertEqual(credential.credential_subject["id"], self.student_did)
        self.assertEqual(credential.credential_subject["degree"]["university"], "Technical University of Berlin")
        
        # Check that the X.509 certificate binding is included in the proof
        self.assertIn("x509CertificateChain", credential.proof)
        self.assertIn("x509CertificateBinding", credential.proof["x509CertificateChain"])
        
        binding = credential.proof["x509CertificateChain"]["x509CertificateBinding"]
        self.assertEqual(binding["did"], self.tu_berlin_did)
    
    def test_issue_credential_without_key_binding(self):
        """Test attempting to issue a credential without a key binding"""
        # Try to issue a credential without registering a key binding
        claims = {
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science"
            }
        }
        
        with self.assertRaises(ValueError):
            self.issuance_service.issue_credential(
                self.tu_berlin_did,
                self.student_did,
                claims
            )
    
    def test_verify_credential_with_x509_binding(self):
        """Test verifying a credential with X.509 binding"""
        # Register a key binding for TU Berlin
        self.issuance_service.register_key_binding(
            self.tu_berlin_cert,
            self.tu_berlin_did,
            self.tu_berlin_bbs_key
        )
        
        # Issue a credential
        claims = {
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science",
                "university": "Technical University of Berlin"
            }
        }
        
        credential = self.issuance_service.issue_credential(
            self.tu_berlin_did,
            self.student_did,
            claims
        )
        
        # Verify the credential
        is_valid, reason = self.issuance_service.verify_credential(credential)
        self.assertTrue(is_valid, reason)
    
    def test_verify_credential_with_invalid_binding(self):
        """Test verifying a credential with an invalid binding"""
        # Register a key binding for TU Berlin
        self.issuance_service.register_key_binding(
            self.tu_berlin_cert,
            self.tu_berlin_did,
            self.tu_berlin_bbs_key
        )
        
        # Issue a credential
        claims = {
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science"
            }
        }
        
        credential = self.issuance_service.issue_credential(
            self.tu_berlin_did,
            self.student_did,
            claims
        )
        
        # Tamper with the binding
        credential.proof["x509CertificateChain"]["x509CertificateBinding"]["did"] = self.fu_berlin_did
        
        # Verify the credential
        is_valid, reason = self.issuance_service.verify_credential(credential)
        self.assertFalse(is_valid)
        self.assertIn("does not match issuer DID", reason)
    
    def test_cross_university_credential_verification(self):
        """Test verifying credentials across different universities"""
        # Register key bindings for both universities
        self.issuance_service.register_key_binding(
            self.tu_berlin_cert,
            self.tu_berlin_did,
            self.tu_berlin_bbs_key
        )
        
        self.issuance_service.register_key_binding(
            self.fu_berlin_cert,
            self.fu_berlin_did,
            self.fu_berlin_bbs_key
        )
        
        # Issue credentials from both universities
        tu_berlin_claims = {
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science",
                "university": "Technical University of Berlin"
            }
        }
        
        fu_berlin_claims = {
            "degree": {
                "type": "MasterDegree",
                "name": "Master of Arts in Philosophy",
                "university": "Free University of Berlin"
            }
        }
        
        tu_credential = self.issuance_service.issue_credential(
            self.tu_berlin_did,
            self.student_did,
            tu_berlin_claims
        )
        
        fu_credential = self.issuance_service.issue_credential(
            self.fu_berlin_did,
            self.student_did,
            fu_berlin_claims
        )
        
        # Verify both credentials
        is_valid_tu, reason_tu = self.issuance_service.verify_credential(tu_credential)
        self.assertTrue(is_valid_tu, reason_tu)
        
        is_valid_fu, reason_fu = self.issuance_service.verify_credential(fu_credential)
        self.assertTrue(is_valid_fu, reason_fu)
    
    def test_selective_disclosure_with_x509_binding(self):
        """Test selective disclosure with X.509 binding"""
        # Register a key binding for TU Berlin
        self.issuance_service.register_key_binding(
            self.tu_berlin_cert,
            self.tu_berlin_did,
            self.tu_berlin_bbs_key
        )
        
        # Issue a rich credential
        claims = {
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science",
                "university": "Technical University of Berlin",
                "graduationDate": "2023-05-15",
                "gpa": 3.8
            },
            "name": "John Doe",
            "birthDate": "1995-07-23",
            "address": {
                "streetAddress": "123 Main St",
                "postalCode": "10001",
                "city": "Berlin",
                "country": "Germany"
            },
            "studentNumber": "TU-2020-12345",
            "email": "john.doe@tu-berlin.de"
        }
        
        credential = self.issuance_service.issue_credential(
            self.tu_berlin_did,
            self.student_did,
            claims
        )
        
        # Create a minimal disclosure
        minimal_frame = {
            "name": True,
            "degree": {
                "type": True,
                "name": True,
                "university": True
            }
        }
        
        disclosed_credential = self.issuance_service.create_selective_disclosure(
            credential,
            minimal_frame
        )
        
        # Check that the disclosed credential only contains the requested fields
        self.assertEqual(disclosed_credential.credential_subject["name"], "John Doe")
        self.assertEqual(disclosed_credential.credential_subject["degree"]["type"], "BachelorDegree")
        self.assertEqual(disclosed_credential.credential_subject["degree"]["name"], "Bachelor of Science in Computer Science")
        self.assertEqual(disclosed_credential.credential_subject["degree"]["university"], "Technical University of Berlin")
        
        # Check that other fields are not included
        self.assertNotIn("birthDate", disclosed_credential.credential_subject)
        self.assertNotIn("address", disclosed_credential.credential_subject)
        self.assertNotIn("studentNumber", disclosed_credential.credential_subject)
        self.assertNotIn("email", disclosed_credential.credential_subject)
        self.assertNotIn("gpa", disclosed_credential.credential_subject["degree"])
        self.assertNotIn("graduationDate", disclosed_credential.credential_subject["degree"])
        
        # Check that the X.509 certificate binding is preserved
        self.assertIn("x509CertificateChain", disclosed_credential.proof)
        
        # Verify the selective disclosure
        is_valid, reason = self.issuance_service.verify_selective_disclosure(disclosed_credential)
        self.assertTrue(is_valid, reason)
    
    def test_expired_certificate_binding(self):
        """Test handling of expired certificate bindings"""
        # Create a certificate with a past expiry date
        expired_cert = MockX509Certificate(
            "CN=Expired University,O=Expired University,L=Berlin,C=DE",
            "CN=StudentVC Intermediate CA,O=StudentVC Authority,OU=Certificate Authority,C=DE",
            "MOCK_EXPIRED_PUBLIC_KEY",
            not_before=datetime.datetime.now() - datetime.timedelta(days=730),
            not_after=datetime.datetime.now() - datetime.timedelta(days=365),
            extensions=[
                {
                    "oid": "2.5.29.17",  # Subject Alternative Name
                    "critical": False,
                    "value": ["did:web:edu:expired.university"]
                }
            ]
        )
        
        expired_did = "did:web:edu:expired.university"
        expired_bbs_key = "MOCK_EXPIRED_BBS_PUBLIC_KEY"
        
        # Register a key binding with the expired certificate
        # In a real implementation, this would likely fail, but for the mock we'll allow it
        key_binding = self.issuance_service.register_key_binding(
            expired_cert,
            expired_did,
            expired_bbs_key
        )
        
        # Manually expire the key binding
        key_binding.binding_expires = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
        
        # Try to issue a credential with the expired binding
        claims = {
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science"
            }
        }
        
        with self.assertRaises(ValueError):
            self.issuance_service.issue_credential(
                expired_did,
                self.student_did,
                claims
            )
    
    def test_multiple_did_methods(self):
        """Test support for different DID methods"""
        # Create certificates for different DID methods
        key_did_cert = MockX509Certificate(
            "CN=KEY DID Authority,O=StudentVC Authority,OU=KEY DID,L=Berlin,C=DE",
            "CN=StudentVC Intermediate CA,O=StudentVC Authority,OU=Certificate Authority,C=DE",
            "MOCK_KEY_DID_PUBLIC_KEY",
            extensions=[
                {
                    "oid": "2.5.29.17",  # Subject Alternative Name
                    "critical": False,
                    "value": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"]
                }
            ]
        )
        
        ion_did_cert = MockX509Certificate(
            "CN=ION DID Authority,O=StudentVC Authority,OU=ION DID,L=Berlin,C=DE",
            "CN=StudentVC Intermediate CA,O=StudentVC Authority,OU=Certificate Authority,C=DE",
            "MOCK_ION_DID_PUBLIC_KEY",
            extensions=[
                {
                    "oid": "2.5.29.17",  # Subject Alternative Name
                    "critical": False,
                    "value": ["did:ion:EiClkZMDxPKqC9c"]
                }
            ]
        )
        
        # Register key bindings for different DID methods
        key_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ion_did = "did:ion:EiClkZMDxPKqC9c"
        
        key_did_bbs_key = "MOCK_KEY_DID_BBS_PUBLIC_KEY"
        ion_did_bbs_key = "MOCK_ION_DID_BBS_PUBLIC_KEY"
        
        self.issuance_service.register_key_binding(
            key_did_cert,
            key_did,
            key_did_bbs_key
        )
        
        self.issuance_service.register_key_binding(
            ion_did_cert,
            ion_did,
            ion_did_bbs_key
        )
        
        # Issue credentials from different DID methods
        key_did_claims = {
            "certification": {
                "type": "ProfessionalCertification",
                "name": "Blockchain Developer Certification",
                "issuer": "Decentralized Identity Authority"
            }
        }
        
        ion_did_claims = {
            "membership": {
                "type": "ProfessionalMembership",
                "organization": "Decentralized Identity Foundation",
                "level": "Contributor"
            }
        }
        
        key_did_credential = self.issuance_service.issue_credential(
            key_did,
            self.student_did,
            key_did_claims
        )
        
        ion_did_credential = self.issuance_service.issue_credential(
            ion_did,
            self.student_did,
            ion_did_claims
        )
        
        # Verify both credentials
        is_valid_key, reason_key = self.issuance_service.verify_credential(key_did_credential)
        self.assertTrue(is_valid_key, reason_key)
        
        is_valid_ion, reason_ion = self.issuance_service.verify_credential(ion_did_credential)
        self.assertTrue(is_valid_ion, reason_ion)


if __name__ == "__main__":
    unittest.main() 