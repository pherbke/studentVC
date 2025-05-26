#!/usr/bin/env python3
"""
Shibboleth Integration Tests for StudentVC

This test suite verifies the integration between Shibboleth federated identity 
and StudentVC verifiable credentials with X.509 certificates.

The tests cover:
1. SAML to VP request translation
2. Credential verification through DID and X.509 paths
3. SAML assertion generation from verified credentials
4. Selective disclosure with BBS+ signatures
5. Error handling and edge cases

Author: StudentVC Team
Date: April 5, 2025
"""

import unittest
import json
import uuid
import datetime
import base64
import sys
import os
from unittest.mock import patch, MagicMock

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Import the demo for testing (in a real environment, we'd import actual modules)
from examples.shibboleth_integration_demo import (
    MockSAMLRequest, 
    MockVerifiableCredential,
    MockX509Certificate,
    create_mock_certificate,
    mock_verify_credential,
    translate_saml_to_vp_request,
    create_verifiable_presentation,
    generate_saml_response,
    simulate_idp_verification
)

class TestShibbolethIntegration(unittest.TestCase):
    """Test the Shibboleth to VC integration functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create a mock SAML request
        self.sp_entity_id = "service.tu-berlin.de"
        self.idp_entity_id = "idp.tu-berlin.de"
        self.requested_attributes = [
            "eduPersonPrincipalName", 
            "displayName", 
            "mail", 
            "eduPersonAffiliation"
        ]
        self.saml_request = MockSAMLRequest(
            self.sp_entity_id, 
            self.idp_entity_id, 
            self.requested_attributes
        )
        
        # Create issuer DIDs and certificates
        self.tu_berlin_did = "did:web:edu:tu.berlin"
        self.fu_berlin_did = "did:web:edu:fu-berlin.de"
        
        # Create student DIDs
        self.student_did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        self.expired_student_did = "did:key:z6MkrTB3qySFV54VkhQP1LqR9U9ExsJJ7CzQTo4z44N28Jii"
        
        # Create certificates
        self.tu_cert = create_mock_certificate("TU Berlin", "TU Berlin CA", self.tu_berlin_did)
        self.fu_cert = create_mock_certificate("FU Berlin", "FU Berlin CA", self.fu_berlin_did)
        self.student_cert = create_mock_certificate("Student", "TU Berlin", self.student_did)
        
        # Create standard student claims
        self.student_claims = {
            "name": "Max Mustermann",
            "studentID": "s123456",
            "university": "Technical University of Berlin",
            "role": "student",
            "email": "max.mustermann@tu-berlin.de",
            "program": "Computer Science",
            "level": "Master"
        }
        
        # Create credentials
        self.credential = self._create_credential(
            self.tu_berlin_did, 
            self.student_did, 
            self.student_claims, 
            self.student_cert
        )
        
        # Create VP request
        self.vp_request = translate_saml_to_vp_request(self.saml_request)
        
        # Create presentation
        self.presentation = create_verifiable_presentation(self.credential, self.vp_request)
    
    def _create_credential(self, issuer_did, subject_did, claims, certificate=None):
        """Helper to create a credential"""
        vc = MockVerifiableCredential(
            issuer_did,
            subject_did,
            "StudentCredential",
            claims
        )
        if certificate:
            vc.add_x509_certificate(certificate)
        return vc.to_json()
    
    def test_saml_to_vp_request_translation(self):
        """Test translation from SAML request to VP request"""
        vp_request = translate_saml_to_vp_request(self.saml_request)
        
        # Check basic structure
        self.assertEqual(vp_request["type"], "VerifiablePresentationRequest")
        self.assertTrue("challenge" in vp_request)
        self.assertEqual(vp_request["domain"], self.idp_entity_id)
        self.assertTrue("presentationDefinition" in vp_request)
        self.assertEqual(vp_request["samlRequestId"], self.saml_request.id)
        
        # Check input descriptors
        descriptors = vp_request["presentationDefinition"]["input_descriptors"]
        self.assertTrue(len(descriptors) > 0)
        self.assertEqual(descriptors[0]["id"], "studentCredential")
        
        # Check that all requested attributes are mapped to constraints
        fields = descriptors[0]["constraints"]["fields"]
        self.assertEqual(len(fields), len(self.requested_attributes))
        
        # Check specific mappings
        email_field = next((f for f in fields if "email" in str(f["path"])), None)
        self.assertIsNotNone(email_field)
        
        name_field = next((f for f in fields if "name" in str(f["path"])), None)
        self.assertIsNotNone(name_field)
    
    def test_credential_verification_with_x509(self):
        """Test verification of credential with X.509 certificate"""
        verification_result = mock_verify_credential(self.credential, "x509")
        
        # Check overall result
        self.assertTrue(verification_result["verified"])
        
        # Check that X.509 verification was performed
        x509_check = next((c for c in verification_result["checks"] if c["type"] == "X509Verification"), None)
        self.assertIsNotNone(x509_check)
        self.assertTrue(x509_check["certificateVerified"])
    
    def test_credential_verification_with_did(self):
        """Test verification of credential with DID only"""
        # Create a credential without X.509
        did_only_credential = self._create_credential(
            self.tu_berlin_did, 
            self.student_did, 
            self.student_claims
        )
        
        verification_result = mock_verify_credential(did_only_credential, "did")
        
        # Check overall result
        self.assertTrue(verification_result["verified"])
        
        # Check that DID verification was performed
        did_check = next((c for c in verification_result["checks"] if c["type"] == "DIDVerification"), None)
        self.assertIsNotNone(did_check)
        self.assertTrue(did_check["verified"])
        
        # Check that no X.509 verification was performed
        x509_check = next((c for c in verification_result["checks"] if c["type"] == "X509Verification"), None)
        self.assertIsNone(x509_check)
    
    def test_credential_verification_with_dual_path(self):
        """Test verification of credential with both DID and X.509 paths"""
        verification_result = mock_verify_credential(self.credential, "dual")
        
        # Check overall result
        self.assertTrue(verification_result["verified"])
        
        # Check that both verification methods were performed
        did_check = next((c for c in verification_result["checks"] if c["type"] == "DIDVerification"), None)
        x509_check = next((c for c in verification_result["checks"] if c["type"] == "X509Verification"), None)
        
        self.assertIsNotNone(did_check)
        self.assertIsNotNone(x509_check)
        self.assertTrue(did_check["verified"])
        self.assertTrue(x509_check["certificateVerified"])
    
    def test_saml_response_generation(self):
        """Test generation of SAML response from verified presentation"""
        verification_result = mock_verify_credential(self.credential, "dual")
        
        # Add to a combined result (as would happen in the real flow)
        combined_result = {
            "verified": verification_result["verified"],
            "credentialResults": [verification_result],
            "vpValid": True,
            "checks": verification_result["checks"]
        }
        
        saml_response = generate_saml_response(combined_result, self.presentation, self.saml_request.id)
        
        # Decode and basic validation
        decoded_response = base64.b64decode(saml_response).decode()
        
        # Check that it's valid XML (simplified check)
        self.assertTrue(decoded_response.startswith("\n    <samlp:Response"))
        
        # Check for required elements
        self.assertIn(f'InResponseTo="{self.saml_request.id}"', decoded_response)
        self.assertIn("<saml:Assertion", decoded_response)
        self.assertIn("<saml:AttributeStatement>", decoded_response)
        self.assertIn("<saml:AuthnStatement>", decoded_response)
        
        # Check that credential attributes are included
        self.assertIn(self.student_claims["name"], decoded_response)
        self.assertIn(self.student_claims["studentID"], decoded_response)
        self.assertIn(self.student_claims["email"], decoded_response)
        
        # Check for X.509 information
        self.assertIn("x509:certificate", decoded_response)
        
        # Check for verification method
        self.assertIn("vc:did:x509", decoded_response)
    
    def test_idp_verification_successful(self):
        """Test the full IdP verification flow with successful verification"""
        # Create a presentation with a valid credential
        vp = create_verifiable_presentation(self.credential, self.vp_request)
        
        # Verify the presentation
        verification_result = simulate_idp_verification(vp, self.vp_request)
        
        # Check the results
        self.assertTrue(verification_result["verified"])
        self.assertTrue(verification_result["vpValid"])
        self.assertTrue(len(verification_result["credentialResults"]) > 0)
        self.assertTrue(verification_result["credentialResults"][0]["verified"])
    
    def test_idp_verification_failed_challenge(self):
        """Test verification failure due to wrong challenge"""
        # Create a VP request with a different challenge
        modified_request = self.vp_request.copy()
        modified_request["challenge"] = str(uuid.uuid4())
        
        # Verify the presentation against the modified request
        verification_result = simulate_idp_verification(self.presentation, modified_request)
        
        # Check that verification failed
        self.assertFalse(verification_result["verified"])
        self.assertFalse(verification_result["vpValid"])
    
    def test_idp_verification_failed_domain(self):
        """Test verification failure due to wrong domain"""
        # Create a VP request with a different domain
        modified_request = self.vp_request.copy()
        modified_request["domain"] = "wrong.domain.com"
        
        # Verify the presentation against the modified request
        verification_result = simulate_idp_verification(self.presentation, modified_request)
        
        # Check that verification failed
        self.assertFalse(verification_result["verified"])
        self.assertFalse(verification_result["vpValid"])
    
    def test_multiple_credentials_in_presentation(self):
        """Test handling multiple credentials in a presentation"""
        # Create a second credential from FU Berlin
        fu_credential = self._create_credential(
            self.fu_berlin_did,
            self.student_did,
            {
                **self.student_claims,
                "university": "Free University of Berlin",
                "studentID": "f789012"
            },
            self.fu_cert
        )
        
        # Create a presentation with both credentials
        multi_vp = {
            **self.presentation,
            "verifiableCredential": [self.credential, fu_credential]
        }
        
        # Verify the presentation
        verification_result = simulate_idp_verification(multi_vp, self.vp_request)
        
        # Check the results
        self.assertTrue(verification_result["verified"])
        self.assertEqual(len(verification_result["credentialResults"]), 2)
        
        # Both credentials should be verified
        self.assertTrue(all(result["verified"] for result in verification_result["credentialResults"]))
    
    @patch('examples.shibboleth_integration_demo.mock_verify_credential')
    def test_attribute_mapping_for_federation(self, mock_verify):
        """Test that credential attributes are correctly mapped to SAML attributes"""
        # Mock the verification to succeed
        mock_verify.return_value = {
            "verified": True,
            "checks": [
                {"type": "DIDVerification", "verified": True},
                {"type": "X509Verification", "certificateVerified": True}
            ]
        }
        
        # Create a specialized credential with eduPerson attributes
        edu_claims = {
            "eduPersonPrincipalName": "max.mustermann@tu-berlin.de",
            "eduPersonAffiliation": "student",
            "eduPersonEntitlement": "urn:mace:dir:entitlement:common-lib-terms",
            "schacHomeOrganization": "tu-berlin.de",
            "name": "Max Mustermann"
        }
        
        edu_credential = self._create_credential(
            self.tu_berlin_did,
            self.student_did,
            edu_claims,
            self.student_cert
        )
        
        # Create a presentation with this credential
        edu_vp = create_verifiable_presentation(edu_credential, self.vp_request)
        
        # Create a verification result
        verification_result = {
            "verified": True,
            "credentialResults": [
                mock_verify.return_value
            ],
            "vpValid": True,
            "checks": mock_verify.return_value["checks"]
        }
        
        # Generate SAML response
        saml_response = generate_saml_response(verification_result, edu_vp, self.saml_request.id)
        decoded_response = base64.b64decode(saml_response).decode()
        
        # Check that eduPerson attributes are included
        self.assertIn("eduPersonPrincipalName", decoded_response)
        self.assertIn("eduPersonAffiliation", decoded_response)
        self.assertIn("eduPersonEntitlement", decoded_response)
        self.assertIn("schacHomeOrganization", decoded_response)
    
    def test_verify_selective_disclosure_path(self):
        """Test that selective disclosure fields are correctly included in the VP request"""
        # Extract just a specific VP request for a subset of fields
        minimal_attributes = ["eduPersonPrincipalName", "displayName"]
        minimal_saml_request = MockSAMLRequest(self.sp_entity_id, self.idp_entity_id, minimal_attributes)
        
        minimal_vp_request = translate_saml_to_vp_request(minimal_saml_request)
        
        # Check that only the requested fields are included
        descriptors = minimal_vp_request["presentationDefinition"]["input_descriptors"]
        fields = descriptors[0]["constraints"]["fields"]
        
        # Should only have fields for the requested attributes
        self.assertEqual(len(fields), len(minimal_attributes))
        
        # Check field paths
        paths = [path for field in fields for path in field["path"]]
        
        # Should include studentID (mapped from eduPersonPrincipalName) and name fields
        self.assertTrue(any("studentID" in path for path in paths))
        self.assertTrue(any("name" in path for path in paths))
        
        # Should NOT include email or role fields
        self.assertFalse(any("email" in path for path in paths))
        self.assertFalse(any("role" in path for path in paths))


class TestShibbolethEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for Shibboleth integration"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create basic test objects
        self.sp_entity_id = "service.tu-berlin.de"
        self.idp_entity_id = "idp.tu-berlin.de"
        self.requested_attributes = ["eduPersonPrincipalName", "displayName"]
        self.saml_request = MockSAMLRequest(
            self.sp_entity_id, 
            self.idp_entity_id, 
            self.requested_attributes
        )
        self.vp_request = translate_saml_to_vp_request(self.saml_request)
    
    def test_empty_requested_attributes(self):
        """Test handling of SAML request with no requested attributes"""
        empty_saml_request = MockSAMLRequest(self.sp_entity_id, self.idp_entity_id, [])
        vp_request = translate_saml_to_vp_request(empty_saml_request)
        
        # Should still create a valid VP request
        self.assertEqual(vp_request["type"], "VerifiablePresentationRequest")
        self.assertTrue("challenge" in vp_request)
        
        # But the input descriptors should have no fields
        descriptors = vp_request["presentationDefinition"]["input_descriptors"]
        self.assertEqual(len(descriptors), 0)
    
    def test_unknown_requested_attributes(self):
        """Test handling of SAML request with unknown attributes"""
        unknown_saml_request = MockSAMLRequest(
            self.sp_entity_id, 
            self.idp_entity_id, 
            ["unknownAttribute1", "unknownAttribute2"]
        )
        vp_request = translate_saml_to_vp_request(unknown_saml_request)
        
        # Should still create a valid VP request
        self.assertEqual(vp_request["type"], "VerifiablePresentationRequest")
        
        # But the input descriptors should have no fields
        descriptors = vp_request["presentationDefinition"]["input_descriptors"]
        self.assertEqual(len(descriptors), 0)
    
    def test_missing_credential_attributes(self):
        """Test handling of credential missing requested attributes"""
        # Create a credential with minimal attributes
        issuer_did = "did:web:edu:tu.berlin"
        subject_did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        
        # Missing most of the standard fields
        minimal_claims = {
            "name": "Max Mustermann"
            # No studentID, email, role, etc.
        }
        
        vc = MockVerifiableCredential(issuer_did, subject_did, "StudentCredential", minimal_claims)
        credential = vc.to_json()
        
        # Create presentation
        vp = create_verifiable_presentation(credential, self.vp_request)
        
        # Verify - should still verify the credential but attributes will be missing
        verification_result = simulate_idp_verification(vp, self.vp_request)
        self.assertTrue(verification_result["verified"])
        
        # Generate SAML response
        saml_response = generate_saml_response(verification_result, vp, self.saml_request.id)
        decoded_response = base64.b64decode(saml_response).decode()
        
        # Should include the name attribute
        self.assertIn("name", decoded_response)
        self.assertIn("Max Mustermann", decoded_response)
        
        # Should NOT include studentID
        self.assertNotIn("studentID", decoded_response)
    
    def test_malformed_credential(self):
        """Test handling of malformed credential"""
        # Create an intentionally malformed credential
        malformed_credential = {
            "id": "urn:uuid:" + str(uuid.uuid4()),
            "type": ["VerifiableCredential"],
            # Missing required fields like issuer, issuanceDate, credentialSubject
        }
        
        # Create presentation with malformed credential
        vp = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": "VerifiablePresentation",
            "id": f"urn:uuid:{uuid.uuid4()}",
            "verifiableCredential": [malformed_credential],
            "proof": {
                "type": "Ed25519Signature2020",
                "created": datetime.datetime.now().isoformat(),
                "challenge": self.vp_request["challenge"],
                "domain": self.vp_request["domain"],
                "proofPurpose": "authentication",
                "verificationMethod": "did:example:123#key-1",
                "proofValue": "invalid_signature"
            }
        }
        
        # Mock verification to simulate failure
        with patch('examples.shibboleth_integration_demo.mock_verify_credential') as mock_verify:
            mock_verify.return_value = {
                "verified": False,
                "checks": [],
                "error": "Malformed credential missing required fields"
            }
            
            # Verify should fail
            verification_result = simulate_idp_verification(vp, self.vp_request)
            self.assertFalse(verification_result["verified"])
    
    def test_expired_credential(self):
        """Test handling of expired credential"""
        # Create an expired credential
        issuer_did = "did:web:edu:tu.berlin"
        subject_did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        
        # Standard claims
        claims = {
            "name": "Max Mustermann",
            "studentID": "s123456",
            "university": "Technical University of Berlin",
        }
        
        # Create the credential with custom expiration date in the past
        vc = MockVerifiableCredential(issuer_did, subject_did, "StudentCredential", claims)
        vc.expiration_date = (datetime.datetime.now() - datetime.timedelta(days=30)).isoformat()
        credential = vc.to_json()
        
        # Create presentation
        vp = create_verifiable_presentation(credential, self.vp_request)
        
        # Mock verification to simulate expiration failure
        with patch('examples.shibboleth_integration_demo.mock_verify_credential') as mock_verify:
            mock_verify.return_value = {
                "verified": False,
                "checks": [
                    {"type": "DIDVerification", "verified": True},
                    {"type": "CredentialStatus", "verified": False, "error": "Credential has expired"}
                ],
                "error": "Credential has expired"
            }
            
            # Verify should fail
            verification_result = simulate_idp_verification(vp, self.vp_request)
            self.assertFalse(verification_result["verified"])
    
    def test_revoked_credential(self):
        """Test handling of revoked credential"""
        # Create a credential (that we'll pretend is revoked)
        issuer_did = "did:web:edu:tu.berlin"
        subject_did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        
        # Standard claims
        claims = {
            "name": "Max Mustermann",
            "studentID": "s123456",
            "university": "Technical University of Berlin",
        }
        
        vc = MockVerifiableCredential(issuer_did, subject_did, "StudentCredential", claims)
        credential = vc.to_json()
        
        # Add revocation evidence (in a real system, this would be handled differently)
        credential["credentialStatus"] = {
            "id": "https://tu-berlin.de/status/1",
            "type": "RevocationList2021Status",
            "revocationListIndex": "123",
            "revocationListCredential": "https://tu-berlin.de/revocation-list-2021"
        }
        
        # Create presentation
        vp = create_verifiable_presentation(credential, self.vp_request)
        
        # Mock verification to simulate revocation failure
        with patch('examples.shibboleth_integration_demo.mock_verify_credential') as mock_verify:
            mock_verify.return_value = {
                "verified": False,
                "checks": [
                    {"type": "DIDVerification", "verified": True},
                    {"type": "RevocationCheck", "verified": False, "error": "Credential has been revoked"}
                ],
                "error": "Credential has been revoked"
            }
            
            # Verify should fail
            verification_result = simulate_idp_verification(vp, self.vp_request)
            self.assertFalse(verification_result["verified"])


if __name__ == "__main__":
    unittest.main() 