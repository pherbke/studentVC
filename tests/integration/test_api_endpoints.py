#!/usr/bin/env python3
"""
API Endpoint Tests for StudentVC

This test suite verifies the implementation of API endpoints
in the StudentVC system, focusing on X.509 certificates,
DID binding, and verifiable credentials.

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
import requests
from unittest.mock import patch, MagicMock

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Mock API server for testing
class MockAPIServer:
    """Mock API server for testing endpoints"""
    
    def __init__(self):
        self.certificates = {}  # serial_number -> certificate
        self.credentials = {}   # id -> credential
        self.presentations = {} # id -> presentation
        self.dids = {}          # did -> did_document
        
        # Initialize with some test data
        self._initialize_test_data()
    
    def _initialize_test_data(self):
        """Initialize with test data"""
        # Add some test DIDs
        self.dids["did:web:edu:tu.berlin"] = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:edu:tu.berlin",
            "verificationMethod": [{
                "id": "did:web:edu:tu.berlin#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:edu:tu.berlin",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }],
            "authentication": ["did:web:edu:tu.berlin#key-1"],
            "assertionMethod": ["did:web:edu:tu.berlin#key-1"]
        }
        
        self.dids["did:web:edu:fu-berlin.de"] = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:edu:fu-berlin.de",
            "verificationMethod": [{
                "id": "did:web:edu:fu-berlin.de#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:edu:fu-berlin.de",
                "publicKeyMultibase": "z6MkrWtLYfEMFGjJ4tLGRvYiDWZw2NxF8ywEXtJRJvWSAb51"
            }],
            "authentication": ["did:web:edu:fu-berlin.de#key-1"],
            "assertionMethod": ["did:web:edu:fu-berlin.de#key-1"]
        }
    
    def generate_certificate(self, subject_dn, issuer_dn=None, subject_did=None, validity_days=365):
        """Generate a certificate"""
        if issuer_dn is None:
            issuer_dn = "CN=StudentVC Root CA"
        
        # Create a mock certificate
        serial_number = len(self.certificates) + 1
        not_before = datetime.datetime.now()
        not_after = not_before + datetime.timedelta(days=validity_days)
        
        certificate = {
            "serialNumber": str(serial_number),
            "subject": subject_dn,
            "issuer": issuer_dn,
            "notBefore": not_before.isoformat(),
            "notAfter": not_after.isoformat(),
            "subjectPublicKeyInfo": {
                "algorithm": "RSA",
                "keySize": 2048,
                "publicKey": "MOCK_PUBLIC_KEY"
            }
        }
        
        # Add subject alternative name with DID if provided
        if subject_did:
            certificate["extensions"] = [{
                "oid": "2.5.29.17",  # Subject Alternative Name
                "critical": False,
                "value": f"DID:{subject_did}"
            }]
        
        # Store the certificate
        self.certificates[serial_number] = certificate
        
        return certificate
    
    def generate_certificate_chain(self, subject_dn, subject_did=None, chain_length=3):
        """Generate a certificate chain"""
        chain = []
        
        # Generate root CA certificate
        root_ca_dn = "CN=StudentVC Root CA"
        root_ca = self.generate_certificate(root_ca_dn, root_ca_dn)
        chain.append(root_ca)
        
        # Generate intermediate CA certificate if chain_length > 2
        if chain_length > 2:
            intermediate_ca_dn = "CN=StudentVC Intermediate CA"
            intermediate_ca = self.generate_certificate(intermediate_ca_dn, root_ca_dn)
            chain.append(intermediate_ca)
            issuer_dn = intermediate_ca_dn
        else:
            issuer_dn = root_ca_dn
        
        # Generate end-entity certificate
        end_entity = self.generate_certificate(subject_dn, issuer_dn, subject_did)
        chain.append(end_entity)
        
        return chain
    
    def issue_credential(self, credential_request):
        """Issue a verifiable credential"""
        # Extract data from the request
        subject_id = credential_request.get("credentialSubject", {}).get("id")
        issuer = credential_request.get("issuer")
        
        if not subject_id or not issuer:
            return {
                "error": "Bad Request",
                "message": "Missing required fields: credentialSubject.id or issuer"
            }
        
        # Check if the issuer DID exists
        if issuer not in self.dids:
            return {
                "error": "Not Found",
                "message": f"Issuer DID not found: {issuer}"
            }
        
        # Create a credential ID if not provided
        if "id" not in credential_request:
            credential_request["id"] = f"urn:uuid:{uuid.uuid4()}"
        
        # Add issuance date if not provided
        if "issuanceDate" not in credential_request:
            credential_request["issuanceDate"] = datetime.datetime.now().isoformat()
        
        # Add a mock proof
        credential = credential_request.copy()
        credential["proof"] = {
            "type": "Ed25519Signature2020",
            "created": datetime.datetime.now().isoformat(),
            "verificationMethod": f"{issuer}#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "MOCK_SIGNATURE"
        }
        
        # Store the credential
        self.credentials[credential["id"]] = credential
        
        return credential
    
    def verify_presentation(self, presentation):
        """Verify a verifiable presentation"""
        # Extract data from the presentation
        holder = presentation.get("holder")
        
        if not holder:
            return {
                "verified": False,
                "checks": [],
                "errors": ["Missing required field: holder"]
            }
        
        # Check if the holder DID exists
        if holder not in self.dids:
            return {
                "verified": False,
                "checks": [],
                "errors": [f"Holder DID not found: {holder}"]
            }
        
        # Check for proof
        if "proof" not in presentation:
            return {
                "verified": False,
                "checks": [],
                "errors": ["Missing proof"]
            }
        
        # Check credentials in the presentation
        verification_checks = []
        verification_errors = []
        
        if "verifiableCredential" in presentation:
            credentials = presentation["verifiableCredential"]
            if not isinstance(credentials, list):
                credentials = [credentials]
            
            for credential in credentials:
                # Check if credential exists (for mock testing)
                if isinstance(credential, str) and credential in self.credentials:
                    credential = self.credentials[credential]
                
                # Check credential issuer
                issuer = credential.get("issuer")
                if not issuer:
                    verification_errors.append("Credential missing issuer")
                    continue
                
                if issuer not in self.dids:
                    verification_errors.append(f"Credential issuer not found: {issuer}")
                    continue
                
                # Check credential proof
                if "proof" not in credential:
                    verification_errors.append("Credential missing proof")
                    continue
                
                # Add successful check
                verification_checks.append({
                    "credential": credential.get("id", "unknown"),
                    "issuer": issuer,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "result": "success"
                })
        
        # Store the presentation
        presentation_id = presentation.get("id", f"urn:uuid:{uuid.uuid4()}")
        self.presentations[presentation_id] = presentation
        
        # Return verification result
        verified = len(verification_checks) > 0 and len(verification_errors) == 0
        return {
            "verified": verified,
            "checks": verification_checks,
            "errors": verification_errors
        }
    
    def verify_certificate_did_binding(self, certificate, did):
        """Verify DID binding in a certificate"""
        # Check if certificate has SAN extension with DID
        if "extensions" not in certificate:
            return {
                "verified": False,
                "errors": ["Certificate does not have extensions"]
            }
        
        # Find the SAN extension
        san_extension = None
        for extension in certificate["extensions"]:
            if extension["oid"] == "2.5.29.17":  # Subject Alternative Name
                san_extension = extension
                break
        
        if not san_extension:
            return {
                "verified": False,
                "errors": ["Certificate does not have SAN extension"]
            }
        
        # Check if SAN contains the DID
        if f"DID:{did}" not in san_extension["value"]:
            return {
                "verified": False,
                "errors": [f"SAN does not contain DID: {did}"]
            }
        
        return {
            "verified": True,
            "errors": []
        }
    
    def get_did_document(self, did):
        """Get a DID document"""
        if did not in self.dids:
            return {
                "error": "Not Found",
                "message": f"DID not found: {did}"
            }
        
        return self.dids[did]
    
    def get_certificate(self, serial_number):
        """Get a certificate by serial number"""
        if serial_number not in self.certificates:
            return {
                "error": "Not Found",
                "message": f"Certificate not found: {serial_number}"
            }
        
        return self.certificates[serial_number]
    
    def get_credential(self, credential_id):
        """Get a credential by ID"""
        if credential_id not in self.credentials:
            return {
                "error": "Not Found",
                "message": f"Credential not found: {credential_id}"
            }
        
        return self.credentials[credential_id]
    
    def get_presentation(self, presentation_id):
        """Get a presentation by ID"""
        if presentation_id not in self.presentations:
            return {
                "error": "Not Found",
                "message": f"Presentation not found: {presentation_id}"
            }
        
        return self.presentations[presentation_id]


# Create a mock requests Session for testing API calls
class MockSession:
    """Mock requests Session for testing API calls"""
    
    def __init__(self, api_server):
        self.api_server = api_server
        self.base_url = "https://api.studentvc.example.com"
    
    def get(self, url, *args, **kwargs):
        """Mock GET request"""
        response = MagicMock()
        
        if url.startswith(self.base_url):
            path = url[len(self.base_url):]
        else:
            path = url
        
        # DID resolution
        if path.startswith("/did/"):
            did = path[5:]
            result = self.api_server.get_did_document(did)
            response.status_code = 200 if "error" not in result else 404
            response.json.return_value = result
        
        # Certificate retrieval
        elif path.startswith("/certificates/"):
            serial_number = int(path[14:])
            result = self.api_server.get_certificate(serial_number)
            response.status_code = 200 if "error" not in result else 404
            response.json.return_value = result
        
        # Credential retrieval
        elif path.startswith("/credentials/"):
            credential_id = path[13:]
            result = self.api_server.get_credential(credential_id)
            response.status_code = 200 if "error" not in result else 404
            response.json.return_value = result
        
        # Presentation retrieval
        elif path.startswith("/presentations/"):
            presentation_id = path[15:]
            result = self.api_server.get_presentation(presentation_id)
            response.status_code = 200 if "error" not in result else 404
            response.json.return_value = result
        
        # Unknown endpoint
        else:
            response.status_code = 404
            response.json.return_value = {
                "error": "Not Found",
                "message": f"Endpoint not found: {path}"
            }
        
        return response
    
    def post(self, url, *args, **kwargs):
        """Mock POST request"""
        response = MagicMock()
        
        if url.startswith(self.base_url):
            path = url[len(self.base_url):]
        else:
            path = url
        
        # Certificate generation
        if path == "/certificates/generate":
            data = kwargs.get("json", {})
            subject_dn = data.get("subject")
            issuer_dn = data.get("issuer")
            subject_did = data.get("subjectDid")
            validity_days = data.get("validityDays", 365)
            
            if not subject_dn:
                response.status_code = 400
                response.json.return_value = {
                    "error": "Bad Request",
                    "message": "Missing required field: subject"
                }
            else:
                result = self.api_server.generate_certificate(
                    subject_dn, issuer_dn, subject_did, validity_days
                )
                response.status_code = 201
                response.json.return_value = result
        
        # Certificate chain generation
        elif path == "/certificates/generate-chain":
            data = kwargs.get("json", {})
            subject_dn = data.get("subject")
            subject_did = data.get("subjectDid")
            chain_length = data.get("chainLength", 3)
            
            if not subject_dn:
                response.status_code = 400
                response.json.return_value = {
                    "error": "Bad Request",
                    "message": "Missing required field: subject"
                }
            else:
                result = self.api_server.generate_certificate_chain(
                    subject_dn, subject_did, chain_length
                )
                response.status_code = 201
                response.json.return_value = result
        
        # Credential issuance
        elif path == "/credentials/issue":
            data = kwargs.get("json", {})
            result = self.api_server.issue_credential(data)
            
            if "error" in result:
                response.status_code = 400
                response.json.return_value = result
            else:
                response.status_code = 201
                response.json.return_value = result
        
        # Presentation verification
        elif path == "/presentations/verify":
            data = kwargs.get("json", {})
            result = self.api_server.verify_presentation(data)
            
            response.status_code = 200
            response.json.return_value = result
        
        # Certificate-DID binding verification
        elif path == "/certificates/verify-did-binding":
            data = kwargs.get("json", {})
            certificate = data.get("certificate")
            did = data.get("did")
            
            if not certificate or not did:
                response.status_code = 400
                response.json.return_value = {
                    "error": "Bad Request",
                    "message": "Missing required fields: certificate or did"
                }
            else:
                result = self.api_server.verify_certificate_did_binding(certificate, did)
                response.status_code = 200
                response.json.return_value = result
        
        # Unknown endpoint
        else:
            response.status_code = 404
            response.json.return_value = {
                "error": "Not Found",
                "message": f"Endpoint not found: {path}"
            }
        
        return response


class TestAPIEndpoints(unittest.TestCase):
    """Test API endpoints"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.api_server = MockAPIServer()
        self.session = MockSession(self.api_server)
        self.base_url = "https://api.studentvc.example.com"
    
    def test_certificate_generation(self):
        """Test certificate generation endpoint"""
        # Prepare request
        url = f"{self.base_url}/certificates/generate"
        data = {
            "subject": "CN=John Doe,O=TU Berlin,C=DE",
            "subjectDid": "did:web:edu:tu.berlin:users:johndoe"
        }
        
        # Send request
        response = self.session.post(url, json=data)
        
        # Check response
        self.assertEqual(response.status_code, 201)
        certificate = response.json()
        
        # Check certificate fields
        self.assertIn("serialNumber", certificate)
        self.assertEqual(certificate["subject"], data["subject"])
        self.assertIn("notBefore", certificate)
        self.assertIn("notAfter", certificate)
        
        # Check DID binding
        self.assertIn("extensions", certificate)
        san_extension = None
        for extension in certificate["extensions"]:
            if extension["oid"] == "2.5.29.17":  # Subject Alternative Name
                san_extension = extension
                break
        
        self.assertIsNotNone(san_extension)
        self.assertIn(f"DID:{data['subjectDid']}", san_extension["value"])
    
    def test_certificate_chain_generation(self):
        """Test certificate chain generation endpoint"""
        # Prepare request
        url = f"{self.base_url}/certificates/generate-chain"
        data = {
            "subject": "CN=John Doe,O=TU Berlin,C=DE",
            "subjectDid": "did:web:edu:tu.berlin:users:johndoe",
            "chainLength": 3
        }
        
        # Send request
        response = self.session.post(url, json=data)
        
        # Check response
        self.assertEqual(response.status_code, 201)
        chain = response.json()
        
        # Check chain length
        self.assertEqual(len(chain), 3)
        
        # Check certificate fields
        root_ca = chain[0]
        intermediate_ca = chain[1]
        end_entity = chain[2]
        
        self.assertEqual(root_ca["subject"], "CN=StudentVC Root CA")
        self.assertEqual(root_ca["issuer"], "CN=StudentVC Root CA")
        
        self.assertEqual(intermediate_ca["subject"], "CN=StudentVC Intermediate CA")
        self.assertEqual(intermediate_ca["issuer"], "CN=StudentVC Root CA")
        
        self.assertEqual(end_entity["subject"], data["subject"])
        self.assertEqual(end_entity["issuer"], "CN=StudentVC Intermediate CA")
        
        # Check DID binding in end-entity certificate
        self.assertIn("extensions", end_entity)
        san_extension = None
        for extension in end_entity["extensions"]:
            if extension["oid"] == "2.5.29.17":  # Subject Alternative Name
                san_extension = extension
                break
        
        self.assertIsNotNone(san_extension)
        self.assertIn(f"DID:{data['subjectDid']}", san_extension["value"])
    
    def test_credential_issuance(self):
        """Test credential issuance endpoint"""
        # Prepare request
        url = f"{self.base_url}/credentials/issue"
        data = {
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": "did:web:edu:tu.berlin",
            "credentialSubject": {
                "id": "did:web:edu:tu.berlin:users:johndoe",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science in Computer Science",
                    "university": "Technical University of Berlin"
                }
            }
        }
        
        # Send request
        response = self.session.post(url, json=data)
        
        # Check response
        self.assertEqual(response.status_code, 201)
        credential = response.json()
        
        # Check credential fields
        self.assertIn("id", credential)
        self.assertIn("type", credential)
        self.assertIn("UniversityDegreeCredential", credential["type"])
        self.assertEqual(credential["issuer"], data["issuer"])
        self.assertIn("issuanceDate", credential)
        
        # Check credential subject
        self.assertIn("credentialSubject", credential)
        subject = credential["credentialSubject"]
        self.assertEqual(subject["id"], data["credentialSubject"]["id"])
        self.assertEqual(subject["degree"]["type"], data["credentialSubject"]["degree"]["type"])
        self.assertEqual(subject["degree"]["name"], data["credentialSubject"]["degree"]["name"])
        
        # Check proof
        self.assertIn("proof", credential)
        proof = credential["proof"]
        self.assertEqual(proof["type"], "Ed25519Signature2020")
        self.assertEqual(proof["verificationMethod"], f"{data['issuer']}#key-1")
        self.assertEqual(proof["proofPurpose"], "assertionMethod")
    
    def test_presentation_verification(self):
        """Test presentation verification endpoint"""
        # First issue a credential
        issue_url = f"{self.base_url}/credentials/issue"
        credential_data = {
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": "did:web:edu:tu.berlin",
            "credentialSubject": {
                "id": "did:web:edu:tu.berlin:users:johndoe",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science in Computer Science",
                    "university": "Technical University of Berlin"
                }
            }
        }
        
        credential_response = self.session.post(issue_url, json=credential_data)
        credential = credential_response.json()
        
        # Now create a presentation
        presentation_data = {
            "type": ["VerifiablePresentation"],
            "id": f"urn:uuid:{uuid.uuid4()}",
            "holder": "did:web:edu:tu.berlin:users:johndoe",
            "verifiableCredential": [credential],
            "proof": {
                "type": "Ed25519Signature2020",
                "created": datetime.datetime.now().isoformat(),
                "verificationMethod": "did:web:edu:tu.berlin:users:johndoe#key-1",
                "proofPurpose": "authentication",
                "proofValue": "MOCK_SIGNATURE"
            }
        }
        
        # Verify the presentation
        verify_url = f"{self.base_url}/presentations/verify"
        response = self.session.post(verify_url, json=presentation_data)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        result = response.json()
        
        # Check verification result
        self.assertTrue(result["verified"])
        self.assertIn("checks", result)
        self.assertGreater(len(result["checks"]), 0)
        self.assertEqual(len(result["errors"]), 0)
        
        # Check verification checks
        check = result["checks"][0]
        self.assertEqual(check["issuer"], credential["issuer"])
        self.assertEqual(check["credential"], credential["id"])
        self.assertEqual(check["result"], "success")
    
    def test_certificate_did_binding_verification(self):
        """Test certificate-DID binding verification endpoint"""
        # First generate a certificate with DID binding
        gen_url = f"{self.base_url}/certificates/generate"
        gen_data = {
            "subject": "CN=John Doe,O=TU Berlin,C=DE",
            "subjectDid": "did:web:edu:tu.berlin:users:johndoe"
        }
        
        gen_response = self.session.post(gen_url, json=gen_data)
        certificate = gen_response.json()
        
        # Now verify the DID binding
        verify_url = f"{self.base_url}/certificates/verify-did-binding"
        verify_data = {
            "certificate": certificate,
            "did": "did:web:edu:tu.berlin:users:johndoe"
        }
        
        response = self.session.post(verify_url, json=verify_data)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        result = response.json()
        
        # Check verification result
        self.assertTrue(result["verified"])
        self.assertEqual(len(result["errors"]), 0)
    
    def test_certificate_did_binding_verification_with_mismatch(self):
        """Test certificate-DID binding verification with mismatched DID"""
        # First generate a certificate with DID binding
        gen_url = f"{self.base_url}/certificates/generate"
        gen_data = {
            "subject": "CN=John Doe,O=TU Berlin,C=DE",
            "subjectDid": "did:web:edu:tu.berlin:users:johndoe"
        }
        
        gen_response = self.session.post(gen_url, json=gen_data)
        certificate = gen_response.json()
        
        # Now verify with a different DID
        verify_url = f"{self.base_url}/certificates/verify-did-binding"
        verify_data = {
            "certificate": certificate,
            "did": "did:web:edu:fu-berlin.de:users:johndoe"
        }
        
        response = self.session.post(verify_url, json=verify_data)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        result = response.json()
        
        # Check verification result
        self.assertFalse(result["verified"])
        self.assertGreater(len(result["errors"]), 0)
    
    def test_certificate_retrieval(self):
        """Test certificate retrieval endpoint"""
        # First generate a certificate
        gen_url = f"{self.base_url}/certificates/generate"
        gen_data = {
            "subject": "CN=John Doe,O=TU Berlin,C=DE"
        }
        
        gen_response = self.session.post(gen_url, json=gen_data)
        certificate = gen_response.json()
        serial_number = certificate["serialNumber"]
        
        # Now retrieve the certificate
        get_url = f"{self.base_url}/certificates/{serial_number}"
        response = self.session.get(get_url)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        retrieved_cert = response.json()
        
        # Check certificate fields
        self.assertEqual(retrieved_cert["serialNumber"], serial_number)
        self.assertEqual(retrieved_cert["subject"], gen_data["subject"])
    
    def test_credential_retrieval(self):
        """Test credential retrieval endpoint"""
        # First issue a credential
        issue_url = f"{self.base_url}/credentials/issue"
        credential_data = {
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": "did:web:edu:tu.berlin",
            "credentialSubject": {
                "id": "did:web:edu:tu.berlin:users:johndoe",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science in Computer Science"
                }
            }
        }
        
        issue_response = self.session.post(issue_url, json=credential_data)
        credential = issue_response.json()
        credential_id = credential["id"]
        
        # Now retrieve the credential
        get_url = f"{self.base_url}/credentials/{credential_id}"
        response = self.session.get(get_url)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        retrieved_cred = response.json()
        
        # Check credential fields
        self.assertEqual(retrieved_cred["id"], credential_id)
        self.assertEqual(retrieved_cred["issuer"], credential_data["issuer"])
        self.assertEqual(
            retrieved_cred["credentialSubject"]["degree"]["name"],
            credential_data["credentialSubject"]["degree"]["name"]
        )
    
    def test_did_resolution(self):
        """Test DID resolution endpoint"""
        # Resolve a DID
        did = "did:web:edu:tu.berlin"
        url = f"{self.base_url}/did/{did}"
        response = self.session.get(url)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        did_doc = response.json()
        
        # Check DID document fields
        self.assertEqual(did_doc["id"], did)
        self.assertIn("verificationMethod", did_doc)
        self.assertIn("authentication", did_doc)
    
    def test_did_resolution_not_found(self):
        """Test DID resolution endpoint with non-existent DID"""
        # Resolve a non-existent DID
        did = "did:web:edu:nonexistent.university"
        url = f"{self.base_url}/did/{did}"
        response = self.session.get(url)
        
        # Check response
        self.assertEqual(response.status_code, 404)
        result = response.json()
        
        # Check error message
        self.assertIn("error", result)
        self.assertIn("message", result)
        self.assertEqual(result["error"], "Not Found")
    
    def test_missing_fields_in_certificate_generation(self):
        """Test certificate generation with missing fields"""
        # Prepare request without subject
        url = f"{self.base_url}/certificates/generate"
        data = {
            "validityDays": 365
        }
        
        # Send request
        response = self.session.post(url, json=data)
        
        # Check response
        self.assertEqual(response.status_code, 400)
        result = response.json()
        
        # Check error message
        self.assertIn("error", result)
        self.assertIn("message", result)
        self.assertEqual(result["error"], "Bad Request")
        self.assertIn("Missing required field", result["message"])
    
    def test_missing_fields_in_credential_issuance(self):
        """Test credential issuance with missing fields"""
        # Prepare request without credentialSubject.id
        url = f"{self.base_url}/credentials/issue"
        data = {
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": "did:web:edu:tu.berlin",
            "credentialSubject": {
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science in Computer Science"
                }
            }
        }
        
        # Send request
        response = self.session.post(url, json=data)
        
        # Check response
        self.assertEqual(response.status_code, 400)
        result = response.json()
        
        # Check error message
        self.assertIn("error", result)
        self.assertIn("message", result)
        self.assertEqual(result["error"], "Bad Request")
        self.assertIn("Missing required fields", result["message"])
    
    def test_nonexistent_endpoint(self):
        """Test accessing a non-existent endpoint"""
        url = f"{self.base_url}/nonexistent"
        response = self.session.get(url)
        
        # Check response
        self.assertEqual(response.status_code, 404)
        result = response.json()
        
        # Check error message
        self.assertIn("error", result)
        self.assertIn("message", result)
        self.assertEqual(result["error"], "Not Found")
        self.assertIn("Endpoint not found", result["message"])


if __name__ == "__main__":
    unittest.main() 