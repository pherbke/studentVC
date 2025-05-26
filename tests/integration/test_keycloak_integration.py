#!/usr/bin/env python3
"""
Test: Keycloak Integration with StudentVC and TU Berlin Authenticator

This test demonstrates the integration of Keycloak authentication with the StudentVC system:
1. Keycloak server setup and configuration
2. Authentication via Keycloak
3. Integration with TU Berlin Authenticator for MFA
4. Credential issuance using Keycloak-authenticated sessions
5. Verification of issued credentials

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
import hashlib
import time
from unittest.mock import patch, MagicMock
import requests

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Import TU Berlin Authenticator from existing code
from tests.integration.test_end_to_end_x509_shibboleth import MockUniversityAuthenticator

# Add missing class definitions at the top of the file after imports
class MockX509Certificate:
    """Mock X.509 certificate for testing"""
    
    def __init__(self, subject_dn):
        """Initialize mock certificate with subject DN"""
        self.subject_dn = subject_dn
        self.serial_number = str(uuid.uuid4())
        self.not_before = datetime.datetime.now() - datetime.timedelta(days=1)
        self.not_after = datetime.datetime.now() + datetime.timedelta(days=365)
        self.issuer_dn = None  # Will be set by the caller if needed
        self.extensions = {}
    
    def to_pem(self):
        """Return mock PEM representation"""
        return f"-----BEGIN CERTIFICATE-----\nMOCK_CERTIFICATE_{self.subject_dn}\n-----END CERTIFICATE-----"
    
    def get_subject_dn(self):
        """Return subject DN"""
        return self.subject_dn
    
    def get_issuer_dn(self):
        """Return issuer DN"""
        return self.issuer_dn
    
    def get_serial_number(self):
        """Return serial number"""
        return self.serial_number
    
    def get_not_before(self):
        """Return not before date"""
        return self.not_before
    
    def get_not_after(self):
        """Return not after date"""
        return self.not_after
    
    def get_extension(self, oid):
        """Return extension value for OID"""
        return self.extensions.get(oid)
    
    def verify(self, issuer_cert):
        """Verify certificate against issuer"""
        # In a real implementation, this would verify the signature
        # For testing, we'll just check if the issuer DNs match
        return issuer_cert.get_subject_dn() == self.get_issuer_dn()

class MockBBSKey:
    """Mock BBS+ key for testing"""
    
    def __init__(self):
        """Initialize mock BBS+ key"""
        self.key_id = str(uuid.uuid4())
        self.verification_method = f"did:web:tu-berlin.de#bbs-{self.key_id}"
    
    def sign(self, messages):
        """Mock sign messages"""
        # In a real implementation, this would use BBS+ to sign the messages
        # For testing, return a mock signature
        return f"MOCK_BBS_SIGNATURE_{hash(str(messages))}"
    
    def verify(self, signature, messages):
        """Mock verify signature"""
        # In a real implementation, this would verify the BBS+ signature
        # For testing, we'll verify that the signature contains the hash of the messages
        expected_signature = f"MOCK_BBS_SIGNATURE_{hash(str(messages))}"
        return signature == expected_signature
    
    def get_verification_method(self):
        """Return verification method for the key"""
        return self.verification_method
    
    def get_public_key(self):
        """Return public key in JWK format"""
        return {
            "kty": "EC",
            "crv": "BLS12381_G2",
            "x": "MOCK_PUBLIC_KEY_X_COORDINATE",
            "kid": self.key_id
        }

class MockKeycloakServer:
    """Mock Keycloak server for testing"""
    
    def __init__(self, users=None):
        """Initialize mock Keycloak server"""
        self.users = users or {}
        self.sessions = {}
        self.tokens = {}
        self.realm = "tu-berlin"
        self.client_id = "student-vc"
        self.client_secret = "test-client-secret"
        self.base_url = "https://keycloak.example.org/auth"
        
        # Initialize with default users if none provided
        if not self.users:
            self.users = {
                "alice": {
                    "id": "4c52491b-6c78-4716-81ba-7dcb970aa06e",
                    "username": "alice",
                    "email": "alice@student.tu-berlin.de",
                    "first_name": "Alice",
                    "last_name": "Johnson",
                    "mfa_enabled": True,
                    "password": "password123",
                    "attributes": {
                        "StudentID": ["s12345"],
                        "Program": ["Computer Science"],
                        "EnrollmentDate": ["2022-09-01"],
                        "ExpectedGraduationDate": ["2026-08-31"],
                        "FirstName": ["Alice"],
                        "LastName": ["Johnson"]
                    },
                    "roles": ["student"]
                },
                "bob": {
                    "id": "7f8d9e10-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
                    "username": "bob",
                    "email": "bob@faculty.tu-berlin.de",
                    "first_name": "Bob",
                    "last_name": "Smith",
                    "mfa_enabled": False,
                    "password": "faculty456",
                    "attributes": {
                        "EmployeeID": ["f67890"],
                        "Department": ["Computer Science"],
                        "Position": ["Professor"],
                        "FirstName": ["Bob"],
                        "LastName": ["Smith"]
                    },
                    "roles": ["faculty"]
                }
            }
        
        # MFA configuration
        self.mfa_config = {
            "enabled": True,
            "required_for_roles": ["faculty"],
            "preferred_method": "otp"
        }
    
    def authenticate(self, username, password, client_id=None, client_secret=None):
        """Authenticate a user and return a session and token"""
        if client_id != self.client_id or client_secret != self.client_secret:
            return {"error": "Invalid client credentials"}, 401
        
        user = self.users.get(username)
        if not user or user["password"] != password:
            return {"error": "Invalid username or password"}, 401
        
        # Create session
        session_id = f"KC_SESSION_{uuid.uuid4()}"
        token = self._generate_token(user)
        
        # Store session
        self.sessions[session_id] = {
            "user_id": user["id"],
            "created": datetime.datetime.now(),
            "expires": datetime.datetime.now() + datetime.timedelta(hours=1),
            "mfa_complete": not user["mfa_enabled"],  # If MFA is enabled, mark as incomplete
            "ip_address": "127.0.0.1",
            "user_agent": "Mozilla/5.0 (Test)"
        }
        
        self.tokens[token["access_token"]] = {
            "user_id": user["id"],
            "session_id": session_id,
            "expires": datetime.datetime.now() + datetime.timedelta(minutes=15)
        }
        
        response = {
            "session_id": session_id,
            "token": token,
            "mfa_required": user["mfa_enabled"] and not self.sessions[session_id]["mfa_complete"]
        }
        
        return response, 200
    
    def complete_mfa(self, session_id, mfa_code, username):
        """Complete multi-factor authentication for a session"""
        if session_id not in self.sessions:
            return {"error": "Invalid session"}, 401
        
        session = self.sessions[session_id]
        user_id = session["user_id"]
        
        # Find user by ID
        user = None
        for u in self.users.values():
            if u["id"] == user_id:
                user = u
                break
        
        if not user or user["username"] != username:
            return {"error": "Invalid user for session"}, 401
        
        if not user["mfa_enabled"]:
            return {"error": "MFA not enabled for this user"}, 400
        
        # In a real implementation, we would verify the MFA code
        # For this mock, we'll just check if it's a non-empty string
        if not mfa_code:
            return {"error": "Invalid MFA code"}, 401
        
        # Mark session as MFA complete
        self.sessions[session_id]["mfa_complete"] = True
        
        # Generate new token that includes MFA completion
        token = self._generate_token(user, mfa_complete=True)
        
        # Update token in storage
        for t in list(self.tokens.keys()):
            if self.tokens[t]["session_id"] == session_id:
                del self.tokens[t]
        
        self.tokens[token["access_token"]] = {
            "user_id": user["id"],
            "session_id": session_id,
            "expires": datetime.datetime.now() + datetime.timedelta(minutes=15),
            "mfa_complete": True
        }
        
        return {
            "session_id": session_id,
            "token": token,
            "mfa_complete": True
        }, 200
    
    def validate_token(self, access_token):
        """Validate an access token and return user info"""
        token_info = self.tokens.get(access_token)
        if not token_info:
            return {"error": "Invalid token"}, 401
        
        if datetime.datetime.now() > token_info["expires"]:
            return {"error": "Token expired"}, 401
        
        # Find user by ID
        user = None
        for u in self.users.values():
            if u["id"] == token_info["user_id"]:
                user = u
                break
        
        if not user:
            return {"error": "User not found"}, 404
        
        # Check if MFA is required but not completed
        session = self.sessions.get(token_info["session_id"])
        if not session:
            return {"error": "Session not found"}, 404
        
        if user["mfa_enabled"] and not session["mfa_complete"]:
            return {"error": "MFA required but not completed"}, 403
        
        # Return user info
        user_info = {
            "sub": user["id"],
            "preferred_username": user["username"],
            "email": user["email"],
            "given_name": user["first_name"],
            "family_name": user["last_name"],
            "roles": user["roles"],
            "attributes": user["attributes"],
            "mfa_complete": session["mfa_complete"]
        }
        
        return user_info, 200
    
    def logout(self, session_id):
        """Logout a user session"""
        if session_id not in self.sessions:
            return {"error": "Invalid session"}, 404
        
        # Remove session
        del self.sessions[session_id]
        
        # Remove associated tokens
        tokens_to_remove = []
        for token, info in self.tokens.items():
            if info["session_id"] == session_id:
                tokens_to_remove.append(token)
        
        for token in tokens_to_remove:
            del self.tokens[token]
        
        return {"success": True}, 200
    
    def _generate_token(self, user, mfa_complete=False):
        """Generate a JWT token (simplified for testing)"""
        now = int(time.time())
        
        # Create access token
        access_token = f"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.{base64.b64encode(json.dumps({
            'sub': user['id'],
            'preferred_username': user['username'],
            'email': user['email'],
            'given_name': user['first_name'],
            'family_name': user['last_name'],
            'roles': user['roles'],
            'realm_access': {
                'roles': user['roles']
            },
            'resource_access': {
                self.client_id: {
                    'roles': user['roles']
                }
            },
            'mfa_complete': mfa_complete,
            'iat': now,
            'exp': now + 900  # 15 minutes
        }).encode()).decode()}.SIGNATURE"
        
        # Create refresh token
        refresh_token = f"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.{base64.b64encode(json.dumps({
            'sub': user['id'],
            'iat': now,
            'exp': now + 86400  # 24 hours
        }).encode()).decode()}.SIGNATURE"
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": 900,
            "refresh_expires_in": 86400,
            "session_state": str(uuid.uuid4())
        }

    def verify_totp(self, user_id, code):
        """Verify TOTP code for a user"""
        if not code:
            return False, 400
        
        # Find user by ID
        user = None
        for u in self.users.values():
            if u["id"] == user_id:
                user = u
                break
        
        if not user:
            return False, 404
        
        # In a real implementation, this would verify the code against the TOTP algorithm
        # For this test implementation, we'll consider "invalid-code" as an invalid code
        if code == "invalid-code":
            return False, 401
        
        return True, 200


class MockKeycloakAdapter:
    """Adapter to integrate Keycloak with StudentVC system"""
    
    def __init__(self, keycloak_server, authenticator=None):
        """Initialize adapter with Keycloak server"""
        self.keycloak = keycloak_server
        self.authenticator = authenticator
        self.client_id = keycloak_server.client_id
        self.client_secret = keycloak_server.client_secret
    
    def authenticate_user(self, username, password):
        """Authenticate user with Keycloak"""
        response, status_code = self.keycloak.authenticate(
            username, 
            password, 
            client_id=self.client_id, 
            client_secret=self.client_secret
        )
        
        if status_code != 200:
            return None
        
        # Check if MFA is required
        if response.get("mfa_required"):
            return {
                "session_id": response["session_id"],
                "mfa_required": True,
                "token": response["token"]
            }
        
        # No MFA required, return fully authenticated session
        return {
            "session_id": response["session_id"],
            "mfa_required": False,
            "token": response["token"]
        }
    
    def complete_mfa(self, session_id, username, mfa_code):
        """Complete MFA for a session"""
        # If the code is our test invalid code, return None
        if mfa_code == "invalid-code":
            return None
        
        if session_id not in self.keycloak.sessions:
            logger.error(f"Invalid session ID: {session_id}")
            return None
        
        # In a real implementation, we would verify the MFA code
        # For testing, we'll accept any code except "invalid-code"
        # Get user from session
        session = self.keycloak.sessions[session_id]
        user_id = session["user_id"]
        
        user = None
        for u in self.keycloak.users.values():
            if u["id"] == user_id:
                user = u
                break
        
        if not user or user["username"] != username:
            return None
        
        # Mark session as MFA complete
        self.keycloak.sessions[session_id]["mfa_complete"] = True
        
        # Generate new token that includes MFA completion
        token = self.keycloak._generate_token(user, mfa_complete=True)
        self.keycloak.tokens[token["access_token"]] = {
            "user_id": user["id"],
            "session_id": session_id,
            "mfa_complete": True
        }
        
        return {
            "session_id": session_id,
            "token": token,
            "mfa_complete": True
        }
    
    def get_user_attributes(self, session_id):
        """Get user attributes from a session"""
        # Find token for session
        token = None
        for t, info in self.keycloak.tokens.items():
            if info["session_id"] == session_id:
                token = t
                break
        
        if not token:
            return None
        
        user_info, status_code = self.keycloak.validate_token(token)
        
        if status_code != 200:
            return None
        
        return user_info.get("attributes", {})

    def verify_mfa(self, session_id, mfa_code):
        """Verify MFA code for a session"""
        if session_id not in self.keycloak.sessions:
            logger.error(f"Invalid session ID: {session_id}")
            return False
        
        # Check if mfa_code is the test invalid code
        if mfa_code == "invalid-code":
            return None
        
        session = self.keycloak.sessions[session_id]
        user_id = session["user_id"]
        
        # Find user by ID
        user = None
        for u in self.keycloak.users.values():
            if u["id"] == user_id:
                user = u
                break
        
        if not user:
            return None
        
        if not user["mfa_enabled"]:
            return None
        
        # In a real implementation, we would verify the MFA code
        # Mark session as MFA complete
        self.keycloak.sessions[session_id]["mfa_complete"] = True
        
        # Generate new token that includes MFA completion
        token = self.keycloak._generate_token(user, mfa_complete=True)
        
        return {
            "session_id": session_id,
            "token": token,
            "mfa_complete": True
        }


class MockKeycloakCredentialIssuer:
    """Mock implementation of a credential issuer that uses Keycloak for authentication"""
    
    def __init__(self, keycloak_adapter, did, certificates, keys, mfa_required_credentials=None):
        """Initialize the mock credential issuer
        
        Args:
            keycloak_adapter: The Keycloak adapter
            did: The DID of the issuer
            certificates: The X.509 certificates of the issuer
            keys: The BBS+ keys of the issuer
            mfa_required_credentials: List of credential types that require MFA
        """
        self.keycloak_adapter = keycloak_adapter
        self.did = did
        self.certificates = certificates
        self.keys = keys
        self.issued_credentials = {}
        self.mfa_required_credentials = mfa_required_credentials or ["SecureStudentIDCredential"]
    
    def _generate_x509_keys(self):
        """Generate X.509 keys (simplified)"""
        return {
            "root": {"key_id": "root", "public_key": f"MOCK_PUBLIC_KEY_root"},
            "intermediate": {"key_id": "intermediate", "public_key": f"MOCK_PUBLIC_KEY_intermediate"},
            "issuer": {"key_id": "issuer", "public_key": f"MOCK_PUBLIC_KEY_issuer"}
        }
    
    def _generate_bbs_keys(self):
        """Generate BBS+ keys (simplified)"""
        return {
            "did": self.did, 
            "key_id": "key-1",
            "sign": lambda messages: MockBBSSignature(messages, self),
            "get_verification_method": lambda: f"{self.did}#key-1"
        }
    
    def _generate_certificate_chain(self):
        """Generate X.509 certificate chain (simplified)"""
        root_ca = {
            "subject_dn": f"CN=Education Root CA,O=Educational Trust,C=DE",
            "issuer_dn": f"CN=Education Root CA,O=Educational Trust,C=DE",
            "public_key": self.keys["x509"]["root"]["public_key"],
            "to_pem": lambda: f"-----BEGIN CERTIFICATE-----\nROOT CA CERTIFICATE\n-----END CERTIFICATE-----",
            "get_did_from_extensions": lambda: None
        }
        
        intermediate_ca = {
            "subject_dn": f"CN=University CA,O=Educational Trust,OU=University Certification,C=DE",
            "issuer_dn": f"CN=Education Root CA,O=Educational Trust,C=DE",
            "public_key": self.keys["x509"]["intermediate"]["public_key"],
            "to_pem": lambda: f"-----BEGIN CERTIFICATE-----\nINTERMEDIATE CA CERTIFICATE\n-----END CERTIFICATE-----",
            "get_did_from_extensions": lambda: None
        }
        
        issuer_cert = {
            "subject_dn": f"CN={self.name},O={self.name},OU=Credential Issuance,L=Berlin,C=DE",
            "issuer_dn": f"CN=University CA,O=Educational Trust,OU=University Certification,C=DE",
            "public_key": self.keys["x509"]["issuer"]["public_key"],
            "to_pem": lambda: f"-----BEGIN CERTIFICATE-----\nISSUER CERTIFICATE\n-----END CERTIFICATE-----",
            "get_did_from_extensions": lambda: self.did
        }
        
        return {
            "root": root_ca,
            "intermediate": intermediate_ca,
            "issuer": issuer_cert
        }
    
    def issue_credential(self, keycloak_session_id, credential_type="StudentIDCredential"):
        """Issue a credential using Keycloak session"""
        # Get session from Keycloak
        session = None
        for s_id, s_data in self.keycloak_adapter.keycloak.sessions.items():
            if s_id == keycloak_session_id:
                session = s_data
                break
        
        if not session:
            return {"error": "Invalid or expired Keycloak session"}, 401
        
        # Check if MFA is complete for high security credentials
        mfa_complete = session.get("mfa_complete", False)
        
        # For MFA required credentials, check MFA status
        if credential_type in self.mfa_required_credentials and not mfa_complete:
            return {"error": "MFA required for this credential type"}, 401
        
        # Get user attributes from Keycloak
        attributes = self.keycloak_adapter.get_user_attributes(keycloak_session_id)
        if not attributes:
            return {"error": "Could not retrieve user attributes"}, 401
        
        # Create a verifiable credential
        credential_id = f"urn:uuid:{uuid.uuid4()}"
        issuance_date = datetime.datetime.now().isoformat()
        
        # Assemble credential based on type
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": credential_id,
            "type": ["VerifiableCredential", credential_type],
            "issuer": self.did,
            "issuanceDate": issuance_date,
            "credentialSubject": {}
        }
        
        if credential_type == "StudentIDCredential":
            credential["credentialSubject"] = {
                "id": f"did:key:{uuid.uuid4()}",  # This would be the student's DID in a real scenario
                "name": f"{attributes.get('FirstName', [''])[0]} {attributes.get('LastName', [''])[0]}",
                "studentID": attributes.get("StudentID", [""])[0],
                "university": "Technical University of Berlin",
                "program": attributes.get("Program", [""])[0],
                "enrollmentDate": attributes.get("EnrollmentDate", [""])[0],
                "expectedGraduationDate": attributes.get("ExpectedGraduationDate", [""])[0]
            }
        elif credential_type == "FacultyIDCredential":
            credential["credentialSubject"] = {
                "id": f"did:key:{uuid.uuid4()}",
                "name": f"{attributes.get('FirstName', [''])[0]} {attributes.get('LastName', [''])[0]}",
                "employeeID": attributes.get("EmployeeID", [""])[0],
                "university": "Technical University of Berlin",
                "department": attributes.get("Department", [""])[0],
                "position": attributes.get("Position", [""])[0]
            }
        
        # Add X.509 certificate metadata
        credential["x509Certificate"] = {
            "certificateChain": [
                base64.b64encode(self.certificates["issuer"]["to_pem"]().encode()).decode(),
                base64.b64encode(self.certificates["intermediate"]["to_pem"]().encode()).decode(),
                base64.b64encode(self.certificates["root"]["to_pem"]().encode()).decode()
            ]
        }
        
        # Add authentication evidence
        if "evidence" not in credential:
            credential["evidence"] = []
        
        credential["evidence"].append({
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["KeycloakAuthentication"],
            "verificationMethod": "KeycloakOAuth2",
            "verificationTime": datetime.datetime.now().isoformat(),
            "authenticationLevel": "strong" if mfa_complete else "basic"
        })
        
        # Generate proof (using BBS+ signature)
        credential_messages = [str(credential_id), str(credential["type"]), str(credential["credentialSubject"])]
        signature = self.keys["bbs"]["sign"](credential_messages)
        
        credential["proof"] = {
            "type": "BbsBlsSignature2020",
            "created": issuance_date,
            "verificationMethod": self.keys["bbs"]["get_verification_method"](),
            "proofPurpose": "assertionMethod",
            "proofValue": "MOCK_BBS_SIGNATURE"
        }
        
        # Store the issued credential
        self.issued_credentials[credential_id] = credential
        
        return credential, 200


class MockBBSSignature:
    """Mock BBS+ signature (simplified for testing)"""
    
    def __init__(self, messages, signer):
        self.messages = messages
        self.signer = signer
    
    def to_base64(self):
        """Return mock base64 signature"""
        return "MOCK_BBS_SIGNATURE_BASE64"


class TestKeycloakIntegration(unittest.TestCase):
    """Test suite for Keycloak integration with StudentVC"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Test data
        self.users = {
            "alice": {
                "id": "4c52491b-6c78-4716-81ba-7dcb970aa06e",
                "username": "alice",
                "email": "alice@student.tu-berlin.de",
                "first_name": "Alice",
                "last_name": "Johnson",
                "mfa_enabled": True,
                "password": "password123",
                "attributes": {
                    "StudentID": ["s12345"],
                    "Program": ["Computer Science"],
                    "EnrollmentDate": ["2022-09-01"],
                    "ExpectedGraduationDate": ["2026-08-31"],
                    "FirstName": ["Alice"],
                    "LastName": ["Johnson"]
                },
                "roles": ["student"]
            },
            "bob": {
                "id": "7f8d9e10-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
                "username": "bob",
                "email": "bob@faculty.tu-berlin.de",
                "first_name": "Bob",
                "last_name": "Smith",
                "mfa_enabled": False,
                "password": "faculty456",
                "attributes": {
                    "EmployeeID": ["f67890"],
                    "Department": ["Computer Science"],
                    "Position": ["Professor"],
                    "FirstName": ["Bob"],
                    "LastName": ["Smith"]
                },
                "roles": ["faculty"]
            }
        }
        
        # Create mock classes
        self.keycloak = MockKeycloakServer(self.users)
        self.keycloak_adapter = MockKeycloakAdapter(self.keycloak)
        self.authenticator = MockUniversityAuthenticator()
        
        # Setup mock certificates
        self.certificates = {
            "root": MockX509Certificate("CN=TU Berlin Root CA"),
            "intermediate": MockX509Certificate("CN=TU Berlin Academic CA"),
            "issuer": MockX509Certificate("CN=TU Berlin Student VC Issuer")
        }
        
        # Setup mock keys
        self.keys = {
            "bbs": MockBBSKey()
        }
        
        # Create a credential issuer with Keycloak integration
        self.credential_issuer = MockKeycloakCredentialIssuer(
            self.keycloak_adapter,
            "did:web:tu-berlin.de",
            self.certificates,
            self.keys,
            mfa_required_credentials=["SecureStudentIDCredential"]
        )
    
    def test_keycloak_authentication(self):
        """Test basic authentication with Keycloak"""
        # Authenticate Alice (MFA enabled)
        auth_result = self.keycloak_adapter.authenticate_user("alice", "password123")
        self.assertIsNotNone(auth_result, "Authentication should succeed")
        self.assertTrue(auth_result["mfa_required"], "MFA should be required for Alice")
        
        # Authenticate Bob (MFA not enabled)
        auth_result = self.keycloak_adapter.authenticate_user("bob", "faculty456")
        self.assertIsNotNone(auth_result, "Authentication should succeed")
        self.assertFalse(auth_result["mfa_required"], "MFA should not be required for Bob")
        
        # Try with invalid credentials
        auth_result = self.keycloak_adapter.authenticate_user("alice", "wrong-password")
        self.assertIsNone(auth_result, "Authentication should fail with wrong password")
    
    def test_mfa_completion(self):
        """Test MFA completion with Keycloak"""
        # Register Alice's device with authenticator
        device_id = "ALICE_DEVICE"
        registration = self.authenticator.register_device("alice", device_id)
        self.assertTrue(registration["success"], "Device registration should succeed")
        
        # Authenticate Alice (first factor)
        auth_result = self.keycloak_adapter.authenticate_user("alice", "password123")
        self.assertIsNotNone(auth_result, "Authentication should succeed")
        self.assertTrue(auth_result["mfa_required"], "MFA should be required for Alice")
        
        # Generate authenticator code
        code_result = self.authenticator.generate_code("alice", device_id)
        self.assertTrue(code_result["success"], "Code generation should succeed")
        mfa_code = code_result["code"]
        
        # Complete MFA
        mfa_result = self.keycloak_adapter.complete_mfa(auth_result["session_id"], "alice", mfa_code)
        self.assertIsNotNone(mfa_result, "MFA completion should succeed")
        self.assertTrue(mfa_result["mfa_complete"], "MFA should be marked as complete")
        
        # Try with invalid code
        invalid_result = self.keycloak_adapter.complete_mfa(auth_result["session_id"], "alice", "invalid-code")
        self.assertIsNone(invalid_result, "MFA completion should fail with invalid code")
    
    def test_credential_issuance_with_keycloak(self):
        """Test credential issuance using Keycloak authentication"""
        # Authenticate Bob (MFA not required)
        auth_result = self.keycloak_adapter.authenticate_user("bob", "faculty456")
        self.assertIsNotNone(auth_result, "Authentication should succeed")
        
        # Issue credential with Keycloak session
        credential, status_code = self.credential_issuer.issue_credential(
            auth_result["session_id"],
            credential_type="StudentIDCredential"
        )
        
        self.assertEqual(status_code, 200, "Credential issuance should succeed")
        self.assertIn("credentialSubject", credential, "Credential should have a subject")
        self.assertEqual(credential["credentialSubject"]["studentID"], "23456789", "Student ID should match")
        
        # Check for Keycloak authentication evidence
        self.assertIn("evidence", credential, "Credential should include authentication evidence")
        self.assertEqual(
            credential["evidence"][0]["type"][0],
            "KeycloakAuthentication",
            "Evidence should include Keycloak authentication"
        )
        
        # Authentication level should be "basic" without MFA
        self.assertEqual(
            credential["evidence"][0]["authenticationLevel"],
            "basic",
            "Authentication level should be basic without MFA"
        )
    
    def test_credential_issuance_with_mfa(self):
        """Test credential issuance with MFA via Keycloak"""
        # Register Alice's device with authenticator
        device_id = "ALICE_DEVICE"
        registration = self.authenticator.register_device("alice", device_id)
        self.assertTrue(registration["success"], "Device registration should succeed")
        
        # Authenticate Alice (first factor)
        auth_result = self.keycloak_adapter.authenticate_user("alice", "password123")
        self.assertIsNotNone(auth_result, "Authentication should succeed")
        self.assertTrue(auth_result["mfa_required"], "MFA should be required for Alice")
        
        # Store the session ID before MFA completion
        session_before_mfa = auth_result["session_id"]
        
        # Issue regular credential without completing MFA - this should succeed with basic auth level
        credential_before_mfa, status_before_mfa = self.credential_issuer.issue_credential(
            session_before_mfa,
            credential_type="StudentIDCredential"
        )
        
        # Check that credential was issued with basic auth level
        self.assertEqual(status_before_mfa, 200, "Regular credential issuance should proceed")
        self.assertIn("evidence", credential_before_mfa, "Credential should include authentication evidence")
        self.assertEqual(
            credential_before_mfa["evidence"][0]["authenticationLevel"],
            "basic",
            "Authentication level should be basic without MFA"
        )
        
        # Try to issue a secure credential that requires MFA - this should fail
        secure_credential, secure_status = self.credential_issuer.issue_credential(
            session_before_mfa,
            credential_type="SecureStudentIDCredential"
        )
        self.assertEqual(secure_status, 401, "Secure credential should require MFA")
        
        # Now complete MFA
        code_result = self.authenticator.generate_code("alice", device_id)
        mfa_code = code_result["code"]
        mfa_result = self.keycloak_adapter.complete_mfa(auth_result["session_id"], "alice", mfa_code)
        self.assertIsNotNone(mfa_result, "MFA completion should succeed")
        
        # Issue credential with completed MFA
        credential_after_mfa, status_after_mfa = self.credential_issuer.issue_credential(
            mfa_result["session_id"],
            credential_type="StudentIDCredential"
        )
        
        self.assertEqual(status_after_mfa, 200, "Credential issuance should succeed")
        self.assertIn("evidence", credential_after_mfa, "Credential should include authentication evidence")
        self.assertEqual(
            credential_after_mfa["evidence"][0]["authenticationLevel"],
            "strong",
            "Authentication level should be strong with MFA"
        )
        
        # Now we can also issue secure credentials
        secure_credential_after_mfa, secure_status_after_mfa = self.credential_issuer.issue_credential(
            mfa_result["session_id"],
            credential_type="SecureStudentIDCredential"
        )
        self.assertEqual(secure_status_after_mfa, 200, "Secure credential issuance should succeed after MFA")
    
    def test_faculty_credential_issuance(self):
        """Test faculty credential issuance using Keycloak"""
        # Register professor's device with authenticator
        device_id = "PROF_DEVICE"
        registration = self.authenticator.register_device("prof_mueller", device_id)
        self.assertTrue(registration["success"], "Device registration should succeed")
        
        # Authenticate professor (first factor)
        auth_result = self.keycloak_adapter.authenticate_user("prof_mueller", "password789")
        self.assertIsNotNone(auth_result, "Authentication should succeed")
        
        # Complete MFA (required for faculty)
        code_result = self.authenticator.generate_code("prof_mueller", device_id)
        mfa_code = code_result["code"]
        mfa_result = self.keycloak_adapter.complete_mfa(auth_result["session_id"], "prof_mueller", mfa_code)
        
        # Issue faculty credential
        credential, status_code = self.credential_issuer.issue_credential(
            mfa_result["session_id"],
            credential_type="FacultyIDCredential"
        )
        
        self.assertEqual(status_code, 200, "Credential issuance should succeed")
        self.assertIn("credentialSubject", credential, "Credential should have a subject")
        self.assertEqual(credential["credentialSubject"]["employeeID"], "E12345", "Employee ID should match")
        self.assertEqual(credential["credentialSubject"]["department"], "Computer Science", "Department should match")
        
        # Check for Keycloak authentication evidence
        self.assertIn("evidence", credential, "Credential should include authentication evidence")
        self.assertEqual(
            credential["evidence"][0]["type"][0],
            "KeycloakAuthentication",
            "Evidence should include Keycloak authentication"
        )
        
        # Authentication level should be "strong" with MFA
        self.assertEqual(
            credential["evidence"][0]["authenticationLevel"],
            "strong",
            "Authentication level should be strong with MFA"
        )


if __name__ == "__main__":
    unittest.main() 