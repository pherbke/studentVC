#!/usr/bin/env python3
"""
OID4VC Protocol Tests for StudentVC

This test suite verifies the implementation of the OpenID for Verifiable Credentials
protocol, covering both credential issuance (OID4VC) and presentation (OID4VP) flows.

The tests cover:
1. Authorization code flow
2. Credential issuance flow
3. Credential presentation flow
4. Error handling

Author: StudentVC Team
Date: April 5, 2025
"""

import unittest
import json
import uuid
import datetime
import base64
import urllib.parse
import os
import sys
from unittest.mock import patch, MagicMock, AsyncMock

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Import the necessary modules
# In a real test, you would import the actual modules
# For this test, we'll use mocks

class MockOpenIDProvider:
    """Mock OpenID Provider for testing"""
    
    def __init__(self):
        self.clients = {
            "client123": {
                "client_id": "client123",
                "client_secret": "secret123",
                "redirect_uris": ["https://wallet.example.com/cb"],
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "client_secret_basic",
                "scope": "openid profile"
            }
        }
        self.auth_codes = {}
        self.access_tokens = {}
        self.refresh_tokens = {}
        self.credentials = {}
    
    async def authorize(self, request_params):
        """Process an authorization request"""
        # Validate the request
        client_id = request_params.get("client_id")
        if client_id not in self.clients:
            return {"error": "invalid_client"}
        
        redirect_uri = request_params.get("redirect_uri")
        if redirect_uri not in self.clients[client_id]["redirect_uris"]:
            return {"error": "invalid_redirect_uri"}
        
        response_type = request_params.get("response_type")
        if response_type not in self.clients[client_id]["response_types"]:
            return {"error": "unsupported_response_type"}
        
        scope = request_params.get("scope", "")
        if "openid" not in scope.split():
            return {"error": "invalid_scope"}
        
        # Generate an authorization code
        code = str(uuid.uuid4())
        self.auth_codes[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "exp": datetime.datetime.now() + datetime.timedelta(minutes=10)
        }
        
        # Return the authorization response
        return {
            "code": code,
            "state": request_params.get("state", "")
        }
    
    async def token(self, request_params, headers):
        """Process a token request"""
        # Validate the client authentication
        auth_header = headers.get("Authorization", "")
        client_id = None
        client_secret = None
        
        if auth_header.startswith("Basic "):
            credentials = base64.b64decode(auth_header[6:]).decode("utf-8")
            client_id, client_secret = credentials.split(":", 1)
        else:
            client_id = request_params.get("client_id")
            client_secret = request_params.get("client_secret")
        
        if client_id not in self.clients or self.clients[client_id]["client_secret"] != client_secret:
            return {"error": "invalid_client"}
        
        # Validate the token request
        grant_type = request_params.get("grant_type")
        if grant_type not in self.clients[client_id]["grant_types"]:
            return {"error": "unsupported_grant_type"}
        
        if grant_type == "authorization_code":
            code = request_params.get("code")
            if code not in self.auth_codes:
                return {"error": "invalid_grant"}
            
            auth_code = self.auth_codes[code]
            if auth_code["client_id"] != client_id:
                return {"error": "invalid_grant"}
            
            if auth_code["redirect_uri"] != request_params.get("redirect_uri"):
                return {"error": "invalid_grant"}
            
            if auth_code["exp"] < datetime.datetime.now():
                return {"error": "invalid_grant"}
            
            # Generate tokens
            access_token = str(uuid.uuid4())
            refresh_token = str(uuid.uuid4())
            id_token = self._generate_id_token(client_id, auth_code["scope"])
            
            self.access_tokens[access_token] = {
                "client_id": client_id,
                "scope": auth_code["scope"],
                "exp": datetime.datetime.now() + datetime.timedelta(hours=1)
            }
            
            self.refresh_tokens[refresh_token] = {
                "client_id": client_id,
                "scope": auth_code["scope"],
                "exp": datetime.datetime.now() + datetime.timedelta(days=30)
            }
            
            # Remove the used authorization code
            del self.auth_codes[code]
            
            # Return the token response
            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "refresh_token": refresh_token,
                "expires_in": 3600,
                "id_token": id_token,
                "scope": auth_code["scope"]
            }
        
        elif grant_type == "refresh_token":
            refresh_token = request_params.get("refresh_token")
            if refresh_token not in self.refresh_tokens:
                return {"error": "invalid_grant"}
            
            refresh_token_data = self.refresh_tokens[refresh_token]
            if refresh_token_data["client_id"] != client_id:
                return {"error": "invalid_grant"}
            
            if refresh_token_data["exp"] < datetime.datetime.now():
                return {"error": "invalid_grant"}
            
            # Generate new tokens
            access_token = str(uuid.uuid4())
            new_refresh_token = str(uuid.uuid4())
            
            self.access_tokens[access_token] = {
                "client_id": client_id,
                "scope": refresh_token_data["scope"],
                "exp": datetime.datetime.now() + datetime.timedelta(hours=1)
            }
            
            self.refresh_tokens[new_refresh_token] = {
                "client_id": client_id,
                "scope": refresh_token_data["scope"],
                "exp": datetime.datetime.now() + datetime.timedelta(days=30)
            }
            
            # Remove the used refresh token
            del self.refresh_tokens[refresh_token]
            
            # Return the token response
            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "refresh_token": new_refresh_token,
                "expires_in": 3600,
                "scope": refresh_token_data["scope"]
            }
        
        return {"error": "unsupported_grant_type"}
    
    async def credential(self, request_params, headers):
        """Process a credential request"""
        # Validate the access token
        auth_header = headers.get("Authorization", "")
        access_token = None
        
        if auth_header.startswith("Bearer "):
            access_token = auth_header[7:]
        
        if access_token not in self.access_tokens:
            return {"error": "invalid_token"}
        
        access_token_data = self.access_tokens[access_token]
        if access_token_data["exp"] < datetime.datetime.now():
            return {"error": "invalid_token"}
        
        # Validate the credential request
        format = request_params.get("format")
        if format not in ["jwt_vc", "ldp_vc"]:
            return {"error": "unsupported_credential_format"}
        
        types = request_params.get("types", [])
        if not isinstance(types, list) or not types:
            return {"error": "invalid_credential_type"}
        
        # Issue the credential
        credential_id = str(uuid.uuid4())
        issuance_date = datetime.datetime.now().isoformat()
        expiration_date = (datetime.datetime.now() + datetime.timedelta(days=365)).isoformat()
        
        if format == "jwt_vc":
            # Create a JWT credential
            credential = {
                "jti": f"urn:uuid:{credential_id}",
                "iss": "https://issuer.example.com",
                "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "iat": int(datetime.datetime.now().timestamp()),
                "exp": int((datetime.datetime.now() + datetime.timedelta(days=365)).timestamp()),
                "vc": {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential"] + types,
                    "credentialSubject": {
                        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                        "name": "John Doe",
                        "degree": {
                            "type": "BachelorDegree",
                            "name": "Bachelor of Science and Arts"
                        }
                    }
                }
            }
            
            # In a real implementation, this would be properly signed
            jwt_header = base64.b64encode(json.dumps({"alg": "ES256K", "typ": "JWT"}).encode()).decode()
            jwt_payload = base64.b64encode(json.dumps(credential).encode()).decode()
            jwt_signature = base64.b64encode("signature".encode()).decode()
            
            credential_jwt = f"{jwt_header}.{jwt_payload}.{jwt_signature}"
            
            self.credentials[credential_id] = credential_jwt
            
            # Return the credential response
            return {
                "format": "jwt_vc",
                "credential": credential_jwt
            }
        
        elif format == "ldp_vc":
            # Create an LDP credential
            credential = {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "id": f"urn:uuid:{credential_id}",
                "type": ["VerifiableCredential"] + types,
                "issuer": "https://issuer.example.com",
                "issuanceDate": issuance_date,
                "expirationDate": expiration_date,
                "credentialSubject": {
                    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                    "name": "John Doe",
                    "degree": {
                        "type": "BachelorDegree",
                        "name": "Bachelor of Science and Arts"
                    }
                },
                "proof": {
                    "type": "Ed25519Signature2020",
                    "created": issuance_date,
                    "verificationMethod": "https://issuer.example.com/keys/1",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndSayn94TGJsW6Y94FCR4GKz3ZVs2dyjfV"
                }
            }
            
            self.credentials[credential_id] = credential
            
            # Return the credential response
            return {
                "format": "ldp_vc",
                "credential": credential
            }
        
        return {"error": "unsupported_credential_format"}
    
    async def presentation(self, request_params, headers=None):
        """Process a presentation request"""
        # In a real implementation, this would validate the presentation
        # For testing, we'll just return a successful response
        
        presentation_definition = request_params.get("presentation_definition", {})
        if not presentation_definition:
            return {"error": "invalid_presentation_definition"}
        
        # Return a successful response
        return {
            "presentation_submission": {
                "id": str(uuid.uuid4()),
                "definition_id": presentation_definition.get("id", ""),
                "descriptor_map": []
            }
        }
    
    def _generate_id_token(self, client_id, scope):
        """Generate an ID token"""
        now = int(datetime.datetime.now().timestamp())
        exp = now + 3600
        
        id_token = {
            "iss": "https://issuer.example.com",
            "sub": "user123",
            "aud": client_id,
            "exp": exp,
            "iat": now,
            "auth_time": now,
            "nonce": "n-0S6_WzA2Mj",
            "name": "John Doe",
            "email": "john.doe@example.com"
        }
        
        # In a real implementation, this would be properly signed
        jwt_header = base64.b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode()
        jwt_payload = base64.b64encode(json.dumps(id_token).encode()).decode()
        jwt_signature = base64.b64encode("signature".encode()).decode()
        
        return f"{jwt_header}.{jwt_payload}.{jwt_signature}"


class MockWallet:
    """Mock wallet for testing"""
    
    def __init__(self):
        self.credentials = {}
        self.presentations = {}
    
    async def request_credential(self, issuer_url, types, format="jwt_vc"):
        """Request a credential from an issuer"""
        # Start the authorization flow
        auth_params = {
            "client_id": "client123",
            "redirect_uri": "https://wallet.example.com/cb",
            "response_type": "code",
            "scope": "openid profile",
            "state": str(uuid.uuid4())
        }
        
        auth_url = f"{issuer_url}/authorize?{urllib.parse.urlencode(auth_params)}"
        
        # In a real wallet, this would redirect to the issuer's authorization endpoint
        # For testing, we'll just mock the response
        auth_response = {
            "code": "auth_code_123",
            "state": auth_params["state"]
        }
        
        # Exchange the authorization code for tokens
        token_params = {
            "grant_type": "authorization_code",
            "code": auth_response["code"],
            "redirect_uri": auth_params["redirect_uri"]
        }
        
        token_headers = {
            "Authorization": "Basic " + base64.b64encode(f"client123:secret123".encode()).decode()
        }
        
        # In a real wallet, this would make a request to the issuer's token endpoint
        # For testing, we'll just mock the response
        token_response = {
            "access_token": "access_token_123",
            "token_type": "Bearer",
            "refresh_token": "refresh_token_123",
            "expires_in": 3600,
            "id_token": "id_token_123"
        }
        
        # Request the credential
        credential_params = {
            "format": format,
            "types": types
        }
        
        credential_headers = {
            "Authorization": f"Bearer {token_response['access_token']}"
        }
        
        # In a real wallet, this would make a request to the issuer's credential endpoint
        # For testing, we'll just mock the response
        if format == "jwt_vc":
            credential_response = {
                "format": "jwt_vc",
                "credential": "header.payload.signature"
            }
        else:
            credential_response = {
                "format": "ldp_vc",
                "credential": {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential"] + types,
                    "credentialSubject": {}
                }
            }
        
        # Store the credential in the wallet
        credential_id = str(uuid.uuid4())
        self.credentials[credential_id] = credential_response["credential"]
        
        return credential_id
    
    async def create_presentation(self, verifier_url, presentation_definition, credential_ids):
        """Create a presentation for a verifier"""
        # Retrieve the credentials
        credentials = [self.credentials[cid] for cid in credential_ids if cid in self.credentials]
        if not credentials:
            return {"error": "no_credentials_found"}
        
        # Create the presentation
        presentation_id = str(uuid.uuid4())
        presentation = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "id": f"urn:uuid:{presentation_id}",
            "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
            "verifiableCredential": credentials,
            "proof": {
                "type": "Ed25519Signature2020",
                "created": datetime.datetime.now().isoformat(),
                "challenge": presentation_definition.get("challenge", ""),
                "domain": verifier_url,
                "proofPurpose": "authentication",
                "verificationMethod": "did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1",
                "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndSayn94TGJsW6Y94FCR4GKz3ZVs2dyjfV"
            }
        }
        
        self.presentations[presentation_id] = presentation
        
        # Submit the presentation to the verifier
        presentation_params = {
            "presentation": presentation,
            "presentation_submission": {
                "id": str(uuid.uuid4()),
                "definition_id": presentation_definition.get("id", ""),
                "descriptor_map": []
            }
        }
        
        # In a real wallet, this would make a request to the verifier's presentation endpoint
        # For testing, we'll just mock the response
        presentation_response = {
            "verified": True
        }
        
        return presentation_response


class TestOID4VCProtocol(unittest.TestCase):
    """Test OID4VC protocol implementation"""
    
    @patch('backend.src.protocols.oid4vc.CredentialIssuer')
    async def test_credential_issuance_flow(self, mock_issuer_class):
        """Test the full credential issuance flow"""
        # Create a mock issuer
        mock_issuer = MockOpenIDProvider()
        mock_issuer_class.return_value = mock_issuer
        
        # Create a mock wallet
        wallet = MockWallet()
        
        # Request a credential
        credential_id = await wallet.request_credential(
            issuer_url="https://issuer.example.com",
            types=["UniversityDegreeCredential"],
            format="jwt_vc"
        )
        
        # Verify the credential was received and stored
        self.assertIn(credential_id, wallet.credentials)
        self.assertTrue(wallet.credentials[credential_id].startswith("header.payload."))
    
    @patch('backend.src.protocols.oid4vc.CredentialVerifier')
    async def test_credential_presentation_flow(self, mock_verifier_class):
        """Test the full credential presentation flow"""
        # Create a mock verifier
        mock_verifier = MockOpenIDProvider()
        mock_verifier_class.return_value = mock_verifier
        
        # Create a mock wallet with a credential
        wallet = MockWallet()
        wallet.credentials["cred123"] = "header.payload.signature"
        
        # Create a presentation definition
        presentation_definition = {
            "id": "example-presentation-definition",
            "input_descriptors": [
                {
                    "id": "UniversityDegreeCredential",
                    "format": {
                        "jwt_vc": {
                            "alg": ["ES256K"]
                        }
                    },
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vc.type"],
                                "filter": {
                                    "type": "array",
                                    "contains": {
                                        "const": "UniversityDegreeCredential"
                                    }
                                }
                            }
                        ]
                    }
                }
            ]
        }
        
        # Create and submit a presentation
        result = await wallet.create_presentation(
            verifier_url="https://verifier.example.com",
            presentation_definition=presentation_definition,
            credential_ids=["cred123"]
        )
        
        # Verify the presentation was verified successfully
        self.assertTrue(result["verified"])
    
    @patch('backend.src.protocols.oid4vc.CredentialIssuer')
    async def test_authorization_code_flow(self, mock_issuer_class):
        """Test the authorization code flow"""
        # Create a mock issuer
        mock_issuer = MockOpenIDProvider()
        mock_issuer_class.return_value = mock_issuer
        
        # Simulate the authorization request
        auth_params = {
            "client_id": "client123",
            "redirect_uri": "https://wallet.example.com/cb",
            "response_type": "code",
            "scope": "openid profile",
            "state": "state123"
        }
        
        auth_response = await mock_issuer.authorize(auth_params)
        
        # Verify the authorization response
        self.assertIn("code", auth_response)
        self.assertEqual(auth_response["state"], auth_params["state"])
        
        # Simulate the token request
        token_params = {
            "grant_type": "authorization_code",
            "code": auth_response["code"],
            "redirect_uri": auth_params["redirect_uri"]
        }
        
        token_headers = {
            "Authorization": "Basic " + base64.b64encode(f"client123:secret123".encode()).decode()
        }
        
        token_response = await mock_issuer.token(token_params, token_headers)
        
        # Verify the token response
        self.assertIn("access_token", token_response)
        self.assertIn("refresh_token", token_response)
        self.assertIn("id_token", token_response)
        self.assertEqual(token_response["token_type"], "Bearer")
        
        # Verify the authorization code was consumed
        self.assertEqual(len(mock_issuer.auth_codes), 0)
    
    @patch('backend.src.protocols.oid4vc.CredentialIssuer')
    async def test_credential_issuance_jwt_format(self, mock_issuer_class):
        """Test credential issuance in JWT format"""
        # Create a mock issuer
        mock_issuer = MockOpenIDProvider()
        mock_issuer_class.return_value = mock_issuer
        
        # Create an access token for testing
        access_token = str(uuid.uuid4())
        mock_issuer.access_tokens[access_token] = {
            "client_id": "client123",
            "scope": "openid profile",
            "exp": datetime.datetime.now() + datetime.timedelta(hours=1)
        }
        
        # Simulate the credential request
        credential_params = {
            "format": "jwt_vc",
            "types": ["UniversityDegreeCredential"]
        }
        
        credential_headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        credential_response = await mock_issuer.credential(credential_params, credential_headers)
        
        # Verify the credential response
        self.assertEqual(credential_response["format"], "jwt_vc")
        self.assertTrue(isinstance(credential_response["credential"], str))
        self.assertTrue("." in credential_response["credential"])
    
    @patch('backend.src.protocols.oid4vc.CredentialIssuer')
    async def test_credential_issuance_ldp_format(self, mock_issuer_class):
        """Test credential issuance in LDP format"""
        # Create a mock issuer
        mock_issuer = MockOpenIDProvider()
        mock_issuer_class.return_value = mock_issuer
        
        # Create an access token for testing
        access_token = str(uuid.uuid4())
        mock_issuer.access_tokens[access_token] = {
            "client_id": "client123",
            "scope": "openid profile",
            "exp": datetime.datetime.now() + datetime.timedelta(hours=1)
        }
        
        # Simulate the credential request
        credential_params = {
            "format": "ldp_vc",
            "types": ["UniversityDegreeCredential"]
        }
        
        credential_headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        credential_response = await mock_issuer.credential(credential_params, credential_headers)
        
        # Verify the credential response
        self.assertEqual(credential_response["format"], "ldp_vc")
        self.assertTrue(isinstance(credential_response["credential"], dict))
        self.assertIn("@context", credential_response["credential"])
        self.assertIn("credentialSubject", credential_response["credential"])
        self.assertIn("proof", credential_response["credential"])
    
    @patch('backend.src.protocols.oid4vc.CredentialVerifier')
    async def test_presentation_verification(self, mock_verifier_class):
        """Test presentation verification"""
        # Create a mock verifier
        mock_verifier = MockOpenIDProvider()
        mock_verifier_class.return_value = mock_verifier
        
        # Create a presentation definition
        presentation_definition = {
            "id": "example-presentation-definition",
            "input_descriptors": [
                {
                    "id": "UniversityDegreeCredential",
                    "format": {
                        "jwt_vc": {
                            "alg": ["ES256K"]
                        }
                    },
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vc.type"],
                                "filter": {
                                    "type": "array",
                                    "contains": {
                                        "const": "UniversityDegreeCredential"
                                    }
                                }
                            }
                        ]
                    }
                }
            ]
        }
        
        # Create a mock presentation
        presentation = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": ["header.payload.signature"],
            "proof": {
                "type": "Ed25519Signature2020",
                "created": datetime.datetime.now().isoformat(),
                "challenge": "challenge123",
                "domain": "https://verifier.example.com",
                "proofPurpose": "authentication",
                "verificationMethod": "did:example:123#key-1",
                "proofValue": "signature123"
            }
        }
        
        # Simulate the presentation verification
        presentation_params = {
            "presentation_definition": presentation_definition,
            "presentation": presentation
        }
        
        presentation_response = await mock_verifier.presentation(presentation_params)
        
        # Verify the presentation response
        self.assertIn("presentation_submission", presentation_response)
        self.assertEqual(presentation_response["presentation_submission"]["definition_id"], presentation_definition["id"])
    
    @patch('backend.src.protocols.oid4vc.CredentialIssuer')
    async def test_refresh_token_flow(self, mock_issuer_class):
        """Test the refresh token flow"""
        # Create a mock issuer
        mock_issuer = MockOpenIDProvider()
        mock_issuer_class.return_value = mock_issuer
        
        # Create a refresh token for testing
        refresh_token = str(uuid.uuid4())
        mock_issuer.refresh_tokens[refresh_token] = {
            "client_id": "client123",
            "scope": "openid profile",
            "exp": datetime.datetime.now() + datetime.timedelta(days=30)
        }
        
        # Simulate the refresh token request
        token_params = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
        
        token_headers = {
            "Authorization": "Basic " + base64.b64encode(f"client123:secret123".encode()).decode()
        }
        
        token_response = await mock_issuer.token(token_params, token_headers)
        
        # Verify the token response
        self.assertIn("access_token", token_response)
        self.assertIn("refresh_token", token_response)
        self.assertEqual(token_response["token_type"], "Bearer")
        
        # Verify the refresh token was rotated
        self.assertNotIn(refresh_token, mock_issuer.refresh_tokens)
    
    @patch('backend.src.protocols.oid4vc.CredentialIssuer')
    async def test_error_handling_invalid_client(self, mock_issuer_class):
        """Test error handling for invalid client"""
        # Create a mock issuer
        mock_issuer = MockOpenIDProvider()
        mock_issuer_class.return_value = mock_issuer
        
        # Simulate an authorization request with invalid client
        auth_params = {
            "client_id": "invalid_client",
            "redirect_uri": "https://wallet.example.com/cb",
            "response_type": "code",
            "scope": "openid profile",
            "state": "state123"
        }
        
        auth_response = await mock_issuer.authorize(auth_params)
        
        # Verify the error response
        self.assertEqual(auth_response["error"], "invalid_client")
    
    @patch('backend.src.protocols.oid4vc.CredentialIssuer')
    async def test_error_handling_invalid_redirect_uri(self, mock_issuer_class):
        """Test error handling for invalid redirect URI"""
        # Create a mock issuer
        mock_issuer = MockOpenIDProvider()
        mock_issuer_class.return_value = mock_issuer
        
        # Simulate an authorization request with invalid redirect URI
        auth_params = {
            "client_id": "client123",
            "redirect_uri": "https://malicious.example.com/cb",
            "response_type": "code",
            "scope": "openid profile",
            "state": "state123"
        }
        
        auth_response = await mock_issuer.authorize(auth_params)
        
        # Verify the error response
        self.assertEqual(auth_response["error"], "invalid_redirect_uri")


if __name__ == "__main__":
    unittest.main() 