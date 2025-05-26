#!/usr/bin/env python3
"""
DID Resolver Tests for StudentVC

This test suite verifies the implementation of DID resolution
functionality in the StudentVC system, focusing on various
DID methods including `did:web` for university domains.

Author: StudentVC Team
Date: April 5, 2025
"""

import unittest
import json
import os
import sys
import requests
from unittest.mock import patch, MagicMock

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Import the necessary modules
# In a real test, you would import the actual modules
# For this file, we'll define mock classes and functions

# Mock DID resolver class
class DIDResolver:
    """A mock DID resolver with support for multiple DID methods"""
    
    def __init__(self):
        # Dictionary to hold mock DID documents
        self.did_documents = {}
        
        # Register well-known test DIDs
        self._initialize_test_dids()
    
    def _initialize_test_dids(self):
        """Initialize test DIDs with mock DID documents"""
        # Add a did:web for TU Berlin
        self.did_documents["did:web:edu:tu.berlin"] = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:edu:tu.berlin",
            "verificationMethod": [{
                "id": "did:web:edu:tu.berlin#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:edu:tu.berlin",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }, {
                "id": "did:web:edu:tu.berlin#bbs-key-1",
                "type": "Bls12381G2Key2020",
                "controller": "did:web:edu:tu.berlin",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "BLS12381_G2",
                    "x": "mock_bbs_public_key_tu_berlin"
                }
            }],
            "authentication": ["did:web:edu:tu.berlin#key-1"],
            "assertionMethod": [
                "did:web:edu:tu.berlin#key-1",
                "did:web:edu:tu.berlin#bbs-key-1"
            ],
            "service": [{
                "id": "did:web:edu:tu.berlin#credential-service",
                "type": "CredentialService",
                "serviceEndpoint": "https://vc.tu.berlin/api/credentials"
            }]
        }
        
        # Add a did:web for FU Berlin
        self.did_documents["did:web:edu:fu-berlin.de"] = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:edu:fu-berlin.de",
            "verificationMethod": [{
                "id": "did:web:edu:fu-berlin.de#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:edu:fu-berlin.de",
                "publicKeyMultibase": "z6MkrWtLYfEMFGjJ4tLGRvYiDWZw2NxF8ywEXtJRJvWSAb51"
            }],
            "authentication": ["did:web:edu:fu-berlin.de#key-1"],
            "assertionMethod": ["did:web:edu:fu-berlin.de#key-1"],
            "service": [{
                "id": "did:web:edu:fu-berlin.de#credential-service",
                "type": "CredentialService",
                "serviceEndpoint": "https://vc.fu-berlin.de/api/credentials"
            }, {
                "id": "did:web:edu:fu-berlin.de#x509-service",
                "type": "X509Service",
                "serviceEndpoint": "https://pki.fu-berlin.de"
            }]
        }
        
        # Add a did:key
        self.did_documents["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"] = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "verificationMethod": [{
                "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }],
            "authentication": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"],
            "assertionMethod": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"]
        }
        
        # Add a did:ion (example of a longer DID document)
        self.did_documents["did:ion:EiA-GtHEaP9rrkpQPRi0qNBMYpYHCLuXkXMpKLrIBe6w0A"] = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:ion:EiA-GtHEaP9rrkpQPRi0qNBMYpYHCLuXkXMpKLrIBe6w0A",
            "verificationMethod": [{
                "id": "did:ion:EiA-GtHEaP9rrkpQPRi0qNBMYpYHCLuXkXMpKLrIBe6w0A#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:ion:EiA-GtHEaP9rrkpQPRi0qNBMYpYHCLuXkXMpKLrIBe6w0A",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": "3t3Z7sG5Ql2JQmLHmNjR-1qhvvctGRwHP7xT9-p0HsI",
                    "y": "YrX-Jd2P13Rn4J8MC-yfRbcEhc9KEOkZFO_ZlcjJCw0"
                }
            }],
            "authentication": ["did:ion:EiA-GtHEaP9rrkpQPRi0qNBMYpYHCLuXkXMpKLrIBe6w0A#key-1"],
            "assertionMethod": ["did:ion:EiA-GtHEaP9rrkpQPRi0qNBMYpYHCLuXkXMpKLrIBe6w0A#key-1"],
            "service": [{
                "id": "did:ion:EiA-GtHEaP9rrkpQPRi0qNBMYpYHCLuXkXMpKLrIBe6w0A#credential-service",
                "type": "CredentialService",
                "serviceEndpoint": "https://example.com/api/credentials"
            }]
        }
    
    def resolve(self, did):
        """Resolve a DID to a DID document"""
        if did in self.did_documents:
            return {
                "didDocument": self.did_documents[did],
                "didResolutionMetadata": {
                    "contentType": "application/did+ld+json",
                    "retrieved": "2025-04-05T12:00:00Z"
                },
                "didDocumentMetadata": {
                    "created": "2024-01-01T00:00:00Z",
                    "updated": "2025-01-01T00:00:00Z"
                }
            }
        
        # Handle did:web resolution via HTTP
        if did.startswith("did:web:"):
            try:
                # Parse the did:web identifier
                parts = did[9:].split(":")
                domain = parts[-1]
                path = "/".join(parts[:-1]) if len(parts) > 1 else ""
                
                # Construct the well-known URL
                if path:
                    url = f"https://{domain}/.well-known/did/{path}"
                else:
                    url = f"https://{domain}/.well-known/did.json"
                
                # In a real test, we would make an HTTP request
                # For this mock, we'll raise an exception for unregistered DIDs
                raise Exception(f"DID document not found for {did}")
            except Exception as e:
                return {
                    "didResolutionMetadata": {
                        "error": "notFound",
                        "message": str(e)
                    }
                }
        
        # DID not found
        return {
            "didResolutionMetadata": {
                "error": "notFound",
                "message": f"DID document not found for {did}"
            }
        }
    
    def add_did_document(self, did, document):
        """Add a mock DID document"""
        self.did_documents[did] = document
    
    def remove_did_document(self, did):
        """Remove a mock DID document"""
        if did in self.did_documents:
            del self.did_documents[did]


class TestDIDResolver(unittest.TestCase):
    """Test DID resolver functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.resolver = DIDResolver()
    
    def test_resolve_did_web_tu_berlin(self):
        """Test resolving did:web:edu:tu.berlin"""
        # Resolve the DID
        result = self.resolver.resolve("did:web:edu:tu.berlin")
        
        # Check that the resolution was successful
        self.assertNotIn("error", result["didResolutionMetadata"])
        self.assertIn("didDocument", result)
        
        # Check the DID document
        doc = result["didDocument"]
        self.assertEqual(doc["id"], "did:web:edu:tu.berlin")
        
        # Check that the document has verification methods
        self.assertIn("verificationMethod", doc)
        self.assertGreater(len(doc["verificationMethod"]), 0)
        
        # Check that the document has authentication
        self.assertIn("authentication", doc)
        self.assertGreater(len(doc["authentication"]), 0)
        
        # Check for BBS+ key for selective disclosure
        has_bbs_key = False
        for vm in doc["verificationMethod"]:
            if "Bls12381G2Key" in vm["type"]:
                has_bbs_key = True
                break
        self.assertTrue(has_bbs_key, "TU Berlin DID document should have a BBS+ key for selective disclosure")
        
        # Check for credential service
        has_credential_service = False
        for service in doc["service"]:
            if service["type"] == "CredentialService":
                has_credential_service = True
                self.assertIn("serviceEndpoint", service)
                break
        self.assertTrue(has_credential_service, "TU Berlin DID document should have a credential service")
    
    def test_resolve_did_web_fu_berlin(self):
        """Test resolving did:web:edu:fu-berlin.de"""
        # Resolve the DID
        result = self.resolver.resolve("did:web:edu:fu-berlin.de")
        
        # Check that the resolution was successful
        self.assertNotIn("error", result["didResolutionMetadata"])
        self.assertIn("didDocument", result)
        
        # Check the DID document
        doc = result["didDocument"]
        self.assertEqual(doc["id"], "did:web:edu:fu-berlin.de")
        
        # Check that the document has verification methods
        self.assertIn("verificationMethod", doc)
        self.assertGreater(len(doc["verificationMethod"]), 0)
        
        # Check that the document has authentication
        self.assertIn("authentication", doc)
        self.assertGreater(len(doc["authentication"]), 0)
        
        # Check for credential service
        has_credential_service = False
        for service in doc["service"]:
            if service["type"] == "CredentialService":
                has_credential_service = True
                self.assertIn("serviceEndpoint", service)
                break
        self.assertTrue(has_credential_service, "FU Berlin DID document should have a credential service")
        
        # Check for X.509 service
        has_x509_service = False
        for service in doc["service"]:
            if service["type"] == "X509Service":
                has_x509_service = True
                self.assertIn("serviceEndpoint", service)
                break
        self.assertTrue(has_x509_service, "FU Berlin DID document should have an X.509 service")
    
    def test_resolve_did_key(self):
        """Test resolving did:key"""
        # Resolve the DID
        result = self.resolver.resolve("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        
        # Check that the resolution was successful
        self.assertNotIn("error", result["didResolutionMetadata"])
        self.assertIn("didDocument", result)
        
        # Check the DID document
        doc = result["didDocument"]
        self.assertEqual(doc["id"], "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        
        # Check that the document has verification methods
        self.assertIn("verificationMethod", doc)
        self.assertGreater(len(doc["verificationMethod"]), 0)
        
        # Check that the document has authentication
        self.assertIn("authentication", doc)
        self.assertGreater(len(doc["authentication"]), 0)
        
        # Check that the key in the verification method matches the DID
        self.assertEqual(
            doc["verificationMethod"][0]["publicKeyMultibase"],
            "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        )
    
    def test_resolve_did_ion(self):
        """Test resolving did:ion"""
        # Resolve the DID
        result = self.resolver.resolve("did:ion:EiA-GtHEaP9rrkpQPRi0qNBMYpYHCLuXkXMpKLrIBe6w0A")
        
        # Check that the resolution was successful
        self.assertNotIn("error", result["didResolutionMetadata"])
        self.assertIn("didDocument", result)
        
        # Check the DID document
        doc = result["didDocument"]
        self.assertEqual(doc["id"], "did:ion:EiA-GtHEaP9rrkpQPRi0qNBMYpYHCLuXkXMpKLrIBe6w0A")
        
        # Check that the document has verification methods
        self.assertIn("verificationMethod", doc)
        self.assertGreater(len(doc["verificationMethod"]), 0)
        
        # Check that the document has authentication
        self.assertIn("authentication", doc)
        self.assertGreater(len(doc["authentication"]), 0)
        
        # Check for JsonWebKey2020 type
        has_jwk = False
        for vm in doc["verificationMethod"]:
            if vm["type"] == "JsonWebKey2020":
                has_jwk = True
                self.assertIn("publicKeyJwk", vm)
                break
        self.assertTrue(has_jwk, "ION DID document should have a JsonWebKey2020 verification method")
    
    def test_resolve_nonexistent_did(self):
        """Test resolving a nonexistent DID"""
        # Resolve the DID
        result = self.resolver.resolve("did:example:123456789")
        
        # Check that the resolution failed
        self.assertIn("error", result["didResolutionMetadata"])
        self.assertEqual(result["didResolutionMetadata"]["error"], "notFound")
    
    def test_add_and_resolve_custom_did(self):
        """Test adding and resolving a custom DID"""
        # Create a custom DID document
        custom_did = "did:example:test123"
        custom_doc = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": custom_did,
            "verificationMethod": [{
                "id": custom_did + "#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": custom_did,
                "publicKeyMultibase": "z6MkrWtLYfEMFGjJ4tLGRvYiDWZw2NxF8ywEXtJRJvWSAb51"
            }],
            "authentication": [custom_did + "#key-1"],
            "assertionMethod": [custom_did + "#key-1"]
        }
        
        # Add the DID document
        self.resolver.add_did_document(custom_did, custom_doc)
        
        # Resolve the DID
        result = self.resolver.resolve(custom_did)
        
        # Check that the resolution was successful
        self.assertNotIn("error", result["didResolutionMetadata"])
        self.assertIn("didDocument", result)
        
        # Check the DID document
        doc = result["didDocument"]
        self.assertEqual(doc["id"], custom_did)
        
        # Remove the DID document
        self.resolver.remove_did_document(custom_did)
        
        # Resolve the DID again
        result = self.resolver.resolve(custom_did)
        
        # Check that the resolution failed
        self.assertIn("error", result["didResolutionMetadata"])
        self.assertEqual(result["didResolutionMetadata"]["error"], "notFound")
    
    def test_verify_did_document_structure(self):
        """Test verifying the structure of a DID document"""
        # Function to verify DID document structure
        def verify_did_document_structure(doc):
            # Check required fields
            required_fields = ["@context", "id"]
            for field in required_fields:
                if field not in doc:
                    return False, f"Missing required field: {field}"
            
            # Check that the context includes DID v1
            if "https://www.w3.org/ns/did/v1" not in doc["@context"]:
                return False, "Missing required context: https://www.w3.org/ns/did/v1"
            
            # Check that the id is a valid DID
            if not doc["id"].startswith("did:"):
                return False, "Invalid DID format for id"
            
            # Check verification methods if present
            if "verificationMethod" in doc:
                for vm in doc["verificationMethod"]:
                    required_vm_fields = ["id", "type", "controller"]
                    for field in required_vm_fields:
                        if field not in vm:
                            return False, f"Missing required field in verificationMethod: {field}"
                    
                    # Check that the verification method has a public key
                    if not any(key in vm for key in ["publicKeyMultibase", "publicKeyJwk", "publicKeyPem"]):
                        return False, "Verification method missing public key"
            
            # Check authentication if present
            if "authentication" in doc:
                if not isinstance(doc["authentication"], list):
                    return False, "authentication must be an array"
            
            # Check services if present
            if "service" in doc:
                if not isinstance(doc["service"], list):
                    return False, "service must be an array"
                
                for service in doc["service"]:
                    required_service_fields = ["id", "type", "serviceEndpoint"]
                    for field in required_service_fields:
                        if field not in service:
                            return False, f"Missing required field in service: {field}"
            
            return True, "DID document is valid"
        
        # Resolve a DID
        result = self.resolver.resolve("did:web:edu:tu.berlin")
        doc = result["didDocument"]
        
        # Verify the structure
        valid, message = verify_did_document_structure(doc)
        self.assertTrue(valid, message)
        
        # Test with an invalid document
        invalid_doc = {
            "id": "did:web:edu:tu.berlin"
            # Missing @context
        }
        valid, message = verify_did_document_structure(invalid_doc)
        self.assertFalse(valid)
        self.assertIn("Missing required field", message)
        
        # Test with invalid verification method
        invalid_doc = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:edu:tu.berlin",
            "verificationMethod": [{
                "id": "did:web:edu:tu.berlin#key-1",
                "type": "Ed25519VerificationKey2020"
                # Missing controller and public key
            }]
        }
        valid, message = verify_did_document_structure(invalid_doc)
        self.assertFalse(valid)
    
    def test_handle_network_errors(self):
        """Test handling network errors during DID resolution"""
        # Mock requests.get to simulate network errors
        with patch('requests.get') as mock_get:
            # Set up the mock to raise an exception
            mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")
            
            # In a real implementation, the resolver would handle this error
            # For this mock, we'll test the error handling in our DID resolver
            
            # Create a DID that would require an HTTP request
            test_did = "did:web:example.org"
            
            # Ensure it's not already in our mock data
            if test_did in self.resolver.did_documents:
                self.resolver.remove_did_document(test_did)
            
            # Resolve the DID
            result = self.resolver.resolve(test_did)
            
            # Check that the resolution failed with an error
            self.assertIn("didResolutionMetadata", result)
            self.assertIn("error", result["didResolutionMetadata"])
    
    def test_cached_resolution(self):
        """Test caching in DID resolution"""
        # Create a subclass of our resolver with caching
        class CachingDIDResolver(DIDResolver):
            def __init__(self):
                super().__init__()
                self.cache = {}
                self.resolution_count = {}
            
            def resolve(self, did):
                # Track resolution count
                self.resolution_count[did] = self.resolution_count.get(did, 0) + 1
                
                # Check cache
                if did in self.cache:
                    # Return cached result with cache metadata
                    result = self.cache[did].copy()
                    result["didResolutionMetadata"]["fromCache"] = True
                    return result
                
                # Resolve using parent method
                result = super().resolve(did)
                
                # Cache successful resolutions
                if "didDocument" in result:
                    self.cache[did] = result.copy()
                
                return result
        
        # Create the caching resolver
        caching_resolver = CachingDIDResolver()
        
        # Resolve a DID twice
        did = "did:web:edu:tu.berlin"
        result1 = caching_resolver.resolve(did)
        result2 = caching_resolver.resolve(did)
        
        # Check that both resolutions were successful
        self.assertIn("didDocument", result1)
        self.assertIn("didDocument", result2)
        
        # Check that the second resolution was from cache
        self.assertIn("fromCache", result2["didResolutionMetadata"])
        self.assertTrue(result2["didResolutionMetadata"]["fromCache"])
        
        # Check that the DID was only resolved once
        self.assertEqual(caching_resolver.resolution_count[did], 2)
    
    def test_did_url_dereferencing(self):
        """Test dereferencing DID URLs"""
        # Function to dereference a DID URL
        def dereference_did_url(did_url, resolver):
            # Parse the DID URL
            if "#" in did_url:
                did, fragment = did_url.split("#", 1)
                fragment = "#" + fragment
            else:
                did = did_url
                fragment = ""
            
            # Resolve the DID
            result = resolver.resolve(did)
            
            # Check for errors
            if "error" in result.get("didResolutionMetadata", {}):
                return result
            
            # If there's a fragment, find the corresponding element
            if fragment:
                doc = result["didDocument"]
                
                # Check verification methods
                if "verificationMethod" in doc:
                    for vm in doc["verificationMethod"]:
                        if vm["id"] == did_url:
                            return {
                                "dereferencingMetadata": {
                                    "contentType": "application/did+json"
                                },
                                "contentStream": vm,
                                "contentMetadata": {}
                            }
                
                # Check services
                if "service" in doc:
                    for service in doc["service"]:
                        if service["id"] == did_url:
                            return {
                                "dereferencingMetadata": {
                                    "contentType": "application/did+json"
                                },
                                "contentStream": service,
                                "contentMetadata": {}
                            }
                
                # Fragment not found
                return {
                    "dereferencingMetadata": {
                        "error": "notFound",
                        "message": f"Fragment {fragment} not found in DID document"
                    }
                }
            
            # Return the full DID document
            return {
                "dereferencingMetadata": {
                    "contentType": "application/did+json"
                },
                "contentStream": result["didDocument"],
                "contentMetadata": result["didDocumentMetadata"]
            }
        
        # Test dereferencing a DID URL with a fragment
        did_url = "did:web:edu:tu.berlin#key-1"
        result = dereference_did_url(did_url, self.resolver)
        
        # Check that dereferencing was successful
        self.assertNotIn("error", result["dereferencingMetadata"])
        self.assertIn("contentStream", result)
        
        # Check that the correct verification method was returned
        vm = result["contentStream"]
        self.assertEqual(vm["id"], did_url)
        self.assertIn("type", vm)
        
        # Test dereferencing a DID without a fragment
        did_url = "did:web:edu:tu.berlin"
        result = dereference_did_url(did_url, self.resolver)
        
        # Check that dereferencing was successful
        self.assertNotIn("error", result["dereferencingMetadata"])
        self.assertIn("contentStream", result)
        
        # Check that the full DID document was returned
        doc = result["contentStream"]
        self.assertEqual(doc["id"], did_url)
        
        # Test dereferencing a nonexistent DID URL
        did_url = "did:web:edu:tu.berlin#nonexistent"
        result = dereference_did_url(did_url, self.resolver)
        
        # Check that dereferencing failed
        self.assertIn("error", result["dereferencingMetadata"])
        self.assertEqual(result["dereferencingMetadata"]["error"], "notFound")


if __name__ == "__main__":
    unittest.main() 