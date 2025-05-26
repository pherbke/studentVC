#!/usr/bin/env python3
"""
Shibboleth Integration Demo for StudentVC

This script demonstrates the integration between Shibboleth federated identity 
and StudentVC verifiable credentials with X.509 certificates.

This is a simplified proof-of-concept that shows:
1. Generation of a SAML authentication request
2. Translation to a verifiable presentation request
3. Creation of a verifiable presentation
4. Verification through both DID and X.509 paths
5. Generation of a SAML assertion from the verified credential

Author: StudentVC Team
Date: April 5, 2025
"""

import json
import uuid
import datetime
import base64
import os
from urllib.parse import urlencode

# Remove cryptography imports and replace with mocked functionality
# from cryptography import x509
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.x509.oid import NameOID

# Mock imports - in a real implementation, these would be actual library imports
# from studentvc.x509.certificate import parse_certificate
# from studentvc.x509.did_binding import find_did_in_certificate_san, verify_bidirectional_linkage
# from studentvc.credentials.verification import verify_credential
# from studentvc.saml.bridge import generate_saml_assertion

# For the demo, we'll create simplified mock versions of these functions
class MockSAMLRequest:
    """Simplified SAML Authentication Request"""
    
    def __init__(self, sp_entity_id, idp_entity_id, requested_attributes):
        self.id = f"SAML-{uuid.uuid4()}"
        self.sp_entity_id = sp_entity_id
        self.idp_entity_id = idp_entity_id
        self.requested_attributes = requested_attributes
        self.issue_instant = datetime.datetime.now().isoformat()
        self.assertion_consumer_service_url = f"https://{sp_entity_id}/acs"
    
    def to_xml(self):
        """Return a simplified SAML request XML"""
        return f"""
        <samlp:AuthnRequest 
            ID="{self.id}"
            IssueInstant="{self.issue_instant}"
            AssertionConsumerServiceURL="{self.assertion_consumer_service_url}">
            <saml:Issuer>{self.sp_entity_id}</saml:Issuer>
            <!-- Simplified request structure -->
        </samlp:AuthnRequest>
        """
    
    def encode(self):
        """Base64 encode the request as would happen in a SAML flow"""
        return base64.b64encode(self.to_xml().encode()).decode()


class MockVerifiableCredential:
    """Mock Verifiable Credential with X.509 integration"""
    
    def __init__(self, issuer_did, subject_did, credential_type, claims):
        self.issuer = issuer_did
        self.subject = subject_did
        self.id = f"urn:uuid:{uuid.uuid4()}"
        self.type = ["VerifiableCredential", credential_type]
        self.issuance_date = datetime.datetime.now().isoformat()
        self.expiration_date = (datetime.datetime.now() + datetime.timedelta(days=365)).isoformat()
        self.credential_subject = {
            "id": subject_did,
            **claims
        }
        self.x509_certificate = None
    
    def add_x509_certificate(self, certificate):
        """Add X.509 certificate to the credential"""
        self.x509_certificate = certificate
    
    def to_json(self):
        """Convert to JSON representation"""
        vc = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": self.id,
            "type": self.type,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date,
            "expirationDate": self.expiration_date,
            "credentialSubject": self.credential_subject
        }
        
        if self.x509_certificate:
            vc["x509Certificate"] = self.x509_certificate
        
        return vc


class MockX509Certificate:
    """Mock X.509 certificate with DID in SAN extension"""
    
    def __init__(self, subject_name, issuer_name, subject_did):
        self.subject_name = subject_name
        self.issuer_name = issuer_name
        self.subject_did = subject_did
        self.serial_number = str(uuid.uuid4())
        self.not_valid_before = datetime.datetime.now()
        self.not_valid_after = datetime.datetime.now() + datetime.timedelta(days=365)
        self.extensions = [
            {
                "oid": "2.5.29.17",  # SubjectAltName
                "critical": False,
                "value": [
                    {
                        "type": "uniformResourceIdentifier",
                        "value": subject_did
                    }
                ]
            }
        ]
    
    def to_pem(self):
        """Return mock PEM-encoded certificate"""
        return f"""-----BEGIN CERTIFICATE-----
MIID+zCCAuOgAwIBAgIUJ7u1gvKQn8YkFGFmbZz8KgTcE2AwDQYJKoZIhvcNAQEL
BQAwXDELMAkGA1UEBhMCREUxHzAdBgNVBAoMFnt7aXNzdWVyX25hbWV9fSBPcmdh
bml6MRIwEAYDVQQDDAl7e2lzc3Vlcl9uYW1lfX0xEjAQBgNVBAMMCXt7aXNzdWVy
X25hbWV9fTAeFw0yNTA0MDUwMDAwMDBaFw0yNjA0MDUwMDAwMDBaMFwxCzAJBgNV
BAYTAkRFMR8wHQYDVQQKDBZ7e3N1YmplY3RfbmFtZX19IE9yZ2FuaXoxEjAQBgNV
BAMMCXt7c3ViamVjdF9uYW1lfX0xEjAQBgNVBAMMCXt7c3ViamVjdF9uYW1lfX0w
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKjMzEfYyji
Axu9DaGRV2OGrX2a4tNlSjZWmVdS4fFOCzEgpoD5a6GgXklE9KwLRv9wNLYvc1bN
SDNvsVY7R9PUWE/PCmjZI58n/q7cuI1h4ByQEm2gTL6wR4ByQEm2gTL6wR4L7mw+
WE3KylxrBpQY2Qli99J8WZ2lVUy2aL4xIctA82nzQjrGkLnwJcfcYqHXbUl3C+Bt
YQh41vSbCxj3FM9K9MbjFdZPeEeIeUL0Ya0Ity1AxCQyLtgnjOxvO5Nh0jBSyhIN
R9EIPmYIaLatl/pxE7PkipbBPOmWgYZrIXlc2zqwAjKXI0sSZQlJbe4BwrAfwVIB
AgMBAAGjgcMwgcAwHQYDVR0OBBYEFF1JLAQgLzlI8s3jXHstzzs1HJL9MB8GA1Ud
IwQYMBaAFHmQ0CuZ5ZzIL3C6y65XJ0Bksoq7MAwGA1UdEwEB/wQCMAAwDgYDVR0P
AQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBXBgNVHREE
UDBOgiB7e3N1YmplY3RfZGlkfX0gSW4gU3ViamVjdEFsdE5hbWWGKntyc3ViamVj
dF9kaWR9fQgJe3tzdWJqZWN0X2RpZH19CXt7c3ViamVjdF9kaWR9fTANBgkqhkiG
9w0BAQsFAAOCAQEANVFGPGesOhSnWfn/yme8qCzP0ZWSrCQa4JKJgMjotoM8h+2a
EV9HsMRZrkbXuRc63SoYHFU1TBELrcWr9TtPcr2pPXqra8xi5JMSaA2W96d/2uwl
DRnuPJL0LpHaEqeGxPJ+iOTa4B3FfJ5raZRjz7g3zYIvcL7xEgGGvs7I0Zjkedwu
tjS0ck7q8zGjYSHELeLUYhOzCLnvdtXC4HGGSANXHCknY5rUaEdPxEqpgLrXcbNq
/v9RbNtLuLDjAGwbJuGI2B/z4NatB2/j6M3ngISMh0lfpLrG+Kr6n3JYfeOl9cGn
X/o3jOYpKXD1GnBK4SxVKPNKFE/Lm2/GBQ==
-----END CERTIFICATE-----
"""


def create_mock_certificate(subject_name, issuer_name, subject_did):
    """Create a mock X.509 certificate with DID in SAN extension"""
    cert = MockX509Certificate(subject_name, issuer_name, subject_did)
    return cert.to_pem()


def mock_parse_certificate(pem_data):
    """Mock function to parse a PEM certificate"""
    # Extract the subject DID from the PEM for demonstration purposes
    # In a real implementation, this would parse the certificate properly
    mock_cert = MockX509Certificate("Mock Subject", "Mock Issuer", "unknown:did")
    
    # For demo, we'll extract the DID from extensions if it's in the PEM data
    for line in pem_data.split('\n'):
        if "subject_did" in line:
            mock_cert.subject_did = line.strip()
    
    return mock_cert


def mock_find_did_in_certificate(cert):
    """Mock function to find DID in certificate SAN extension"""
    # In a real implementation, this would parse the certificate's SAN extension
    # For the demo, we'll just return the subject_did property we set
    return cert.subject_did


def mock_verify_bidirectional_linkage(did, cert):
    """Mock function to verify DID-X.509 bidirectional linkage"""
    # In a real implementation, this would:
    # 1. Check that the DID document references this certificate
    # 2. Check that the certificate contains the DID in SAN
    # 3. Verify signatures
    
    # For demo purposes, just return True if the DID is in the certificate
    found_did = mock_find_did_in_certificate(cert)
    return found_did == did


def mock_verify_credential(credential, verification_method="dual"):
    """Mock credential verification with dual-path support"""
    print(f"Verifying credential using {verification_method} verification method")
    
    verified = True
    verification_results = {
        "verified": verified,
        "checks": []
    }
    
    # DID path verification
    if verification_method in ["did", "dual"]:
        # In a real implementation, this would verify the DID-based signature
        verification_results["checks"].append({
            "type": "DIDVerification",
            "verified": True
        })
    
    # X.509 path verification
    if verification_method in ["x509", "dual"] and credential.get("x509Certificate"):
        # Parse certificate
        cert_pem = credential["x509Certificate"]
        try:
            cert = mock_parse_certificate(cert_pem)
            
            # Find DID in certificate
            cert_did = mock_find_did_in_certificate(cert)
            
            # Check if certificate contains the right DID
            did_verified = cert_did == credential["issuer"]
            
            # Check bidirectional linkage
            bidirectional_verified = mock_verify_bidirectional_linkage(credential["issuer"], cert)
            
            verification_results["checks"].append({
                "type": "X509Verification",
                "certificateVerified": True,
                "didInCertificate": did_verified,
                "bidirectionalLinkage": bidirectional_verified
            })
            
        except Exception as e:
            verification_results["checks"].append({
                "type": "X509Verification",
                "verified": False,
                "error": str(e)
            })
            verified = False
    
    verification_results["verified"] = verified
    return verification_results


def translate_saml_to_vp_request(saml_request):
    """Translate SAML authentication request to VP request"""
    print(f"Translating SAML request {saml_request.id} to VP request")
    
    # Map SAML attributes to VC fields
    attribute_field_mapping = {
        "eduPersonPrincipalName": ["$.credentialSubject.studentID", "$.vc.credentialSubject.studentID"],
        "displayName": ["$.credentialSubject.name", "$.vc.credentialSubject.name"],
        "mail": ["$.credentialSubject.email", "$.vc.credentialSubject.email"],
        "eduPersonAffiliation": ["$.credentialSubject.role", "$.vc.credentialSubject.role"],
    }
    
    # Create input descriptors based on requested attributes
    input_descriptors = []
    fields = []
    
    for attr in saml_request.requested_attributes:
        if attr in attribute_field_mapping:
            fields.append({
                "path": attribute_field_mapping[attr],
                "purpose": f"We need your {attr} for authentication"
            })
    
    if fields:
        input_descriptors.append({
            "id": "studentCredential",
            "name": "Student Credential",
            "purpose": "Authenticate to university services",
            "constraints": {
                "fields": fields
            }
        })
    
    # Create VP request
    vp_request = {
        "type": "VerifiablePresentationRequest",
        "challenge": str(uuid.uuid4()),
        "domain": saml_request.idp_entity_id,
        "callbackUrl": f"https://{saml_request.idp_entity_id}/vc/callback",
        "presentationDefinition": {
            "id": f"saml-{saml_request.id}",
            "input_descriptors": input_descriptors
        },
        "samlRequestId": saml_request.id,
        "relayState": f"https://{saml_request.sp_entity_id}/protected-resource"
    }
    
    return vp_request


def create_verifiable_presentation(credential, vp_request):
    """Create a VP from a credential in response to a request"""
    print(f"Creating verifiable presentation for credential {credential['id']}")
    
    # In a real implementation, this would:
    # 1. Select the credentials matching the request
    # 2. Create a presentation with those credentials
    # 3. Sign the presentation
    
    # Simplified VP structure
    vp = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1"
        ],
        "type": "VerifiablePresentation",
        "id": f"urn:uuid:{uuid.uuid4()}",
        "verifiableCredential": [credential],
        "proof": {
            "type": "Ed25519Signature2020",
            "created": datetime.datetime.now().isoformat(),
            "challenge": vp_request["challenge"],
            "domain": vp_request["domain"],
            "proofPurpose": "authentication",
            "verificationMethod": f"{credential['issuer']}#keys-1",
            "proofValue": "mock_signature_value_for_demo_only"
        }
    }
    
    return vp


def generate_saml_response(vp_verification_result, vp, saml_request_id):
    """Generate SAML response from verified presentation"""
    print(f"Generating SAML response for request {saml_request_id}")
    
    # Extract the credential
    vc = vp["verifiableCredential"][0]
    
    # Extract verification methods used
    verification_methods = []
    for check in vp_verification_result["checks"]:
        if check["type"] == "DIDVerification":
            verification_methods.append("DID")
        elif check["type"] == "X509Verification":
            verification_methods.append("X509")
    
    verification_method_string = ":".join([m.lower() for m in verification_methods])
    
    # Create SAML response (simplified XML)
    response = f"""
    <samlp:Response ID="{uuid.uuid4()}" InResponseTo="{saml_request_id}">
      <saml:Assertion ID="{uuid.uuid4()}">
        <saml:Issuer>mock_idp_entity_id</saml:Issuer>
        <saml:Subject>
          <saml:NameID>{vc["credentialSubject"]["id"]}</saml:NameID>
        </saml:Subject>
        
        <saml:AttributeStatement>
          <saml:Attribute Name="vc:issuer">
            <saml:AttributeValue>{vc["issuer"]}</saml:AttributeValue>
          </saml:Attribute>
          
          <saml:Attribute Name="vc:issuanceDate">
            <saml:AttributeValue>{vc["issuanceDate"]}</saml:AttributeValue>
          </saml:Attribute>
          
          <saml:Attribute Name="vc:credentialType">
            <saml:AttributeValue>{vc["type"][1]}</saml:AttributeValue>
          </saml:Attribute>
    """
    
    # Add credential subject attributes
    for attr_name, attr_value in vc["credentialSubject"].items():
        if attr_name != "id":  # Skip the ID as it's already in the Subject
            response += f"""
          <saml:Attribute Name="{attr_name}">
            <saml:AttributeValue>{attr_value}</saml:AttributeValue>
          </saml:Attribute>
            """
    
    # Add X.509 information if available
    if "x509Certificate" in vc:
        response += f"""
          <saml:Attribute Name="x509:certificate">
            <saml:AttributeValue>CERTIFICATE_DATA_ABBREVIATED</saml:AttributeValue>
          </saml:Attribute>
        """
    
    # Complete the response
    response += f"""
        </saml:AttributeStatement>
        
        <saml:AuthnStatement>
          <saml:AuthnContext>
            <saml:AuthnContextClassRef>
              urn:oasis:names:tc:SAML:2.0:ac:classes:vc:{verification_method_string}
            </saml:AuthnContextClassRef>
          </saml:AuthnContext>
        </saml:AuthnStatement>
      </saml:Assertion>
    </samlp:Response>
    """
    
    return base64.b64encode(response.encode()).decode()


def simulate_wallet_authentication(credential, vp_request):
    """Simulate wallet authentication flow"""
    print("\n3. WALLET: User selects credential and creates presentation")
    
    # Create verifiable presentation
    vp = create_verifiable_presentation(credential, vp_request)
    
    # In a real implementation, this would be sent back to the IdP
    # via the callback URL in the VP request
    callback_url = vp_request["callbackUrl"]
    print(f"   Submitting VP to callback URL: {callback_url}")
    
    return vp


def simulate_bridge_service(saml_request):
    """Simulate the VC-SAML bridge service"""
    print("\n2. BRIDGE: Converting SAML request to VP request")
    
    # Translate SAML request to VP request
    vp_request = translate_saml_to_vp_request(saml_request)
    
    # Print the VP request (for demo purposes)
    print(f"   VP Request generated with challenge: {vp_request['challenge']}")
    
    # Create a deep link URL (simplified)
    wallet_url = "studentvc://authenticate?" + urlencode({
        "request": json.dumps(vp_request)
    })
    print(f"   Deep link for wallet: {wallet_url[:60]}...")
    
    return vp_request


def simulate_idp_verification(vp, vp_request):
    """Simulate IdP verification of the VP"""
    print("\n4. IdP: Verifying the presentation")
    
    # Extract the credentials from the VP
    credentials = vp["verifiableCredential"]
    
    # Verify each credential through both paths
    all_verified = True
    verification_results = []
    
    for credential in credentials:
        result = mock_verify_credential(credential, "dual")
        verification_results.append(result)
        
        if not result["verified"]:
            all_verified = False
            print(f"   ❌ Credential verification failed: {credential['id']}")
        else:
            print(f"   ✅ Credential verified successfully: {credential['id']}")
            
            # Check verification paths
            paths = []
            for check in result["checks"]:
                if check["type"] == "DIDVerification":
                    paths.append("DID")
                elif check["type"] == "X509Verification":
                    paths.append("X.509")
            
            print(f"   Verification paths used: {', '.join(paths)}")
    
    # Verify the VP itself (challenge, domain, etc.)
    vp_valid = (
        vp["proof"]["challenge"] == vp_request["challenge"] and
        vp["proof"]["domain"] == vp_request["domain"]
    )
    
    if not vp_valid:
        all_verified = False
        print("   ❌ VP challenge/domain verification failed")
    else:
        print("   ✅ VP challenge and domain verified")
    
    # Combined verification result
    combined_result = {
        "verified": all_verified,
        "credentialResults": verification_results,
        "vpValid": vp_valid,
        "checks": []  # Add empty checks array to avoid KeyError
    }
    
    # Add checks for verification methods used (to match expected structure in generate_saml_response)
    for result in verification_results:
        for check in result.get("checks", []):
            combined_result["checks"].append(check)
    
    return combined_result


def simulate_saml_authentication_flow():
    """Simulate the complete SAML authentication flow with VCs"""
    print("\n=== Shibboleth + Verifiable Credentials Authentication Demo ===\n")
    
    # Step 1: User accesses a protected resource
    sp_entity_id = "service.tu-berlin.de"
    idp_entity_id = "idp.tu-berlin.de"
    
    print("1. SERVICE PROVIDER: User accesses protected resource")
    print(f"   SP Entity ID: {sp_entity_id}")
    print(f"   IdP Entity ID: {idp_entity_id}")
    
    # Create SAML authentication request
    requested_attributes = ["eduPersonPrincipalName", "displayName", "mail", "eduPersonAffiliation"]
    saml_request = MockSAMLRequest(sp_entity_id, idp_entity_id, requested_attributes)
    print(f"   Generated SAML request ID: {saml_request.id}")
    
    # Simulate redirect to IdP
    print(f"   Redirecting to IdP with SAML request")
    
    # Step 2: Bridge service converts SAML to VP request
    vp_request = simulate_bridge_service(saml_request)
    
    # Step 3: Create a mock student credential with X.509 certificate
    print("\nCreating mock student credential with X.509 certificate")
    
    # Generate certificate for TU Berlin
    issuer_did = "did:web:edu:tu.berlin"
    issuer_name = "TU Berlin"
    
    # Generate certificate for the student
    student_did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
    student_cert = create_mock_certificate(
        "Student Name", 
        issuer_name, 
        student_did
    )
    print(f"   Generated X.509 certificate for {student_did}")
    
    # Create verifiable credential
    student_claims = {
        "name": "Max Mustermann",
        "studentID": "s123456",
        "university": "Technical University of Berlin",
        "role": "student",
        "email": "max.mustermann@tu-berlin.de",
        "program": "Computer Science",
        "level": "Master"
    }
    
    vc = MockVerifiableCredential(
        issuer_did,
        student_did,
        "StudentCredential",
        student_claims
    )
    vc.add_x509_certificate(student_cert)
    
    credential = vc.to_json()
    
    # Step 3: Wallet authentication
    vp = simulate_wallet_authentication(credential, vp_request)
    
    # Step 4: IdP verification
    verification_result = simulate_idp_verification(vp, vp_request)
    
    # Step 5: Generate SAML response if verified
    if verification_result["verified"]:
        print("\n5. IdP: Generating SAML response")
        saml_response = generate_saml_response(verification_result, vp, saml_request.id)
        print(f"   Generated SAML response (truncated): {saml_response[:50]}...")
        
        # Simulate redirect back to SP
        print("\n6. IdP: Redirecting to SP with SAML response")
        print(f"   Destination: {saml_request.assertion_consumer_service_url}")
        
        # Simulate SP receiving the response
        print("\n7. SERVICE PROVIDER: Processing SAML response")
        print("   ✅ Authentication successful")
        print("   User granted access to protected resource")
        
        # Print attributes that would be available to the SP
        print("\n   Available user attributes:")
        for attr, value in student_claims.items():
            print(f"   - {attr}: {value}")
    else:
        print("\n❌ Authentication failed: Credential verification failed")


if __name__ == "__main__":
    # Run the simulation
    simulate_saml_authentication_flow()

