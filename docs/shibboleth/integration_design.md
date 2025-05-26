# Shibboleth Integration with StudentVC

## Technical Design Document

**Version:** 1.0  
**Last Updated:** April 5, 2025  
**Status:** Draft  

## 1. Introduction

This document details the technical design for integrating Shibboleth federated identity management with the StudentVC system. The integration enables students and employees to use their verifiable credentials for authentication across institutional systems while leveraging existing Shibboleth infrastructure.

### 1.1 Purpose

The purpose of this integration is to:

- Bridge traditional federated identity management (Shibboleth/SAML) with Self-Sovereign Identity (SSI)
- Enable seamless authentication using W3C Verifiable Credentials across institutional services
- Leverage X.509 certificate chains for enhanced trust and security
- Support selective disclosure of identity attributes using BBS+ signatures
- Maintain compatibility with existing institutional identity infrastructure

### 1.2 Scope

This design covers:

- Modified Shibboleth Identity Provider (IdP) components
- Integration with StudentVC wallet for authentication
- Bridge services between SAML and Verifiable Credential ecosystems
- X.509 certificate validation and trust establishment
- Revocation checking mechanisms
- Administrative interfaces and monitoring

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────┐      ┌─────────────────────────┐
│                         │      │                         │
│  Shibboleth Service     │      │  Shibboleth Identity    │
│  Provider (SP)          │◄─────┤  Provider (IdP)         │
│                         │      │                         │
└─────────────────────────┘      └───────────┬─────────────┘
                                             │
                                             │
                                             ▼
┌─────────────────────────┐      ┌─────────────────────────┐
│                         │      │                         │
│  User's StudentVC       │◄─────┤  VC-SAML Bridge         │
│  Wallet                 │      │  Service                │
│                         │      │                         │
└─────────────────────────┘      └───────────┬─────────────┘
                                             │
                                             │
                                             ▼
                                  ┌─────────────────────────┐
                                  │                         │
                                  │  StudentVC Backend      │
                                  │  Services               │
                                  │                         │
                                  └─────────────────────────┘
```

### 2.2 Component Description

#### 2.2.1 Enhanced Shibboleth IdP

A standard Shibboleth Identity Provider with custom extensions to:
- Accept and verify verifiable credential presentations
- Validate X.509 certificate chains
- Generate SAML assertions from verified credentials
- Support enhanced authentication contexts

#### 2.2.2 VC-SAML Bridge Service

A new middleware component that:
- Translates between SAML protocol flows and VC presentation requests
- Handles credential verification using StudentVC backend services
- Manages session state for wallet-based authentication
- Implements trust registry lookups and policy enforcement

#### 2.2.3 StudentVC Wallet Extensions

Additional functionality in the StudentVC wallet to:
- Respond to Shibboleth authentication requests
- Present relevant credentials based on requested attributes
- Support deep linking from web applications
- Manage active SSO sessions

#### 2.2.4 Trust Registry Service

A service that:
- Maintains mappings between Shibboleth federation members and trusted DIDs
- Stores validation policies for credential types and issuers
- Provides configuration for cross-domain trust relationships

## 3. Technical Interfaces

### 3.1 Authentication Protocol Flow

```
User                  Wallet                SP                 IdP               Bridge             Backend
 │                     │                     │                  │                  │                  │
 │ 1. Access SP        │                     │                  │                  │                  │
 │ ────────────────────────────────────────►│                  │                  │                  │
 │                     │                     │                  │                  │                  │
 │                     │                     │ 2. SAML AuthnRequest               │                  │
 │                     │                     │ ────────────────►│                  │                  │
 │                     │                     │                  │                  │                  │
 │                     │                     │                  │ 3. Request VC auth                  │
 │                     │                     │                  │ ─────────────────►                  │
 │                     │                     │                  │                  │                  │
 │                     │                     │                  │                  │ 4. Generate VP request
 │                     │                     │                  │                  │ ────────────────►│
 │                     │                     │                  │                  │                  │
 │                     │                     │                  │                  │◄────────────────┐│
 │                     │                     │                  │                  │ 5. VP request   ││
 │                     │                     │                  │                  │                  │
 │                     │                     │                  │ 6. Redirect to wallet with request  │
 │                     │                     │                  │◄─────────────────┘                  │
 │                     │                     │                  │                  │                  │
 │ 7. Redirect to wallet with request        │                  │                  │                  │
 │◄─────────────────────────────────────────┐                  │                  │                  │
 │                     │                     │                  │                  │                  │
 │ 8. Open wallet      │                     │                  │                  │                  │
 │ ────────────────────►                    │                  │                  │                  │
 │                     │                     │                  │                  │                  │
 │                     │ 9. User selects VC  │                  │                  │                  │
 │ ◄───────────────────────────────────────►│                  │                  │                  │
 │                     │                     │                  │                  │                  │
 │                     │ 10. Create VP       │                  │                  │                  │
 │                     │ ───────────────────┐│                  │                  │                  │
 │                     │◄──────────────────┐││                  │                  │                  │
 │                     │                   │││                  │                  │                  │
 │                     │ 11. Submit VP     │││                  │                  │                  │
 │                     │ ──────────────────┘└┘─────────────────────────────────────────────────────►│
 │                     │                     │                  │                  │                  │
 │                     │                     │                  │                  │ 12. Verify VP    │
 │                     │                     │                  │                  │ ────────────────►│
 │                     │                     │                  │                  │                  │
 │                     │                     │                  │                  │◄────────────────┐│
 │                     │                     │                  │                  │ 13. VP verified ││
 │                     │                     │                  │                  │                  │
 │                     │                     │                  │ 14. Create SAML assertion          │
 │                     │                     │                  │◄─────────────────┘                  │
 │                     │                     │                  │                  │                  │
 │                     │                     │ 15. SAML Response│                  │                  │
 │                     │                     │◄─────────────────┘                  │                  │
 │                     │                     │                  │                  │                  │
 │ 16. Access granted  │                     │                  │                  │                  │
 │◄────────────────────────────────────────┐│                  │                  │                  │
 │                     │                     │                  │                  │                  │
```

### 3.2 API Specifications

#### 3.2.1 VC-SAML Bridge API

| Endpoint | Method | Description | Parameters | Response |
|----------|--------|-------------|------------|----------|
| `/bridge/request` | POST | Generate VP request from SAML AuthnRequest | SAML AuthnRequest, required attributes | VP request object, redirect URI |
| `/bridge/verify` | POST | Verify VP and generate SAML attributes | VP, authentication context, request ID | Verification result, attribute statements |
| `/bridge/sessions` | GET | List active authentication sessions | User identifier | List of active sessions |
| `/bridge/sessions/{id}` | DELETE | Terminate a session | Session ID | Success/failure indication |

#### 3.2.2 Enhanced IdP API Extensions

| Endpoint | Method | Description | Parameters | Response |
|----------|--------|-------------|------------|----------|
| `/idp/authn/vc` | GET | Initiate VC authentication flow | SAML request ID, return URL | Redirect to wallet or QR display |
| `/idp/profile/vc/callback` | POST | Process VP submission | VP, state parameters | Authentication result, redirect |
| `/idp/metadata/vc` | GET | Retrieve IdP VC capabilities | None | VC authentication capabilities |

#### 3.2.3 Wallet API Extensions

| Endpoint | Method | Description | Parameters | Response |
|----------|--------|-------------|------------|----------|
| `/wallet/api/auth/saml/request` | POST | Process incoming SAML auth request | VP request, request origin | Request acceptance status |
| `/wallet/api/auth/saml/sessions` | GET | List active SAML sessions | None | List of active sessions |
| `/wallet/api/auth/saml/logout` | POST | Initiate global logout | Session ID(s) | Logout success status |

### 3.3 Data Models

#### 3.3.1 Enhanced SAML Assertion

```xml
<saml:Assertion>
  <!-- Standard SAML elements -->
  
  <!-- Extended elements -->
  <saml:AttributeStatement>
    <!-- Standard attributes -->
    
    <!-- VC-sourced attributes -->
    <saml:Attribute Name="vc:credentialType">
      <saml:AttributeValue>StudentCredential</saml:AttributeValue>
    </saml:Attribute>
    
    <saml:Attribute Name="vc:issuer">
      <saml:AttributeValue>did:web:edu:tu.berlin</saml:AttributeValue>
    </saml:Attribute>
    
    <saml:Attribute Name="vc:issuanceDate">
      <saml:AttributeValue>2025-01-15T14:32:19Z</saml:AttributeValue>
    </saml:Attribute>
    
    <!-- X.509 metadata -->
    <saml:Attribute Name="x509:subjectDN">
      <saml:AttributeValue>CN=TU Berlin, O=Technical University of Berlin, C=DE</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
  
  <saml:AuthnStatement>
    <!-- Standard authentication statement -->
    
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>
        urn:oasis:names:tc:SAML:2.0:ac:classes:vc:x509
      </saml:AuthnContextClassRef>
      
      <!-- Custom context describing VC authentication -->
      <saml:AuthnContextDecl>
        <vc:VerifiableCredentialAuthn xmlns:vc="urn:oid:vc:schema:1.0">
          <vc:VerificationMethod>DualPath</vc:VerificationMethod>
          <vc:TrustFramework>HAVID</vc:TrustFramework>
          <vc:X509CertificateChainUsed>true</vc:X509CertificateChainUsed>
          <vc:SelectiveDisclosure>true</vc:SelectiveDisclosure>
        </vc:VerifiableCredentialAuthn>
      </saml:AuthnContextDecl>
    </saml:AuthnContext>
  </saml:AuthnStatement>
</saml:Assertion>
```

#### 3.3.2 VC Authentication Request

```json
{
  "type": "VerifiablePresentationRequest",
  "challenge": "d602e96d-48db-4d71-9a9f-cb4bdc24d014",
  "domain": "https://idp.tu-berlin.de",
  "callbackUrl": "https://idp.tu-berlin.de/idp/profile/vc/callback",
  "presentationDefinition": {
    "id": "saml-authn-request-12345",
    "input_descriptors": [
      {
        "id": "studentCredential",
        "name": "Student Credential",
        "purpose": "We need to verify your student status",
        "constraints": {
          "fields": [
            {
              "path": ["$.credentialSubject.studentID", "$.vc.credentialSubject.studentID"],
              "filter": {
                "type": "string"
              }
            },
            {
              "path": ["$.credentialSubject.university", "$.vc.credentialSubject.university"],
              "filter": {
                "type": "string",
                "enum": ["Technical University of Berlin", "Free University of Berlin"]
              }
            }
          ]
        }
      }
    ]
  },
  "samlRequestId": "SAML-12345678901234567890",
  "relayState": "https://service.example.org/protected-resource"
}
```

## 4. X.509 Integration Details

### 4.1 X.509 Certificate Usage

The integration leverages X.509 certificates in several ways:

1. **Certificate Chain Validation**
   - The IdP verifies the X.509 certificate chain embedded in the verifiable credential
   - Certificates are validated against institution-specific trust anchors
   - Path validation follows RFC 5280 requirements

2. **Subject Alternative Name (SAN) Extraction**
   - DIDs are extracted from the Subject Alternative Name extension of certificates
   - The format follows the HAVID specification for DID embedding

3. **Cross-Certification**
   - Educational institution CAs may establish cross-certification with Shibboleth federation operators
   - This allows traditional PKI trust to enhance SSI trust mechanisms

### 4.2 Certificate Extensions

The following certificate extensions are utilized:

```
SubjectAltName [critical]:
  URI:did:web:edu:tu.berlin

AuthorityInfoAccess:
  OCSP - URI:http://ocsp.tu-berlin.de/
  CA Issuers - URI:http://ca.tu-berlin.de/certs/ca.crt

CertificatePolicies:
  Policy: 2.16.840.1.114412.1.3.0.1
    CPS: https://tu-berlin.de/pki/cps
    User Notice:
      Explicit Text: This certificate may be used for educational credential issuance

QcStatements:
  id-etsi-qcs-QcCompliance
  id-etsi-qcs-QcType (id-etsi-qct-eseal)
```

## 5. Selective Disclosure Implementation

### 5.1 BBS+ Integration with SAML

The integration supports BBS+ selective disclosure by:

1. Ensuring the Shibboleth SP only requests necessary attributes
2. Translating these attribute requests into appropriate VP request format
3. Supporting the wallet's capability to create derived proofs
4. Extending SAML assertions to indicate which attributes were selectively disclosed

### 5.2 Technical Implementation

```python
# Example of generating a VP request with selective disclosure support
def generate_vp_request_with_selective_disclosure(saml_authn_request):
    # Extract requested attributes from SAML request
    requested_attributes = extract_requested_attributes(saml_authn_request)
    
    # Map SAML attributes to VC credential fields
    vc_field_paths = map_attributes_to_vc_fields(requested_attributes)
    
    # Create presentation definition with only necessary fields
    presentation_definition = {
        "id": f"saml-authn-{uuid.uuid4()}",
        "input_descriptors": [
            {
                "id": "student_credential",
                "constraints": {
                    "fields": [{"path": path} for path in vc_field_paths]
                }
            }
        ]
    }
    
    # Include BBS+ specific options
    vp_request = {
        "challenge": generate_challenge(),
        "domain": get_idp_domain(),
        "presentation_definition": presentation_definition,
        "format": {
            "ldp_vp": {
                "proof_type": ["BbsBlsSignatureProof2020"]
            }
        }
    }
    
    return vp_request
```

## 6. Revocation Checking

### 6.1 Revocation Methods

The integration supports multiple revocation methods:

1. **X.509 OCSP and CRL**
   - Standard X.509 revocation checking for embedded certificates
   - OCSP stapling for performance optimization

2. **Status List 2021**
   - W3C standard revocation method for verifiable credentials
   - Integration with institutional status list endpoints

3. **RevocationList2021**
   - Alternative revocation mechanism for compatibility

### 6.2 Revocation Checking Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  Receive VP     │────►│  Extract VC     │────►│ Check X.509     │
│                 │     │  and X.509      │     │ Revocation      │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  Complete       │◄────┤  Check Status   │◄────┤  Check VC       │
│  Verification   │     │  List Service   │     │  Revocation     │
│                 │     │                 │     │  Credential     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## 7. Trust Registry Implementation

### A centralized service will maintain federation trust relationships:

```json
{
  "federations": [
    {
      "id": "eduGAIN",
      "description": "Global academic identity federation",
      "metadata_url": "https://technical.edugain.org/metadata.php",
      "trusted_issuers": [
        {
          "did": "did:web:edu:tu.berlin",
          "x509_subject_dn": "CN=TU Berlin, O=Technical University of Berlin, C=DE",
          "federation_entity_id": "https://idp.tu-berlin.de/idp/shibboleth",
          "trust_level": "high",
          "credential_types": ["StudentCredential", "FacultyCredential"]
        },
        {
          "did": "did:web:edu:fu-berlin.de",
          "x509_subject_dn": "CN=FU Berlin, O=Free University of Berlin, C=DE",
          "federation_entity_id": "https://idp.fu-berlin.de/idp/shibboleth",
          "trust_level": "high",
          "credential_types": ["StudentCredential", "FacultyCredential"]
        }
      ]
    }
  ],
  "trust_policies": [
    {
      "id": "standard_education",
      "description": "Standard policy for educational service providers",
      "required_attributes": {
        "minimum": ["eduPersonPrincipalName", "eduPersonAffiliation"],
        "optional": ["eduPersonEntitlement", "displayName"]
      },
      "authentication_context": {
        "acceptable_classes": [
          "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
          "urn:oasis:names:tc:SAML:2.0:ac:classes:vc:x509"
        ],
        "minimum_assurance_level": "substantial"
      }
    }
  ]
}
```

## 8. Implementation Plan

### 8.1 Development Phases

1. **Phase 1: Core Components**
   - Develop the VC-SAML Bridge service
   - Create Shibboleth IdP extensions
   - Implement basic wallet SAML support
   - Develop trust registry prototype

2. **Phase 2: X.509 Integration**
   - Implement X.509 certificate chain validation
   - Add certificate revocation checking
   - Create SAN extraction and verification
   - Test dual-path verification

3. **Phase 3: Advanced Features**
   - Implement BBS+ selective disclosure
   - Add Status List 2021 integration
   - Create administrative interfaces
   - Develop security audit logging

4. **Phase 4: Testing and Deployment**
   - Set up test federation environment
   - Conduct integration testing with multiple IdPs and SPs
   - Perform security assessment
   - Develop documentation and training materials

### 8.2 Key Milestones

| Milestone | Description | Target Date |
|-----------|-------------|-------------|
| Initial Prototype | Basic VC-SAML Bridge with simple authentication flow | Q2 2025 |
| X.509 Integration | Complete PKI integration with certificate validation | Q3 2025 |
| Selective Disclosure | Working BBS+ selective disclosure in SAML context | Q4 2025 |
| Pilot Deployment | Deployment with selected educational institutions | Q1 2026 |
| Production Release | Full production deployment with documentation | Q2 2026 |

## 9. Security Considerations

### 9.1 Threat Model

Key threats and mitigations:

1. **Credential Forgery**
   - Mitigation: Dual-path verification through both DID and X.509
   - Mitigation: Signature validation on all credentials

2. **Man-in-the-Middle Attacks**
   - Mitigation: TLS for all communications
   - Mitigation: Domain binding in authentication requests

3. **Replay Attacks**
   - Mitigation: One-time challenges in VP requests
   - Mitigation: Limited validity periods for authentication sessions

4. **Privacy Leakage**
   - Mitigation: Selective disclosure with BBS+
   - Mitigation: Minimal attribute disclosure policy enforcement

5. **Revocation Delays**
   - Mitigation: Multiple revocation checking methods
   - Mitigation: Configurable validity periods

### 9.2 Audit Requirements

The system will maintain comprehensive logs for:

1. Authentication attempts and results
2. Credential verification details (issuer, type, verification path)
3. Attribute release decisions
4. Administrative actions
5. Security-relevant events (failed verifications, potential attacks)

## 10. References

1. Shibboleth Identity Provider v4.x Documentation
2. SAML 2.0 Technical Overview
3. W3C Verifiable Credentials Data Model 2.0
4. IETF RFC 5280: Internet X.509 Public Key Infrastructure
5. W3C Decentralized Identifiers (DIDs) v1.0
6. BBS+ Signatures 2020 Specification
7. Status List 2021 Specification
8. High Assurance Verifiable Identifiers (HAVID) Specification

---

## Appendix A: Sample Code Snippets

### A.1 Extracting DIDs from X.509 Certificates

```python
def extract_did_from_certificate(x509_cert):
    """Extract DID from X.509 certificate SAN extension."""
    for extension in x509_cert.extensions:
        if extension.oid.dotted_string == '2.5.29.17':  # SubjectAltName
            san = extension.value
            for name in san:
                if name.type_id == '1.3.6.1.5.5.7.8.3':  # uniformResourceIdentifier
                    uri = name.value
                    if uri.startswith('did:'):
                        return uri
    return None
```

### A.2 Generating SAML Assertion from Verified Credential

```python
def generate_saml_assertion_from_vc(verified_credential, saml_request_id):
    """Create SAML assertion from verified credential."""
    # Extract credential subject attributes
    attributes = extract_attributes_from_vc(verified_credential)
    
    # Create standard SAML assertion
    assertion = create_basic_saml_assertion(saml_request_id)
    
    # Add VC-specific attributes
    assertion.attribute_statements[0].attributes.extend([
        create_saml_attribute('vc:issuer', verified_credential['issuer']),
        create_saml_attribute('vc:issuanceDate', verified_credential['issuanceDate']),
        create_saml_attribute('vc:credentialType', 
                             verified_credential['type'][1] if len(verified_credential['type']) > 1 else 'VerifiableCredential')
    ])
    
    # Add X.509 metadata if available
    if 'x509Certificate' in verified_credential:
        x509_cert = parse_x509_certificate(verified_credential['x509Certificate'])
        assertion.attribute_statements[0].attributes.append(
            create_saml_attribute('x509:subjectDN', x509_cert.subject.rfc4514_string())
        )
    
    # Add credential subject attributes
    for attr_name, attr_value in attributes.items():
        assertion.attribute_statements[0].attributes.append(
            create_saml_attribute(attr_name, attr_value)
        )
    
    # Set authentication context
    verification_methods = []
    if verified_credential.get('x509Certificate'):
        verification_methods.append('X509')
    if verified_credential.get('proof'):
        verification_methods.append('DID')
    
    assertion.authn_statement.authn_context.authn_context_class_ref.text = \
        f"urn:oasis:names:tc:SAML:2.0:ac:classes:vc:{':'.join(verification_methods).lower()}"
    
    return assertion
```

## Appendix B: IdP Configuration Example

```xml
<bean id="shibboleth.authn.VC.externalAuthnPath" class="java.lang.String"
    c:_0="contextRelative:api/authn/vc" />

<bean id="shibboleth.authn.VC.nonBrowserSupported" class="java.lang.Boolean"
    c:_0="true" />

<bean id="shibboleth.authn.VC.supported" class="java.lang.Boolean"
    c:_0="true" />

<bean id="shibboleth.authn.VC.VCVerificationService"
    class="org.shibboleth.idp.vc.authn.impl.VCVerificationService"
    p:verificationService-ref="studentVC.verificationService"
    p:trustRegistryService-ref="studentVC.trustRegistry"
    p:x509TrustManager-ref="shibboleth.X509TrustManager"
    p:allowedCredentialTypes="#{{'StudentCredential', 'FacultyCredential', 'AlumniCredential'}}" />
