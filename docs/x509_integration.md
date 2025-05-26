# X.509 Certificate Integration for StudentVC

This document describes the X.509 certificate integration implemented in the StudentVC project, enabling verifiable credentials to be linked with X.509 certificates for enhanced trust and interoperability.

## Overview

The StudentVC system now supports dual verification paths:
1. Traditional DID-based verification
2. X.509 certificate-based verification

This integration allows verifiable credentials to be anchored to existing PKI trust frameworks like GÉANT TCS and DFN-PKI, making it easier to establish trust in academic environments that already rely on X.509 certificates.

## High Assurance Verifiable Identifiers (HAVID)

The implementation follows the High Assurance Verifiable Identifiers (HAVID) specification, which defines mechanisms for binding X.509 certificates with DIDs to create high assurance verifiable identifiers. Key aspects include:

- Bidirectional binding between DIDs and X.509 certificates
- Inclusion of certificate chains in DID documents
- Embedding DIDs in certificate SubjectAlternativeName (SAN) extensions
- Dual-path verification protocols

## Certificate Chain Support

The system now supports full certificate chain generation and validation:

1. **Root CA**: Self-signed certificate representing the root of trust
2. **Intermediate CA**: CA certificate signed by the Root CA
3. **End-Entity Certificate**: Certificate for the credential issuer, signed by the Intermediate CA

The certificates are generated with the following structure:
- Root CA has a 10-year validity period and BasicConstraints with CA=true
- Intermediate CA has a 5-year validity period and BasicConstraints with CA=true, path_length=0
- End-Entity certificate has a 1-year validity period and includes the DID in the SAN extension

## Multi-Issuer Support

A key feature of our implementation is support for multiple issuers with their own DIDs while sharing a common PKI infrastructure. This is particularly useful for educational institutions that want to maintain their distinct identities but leverage a shared trust framework.

### Educational PKI Example

As demonstrated in the `multi_issuer_x509_simulation.py` example, multiple universities can issue credentials under their own DIDs:

- Technical University of Berlin (did:web:edu:tu.berlin)
- Free University of Berlin (did:web:edu:fu-berlin.de)

These institutions:
1. Share a common educational PKI with a shared Root CA and Intermediate CA
2. Have their own end-entity certificates with their respective DIDs embedded
3. Create DID documents that include their certificates as verification methods
4. Issue credentials that can be verified through both their DIDs and the educational PKI

### Shared PKI Infrastructure

The shared PKI infrastructure provides several benefits:
- Reduced overhead for individual institutions
- Consistent trust model across different issuers
- Simplified verification process for credential holders and verifiers
- Enhanced interoperability between educational institutions

## X.509 Infrastructure

### Certificate Management

- Certificates are stored in the `instance/certs/` directory
- CA certificates are stored in `instance/certs/ca/`
- The system automatically loads the issuer certificate from `instance/issuer.pem` if available

### Trust Chain Verification

The system supports verification of certificate chains against trusted CA certificates, with specific support for:

- GÉANT TCS (Global Education and Research Network)
- DFN-PKI (German Research Network)
- Custom educational PKIs as demonstrated in the multi-issuer example

## DID-X.509 Binding

The system supports binding X.509 certificates to DIDs in multiple ways:

### did:web Educational Institution Binding

Our implementation introduces special support for educational institutions using DIDs of the form:
- `did:web:edu:institution-name` (e.g., `did:web:edu:tu.berlin`)
- `did:web:edu:institution-domain` (e.g., `did:web:edu:fu-berlin.de`)

These DIDs are bound to X.509 certificates by:
1. Embedding the full DID in the certificate's SubjectAlternativeName extension
2. Including the certificate chain in the DID document as a verification method
3. Ensuring the DID controller matches the certificate subject

### Implementation Example

From the multi-issuer example:

```python
# Create end-entity certificate for TU Berlin with DID in SAN
cert_chain, keys = generate_certificate_chain(
    subject_name=f"{tu_berlin_did}#key-1",
    did=tu_berlin_did
)

# Add certificate chain to DID document as verification method
verification_method_id = f"{tu_berlin_did}#key-1"
tu_berlin_did_document = add_x509_verification_method_to_did_document(
    tu_berlin_did_document,
    end_entity_cert,
    verification_method_id,
    ca_certificates=[intermediate_ca_cert, root_ca_cert]
)
```

## Credential Issuance with X.509

When a credential is issued with X.509 support:

1. The issuer's X.509 certificate chain is included in the credential
2. The credential contains a binding between the issuer's DID and X.509 certificate
3. The credential gains enhanced trust by leveraging existing PKI trust relationships

Example credential with X.509 metadata:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/x509-2021/v1"
  ],
  "id": "https://tu-berlin.de/credentials/123456",
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": "did:web:edu:tu.berlin",
  "issuanceDate": "2025-04-05T13:29:14Z",
  "credentialSubject": {
    "id": "did:web:example.com:holder",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science in Computer Science"
    }
  },
  "x509": {
    "certificateChain": [
      "MIIDEDCCAfigAwIBAgIUEf4tzA...",  // End-entity certificate
      "MIIE1DCCArygAwIBAgIUYH9jsQ...",  // Intermediate CA certificate
      "MIIFTDCCAzSgAwIBAgIUP1gu6x..."   // Root CA certificate
    ],
    "subject": {
      "common_name": "did:web:edu:tu.berlin#key-1"
    }
  },
  "proof": {
    "type": "RsaSignature2018",
    "created": "2025-04-05T13:29:14Z",
    "verificationMethod": "did:web:edu:tu.berlin#key-1",
    "proofPurpose": "assertionMethod",
    "jws": "eyJhbGciOiJSUzI1NiIsI..."
  }
}
```

## Credential Verification with X.509

The verification process supports dual-path verification:

1. **DID-Based Verification**:
   - Resolve the issuer's DID to retrieve the DID document
   - Verify the credential signature using the verification method in the DID document
   - Check the credential status if available

2. **X.509-Based Verification**:
   - Extract the certificate chain from the credential
   - Verify the certificate chain against trusted root CA certificates
   - Check certificate validity periods and revocation status
   - Extract the DID from the certificate's SAN extension
   - Verify that the extracted DID matches the credential issuer

The verifier can choose to require one or both verification paths depending on their trust requirements.

### Implementation Example

```python
# Verify credential using X.509 trust path
is_valid, reason = verify_credential_with_x509(credential, trusted_cas)

if is_valid:
    print("Credential successfully verified using X.509 trust path")
else:
    print(f"Verification failed: {reason}")
```

## Integration with OID4VC and OID4VP

The X.509 integration extends to the OpenID for Verifiable Credentials (OID4VC) and OpenID for Verifiable Presentations (OID4VP) protocols:

1. **OID4VC Issuance**:
   - Enhanced issuer metadata includes X.509 certificate information
   - Credentials issued through OID4VC can include X.509 metadata
   - The credential offer can include certificate chain information

2. **OID4VP Verification**:
   - Presentations can be verified using both DID and X.509 trust paths
   - Verifiers can specify X.509 trust requirements in presentation requests
   - Presentation responses can include X.509 metadata for verification

## End-to-End Simulation

The repository includes a comprehensive end-to-end simulation of the X.509 integration workflow in `examples/multi_issuer_x509_simulation.py`. This simulation demonstrates:

1. Setting up a shared educational PKI with Root and Intermediate CAs
2. Creating certificates for multiple universities with embedded DIDs
3. Creating DID documents with X.509 verification methods
4. Issuing credentials with X.509 metadata from multiple issuers
5. Storing credentials in a holder's wallet
6. Verifying credentials using both DID and X.509 trust paths

## Setup Instructions

### Adding an Issuer Certificate

1. Obtain an X.509 certificate from a trusted CA like GÉANT TCS or DFN-PKI
2. Place the certificate in PEM format at `instance/issuer.pem`
3. Restart the application

### Adding Trusted CA Certificates

1. Place CA certificates in PEM format in the `instance/certs/ca/` directory
2. Restart the application

### Generating a Certificate Chain

```python
from src.x509.certificate import generate_certificate_chain

# Generate a certificate chain with a Root CA, Intermediate CA, and End-Entity certificate
cert_chain, keys = generate_certificate_chain(
    subject_name="did:web:edu:example:issuer#key-1",
    did="did:web:edu:example:issuer"
)

# The cert_chain list contains [end_entity_cert, intermediate_ca_cert, root_ca_cert]
# The keys list contains [end_entity_key, intermediate_ca_key, root_ca_key]
```

## Security Considerations

- Keep private keys secure and separate from certificates
- Regularly update CA certificates to ensure the latest trust information
- Monitor certificate expiration dates
- Use strong cryptographic algorithms for certificates (RSA 2048+ or ECC)
- Implement proper certificate revocation mechanisms

## Future Improvements

- Support for OCSP and CRL-based revocation checking
- Integration with certificate transparency logs
- Automatic certificate renewal via ACME
- Support for additional DID methods with X.509 bindings
- Hardware Security Module (HSM) integration for key protection
- Support for alternative certificate formats (e.g., compact certificates)
- Enhanced performance optimizations for certificate validation 