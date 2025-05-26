# X.509 Credential Flow with did:web:edu:tub DID

This directory contains a complete implementation and test of an end-to-end flow for X.509 certificate integration with verifiable credentials using did:web:edu:tub DID.

## Overview

The implementation demonstrates:

1. Creating a test X.509 certificate
2. Creating a did:web:edu:tub DID linked to the certificate
3. Creating a DID document with the certificate as verification method
4. Signing a credential with the X.509 certificate
5. Storing the credential locally
6. Verifying the credential using both DID and X.509 trust paths

## Files

- `src/x509/did_binding.py`: Functions for binding DIDs to X.509 certificates
- `src/x509/certificate.py`: Functions for X.509 certificate operations
- `src/x509/integration.py`: Functions for integrating X.509 with verifiable credentials
- `tests/test_x509_flow.py`: End-to-end pytest test for the complete flow
- `print_test_credential.py`: Standalone script to run the test and print the credential
- `run_x509_flow_test.sh`: Shell script to run the test in a virtual environment

## Running the Tests

To run the test with pytest:

```bash
./run_x509_flow_test.sh
```

To run the standalone script that prints the credential:

```bash
python print_test_credential.py
```

## did:web:edu:tub DID

The implementation uses a did:web:edu:tub DID format, which is a did:web DID specific to educational institutions, in this case, Technical University of Berlin (TUB). This DID is linked to an X.509 certificate by:

1. Embedding the DID in the certificate's SubjectAlternativeName extension
2. Including the certificate in the DID document as a verification method
3. Signing credentials with this verification method
4. Verifying credentials using both DID and X.509 trust paths

## X.509 Integration

The X.509 integration includes:

1. Bidirectional linkage between X.509 certificates and DIDs
2. Enhanced issuer metadata with X.509 certificate information
3. X.509 metadata embedding in verifiable credentials
4. Verification of credentials using X.509 trust chains

## Example Credential

The test creates a credential with the following structure:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://w3id.org/security/suites/x509-2021/v1"
  ],
  "id": "https://tu-berlin.de/credentials/{uuid}",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "issuer": "did:web:edu:tub:issuer",
  "issuanceDate": "{timestamp}",
  "credentialSubject": {
    "id": "did:web:example.com:holder",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science in Computer Science"
    },
    "college": "Technical University of Berlin",
    "graduationDate": "2023-06-15"
  },
  "x509": {
    "certificateChain": "{certificate-pem}",
    "subject": {
      "common_name": "Technical University of Berlin",
      "organization_name": "TU Berlin",
      "organizational_unit_name": "Computer Science",
      "country_name": "DE",
      "email_address": "issuer@tu-berlin.de"
    }
  },
  "proof": {
    "type": "RsaSignature2018",
    "created": "{timestamp}",
    "verificationMethod": "did:web:edu:tub:issuer#x509-1",
    "proofPurpose": "assertionMethod",
    "jws": "{signature}"
  }
}
```

## Dependencies

- Python 3.10+
- cryptography
- pytest

## Next Steps

- Implement actual cryptographic signing and verification
- Support for X.509 certificate chains and CA verification
- Integration with OCSP and CRL for certificate status checking
- Enhanced security features like challenge-response protocols 