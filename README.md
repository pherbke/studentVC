# Student Wallet - Verifiable Credentials

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Platform: Android](https://img.shields.io/badge/Platform-Android-brightgreen.svg)](https://shields.io/)
[![Platform: iOS](https://img.shields.io/badge/Platform-iOS-lightgray.svg)](https://shields.io/)
[![BBS+: Signatures](https://img.shields.io/badge/BBS+-Signatures-orange.svg)](https://shields.io/)

## Project Overview

StudentVC is a cross-platform mobile application designed to securely manage, store, and verify academic credentials using Verifiable Credentials (VC) technology. StudentVC leverages BBS+ signatures to ensure cryptographic security and zero-knowledge proof capabilities for selective disclosure of credential attributes - claims.

This project was completed as part of the Internet of Services Lab (IoSL) course during the winter term 2024/25 at [TU Berlin]((https://www.tu.berlin/)). The project was developed by Patrick Herbke, Research Associate at [SNET](https://www.tu.berlin/snet), lead by Prof. Dr. Axel Küpper, in collaboration with Christopher Ritter as parther during the IDunion project.

## Documentation & Demo

- [📱 Demo Video](https://tubcloud.tu-berlin.de/s/NWB76D3fynL6qAB) - Watch the Student Wallet in action
- [📄 Project Report](docs/Mobile_Wallet-Final_Report.pdf) - Detailed documentation and implementation details
- [🔧 Backend Documentation](backend/README.md) - Setup and usage instructions for the backend server
- [📱 iOS Documentation](ios/README.md) - Setup and usage instructions for iOS application
- [📱 Android Documentation](android/README.md) - Setup and usage instructions for Android application
- [🔒 X.509 Integration](examples/README_X509_INTEGRATION.md) - Details on the X.509 certificate integration
- [🔄 X.509 Workflow](backend/README_X509_Flow.md) - End-to-end flow of X.509 with DIDs and VCs
- [🏫 Multi-Issuer Demo](examples/multi_issuer_x509_simulation.py) - Demonstration of multiple educational institutions using X.509

## Key Features

- **Secure Credential Storage:** Safely store academic credentials on mobile devices.
- **Zero-Knowledge Proofs:** Enable selective disclosure of credential attributes.
- **Cross-Platform Support:** Available on Android and [iOS](https://developer.apple.com/documentation/cryptokit/).
- **Standards Compliance:** Conforms to [W3C Verifiable Credentials standards v2.0](https://www.w3.org/TR/vc-data-model-2.0/).
- **BBS+ Signatures:** Robust cryptographic signature scheme for secure credential management - [Rust crate](https://docs.rs/bbs/0.4.1/bbs/).
- **X.509 Certificate Integration:** Support for traditional PKI-based certificate chains and verification.

## X.509 Implementation

The StudentVC platform integrates X.509 certificate technology with Decentralized Identifiers (DIDs) and Verifiable Credentials according to the High Assurance Verifiable Identifiers (HAVID) specification. This integration enables a dual trust model where credentials can be verified through both traditional PKI chains and DID-based verification.

### Key Components

1. **Certificate Chain Integration:**
   - Full X.509 certificate chain support (Root CA, Intermediate CA, End-Entity certificates)
   - Bidirectional binding between X.509 certificates and DIDs
   - DID embedding in certificate SubjectAlternativeName (SAN) extensions

2. **Multi-Issuer Support:**
   - Educational institutions can leverage their own DIDs (e.g., did:web:edu:tu.berlin, did:web:edu:fu-berlin.de)
   - Shared educational PKI for certificate trust
   - DID documents with X.509 verification methods

3. **Dual-Path Verification:**
   - Traditional PKI trust path verification using certificate chains
   - DID-based verification using verification methods
   - Enhanced security through complementary verification approaches

### Implementation Examples

The repository includes detailed examples and simulations:

- [Multi-Issuer X.509 Simulation](/examples/multi_issuer_x509_simulation.py): Demonstrates how multiple educational institutions can use X.509 certificates with their own DIDs
- [X.509 End-to-End Flow](/backend/README_X509_Flow.md): Comprehensive implementation of certificate generation, DID binding, credential issuance, and verification
- [X.509 Integration Details](/examples/README_X509_INTEGRATION.md): Technical details of the X.509 implementation

### Usage

X.509 integration can be used in the following contexts:

```python
# Generate a certificate chain
from src.x509.certificate import generate_certificate_chain

cert_chain, keys = generate_certificate_chain(
    subject_name="did:web:edu:example:issuer#key-1",
    did="did:web:edu:example:issuer"
)

# Add X.509 verification method to DID document
from src.x509.did_binding import add_x509_verification_method_to_did_document

did_document = add_x509_verification_method_to_did_document(
    did_document,
    cert_chain[0],  # End-entity certificate
    verification_method_id,
    ca_certificates=[cert_chain[1], cert_chain[2]]  # Intermediate and Root CA
)

# Embed X.509 metadata in credential
from src.x509.integration import embed_x509_metadata_in_credential

credential_with_x509 = embed_x509_metadata_in_credential(
    credential,
    cert_chain[0],  # End-entity certificate
    ca_certificates=[cert_chain[1], cert_chain[2]]  # Intermediate and Root CA
)

# Verify credential using X.509 trust path
from src.x509.integration import verify_credential_with_x509

is_valid, reason = verify_credential_with_x509(credential, trusted_cas)
```

### Benefits

- **Enhanced Trust:** Combines traditional PKI trust mechanisms with decentralized identity systems
- **Backwards Compatibility:** Works with existing X.509 certificate infrastructure
- **Standards Compliance:** Follows W3C Verifiable Credentials Data Model and HAVID specifications
- **Interoperability:** Enables credentials to be verified across different trust domains

## Project Structure

The project consists of four main components:

1. **Android Application** (`/android`): [Native Android implementation](https://developer.android.com/compose) with credential storage and verification.
2. **iOS Application** (`/ios`): Native iOS implementation with secure credential management.
3. **Backend Services** (`/backend`): Server-side implementation for credential issuance and verification.
   - Core API services for credential issuance and verification
   - X.509 integration modules for certificate management and trust
   - OID4VC/OID4VP protocol implementation
4. **BBS Core Library** (`/bbs-core`): Core cryptographic library implementing BBS+ signatures.
5. **Examples** (`/examples`): Sample implementations and simulations.
   - Multi-issuer X.509 simulation with educational institutions
   - End-to-end workflow demonstrations
6. **Documentation** (`/docs`): Detailed technical documentation.
   - X.509 integration documentation
   - Protocol specifications

## Installation & Setup

### Prerequisites

- [Android Studio 4.0+](https://android-developers.googleblog.com/2020/05/android-studio-4.html) (for Android development)
- [Xcode 12.0+](https://developer.apple.com/documentation/xcode-release-notes/xcode-12_0_1-release-notes) (for iOS development)
- [Node.js 14.0+](https://nodejs.org/en/blog/release/v14.0.0) and npm or yarn (for backend and library)
- [MongoDB](https://www.mongodb.com/) (for backend data storage)

### Clone the Repository

```bash
git clone https://github.com/yourusername/student-wallet.git
cd student-wallet
```

### Backend Setup

```bash
cd backend
docker compose up --build
```

### Android App Setup

```bash
cd android
./gradlew build
./gradlew installDebug
```

### iOS App Setup

```bash
cd ios
pod install
open StudentWallet.xcworkspace
```

### BBS Core Library Setup

```bash
cd bbs-core
npm install
npm run build
npm test
```

## Usage

1. Set up the BBS core library. The library builds upon the research of [Camenisch et al.](https://eprint.iacr.org/2016/663.pdf).
2. Start the backend server.
3. Run the mobile apps on Android or iOS.

## Open Research 
- Multi-signatures
- Archiving, Re-Issuance, Recovery
- Revocation
- X.509 and DID convergence techniques
- Cross-domain trust establishment
- PKI-DID hybrid verification models
- Certificate transparency for educational credentials

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at:

[Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Acknowledgements

This project was developed as part of the Internet of Services Lab (IoSL) at TU Berlin, under the supervision of Prof. Dr. Axel Küpper.

For questions or further information, please contact Patrick Herbke p.herbke#at##tu-berlin.de.

## University Integration

### Authentication Options

StudentVC provides flexible authentication options to integrate with university identity systems:

#### Shibboleth Connection

StudentVC integrates with Shibboleth Identity Provider (IdP) systems that universities already have in place. This integration allows:

1. Authentication of students and employees using existing university credentials
2. Secure attribute passing from Shibboleth to the credential issuance service
3. Mapping of Shibboleth sessions to credential issuance processes

#### Keycloak Integration

As an alternative to Shibboleth, StudentVC also supports Keycloak for authentication and user management:

```
┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
│                 │        │                 │        │                 │
│    Keycloak     │───────▶│  StudentVC      │───────▶│  Credential     │
│    Server       │        │  Adapter        │        │  Issuance       │
│                 │        │                 │        │                 │
└─────────────────┘        └─────────────────┘        └─────────────────┘
```

##### Key Features

- **Comprehensive IAM**: Single sign-on (SSO), identity federation, and user management
- **Flexible Deployment**: Can run alongside Shibboleth or as a complete replacement
- **Role-Based Access Control**: Fine-grained control over credential issuance and management
- **API Integration**: RESTful APIs for seamless integration with university systems
- **Identity Federation**: Connect with external identity providers (SAML, OIDC, etc.)

##### Implementation

The Keycloak integration provides:

1. User authentication via OAuth2/OpenID Connect
2. Attribute mapping from Keycloak to credential issuance
3. Role-based authorization for different credential types
4. Comprehensive logging and audit trails
5. Integration with the TU Berlin Authenticator for MFA

For detailed setup instructions, see [Keycloak Integration Documentation](docs/keycloak_integration.md).

### Enhanced Security with TU Berlin Authenticator

In addition to primary authentication (Shibboleth or Keycloak), StudentVC provides enhanced security for credential issuance through the TU Berlin Authenticator app:

```
┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
│                 │        │                 │        │                 │
│    Primary      │───────▶│  TU Berlin      │───────▶│  Credential     │
│    Auth         │        │  Authenticator  │        │  Issuance       │
│                 │        │  (2nd factor)   │        │                 │
└─────────────────┘        └─────────────────┘        └─────────────────┘
```

#### Key Features

- **Multi-Factor Authentication**: Requires both "what you know" (password) and "what you have" (mobile device)
- **Time-Based One-Time Passwords (TOTP)**: Generates secure 6-digit codes that expire after 30 seconds
- **Device Binding**: Associates specific registered devices with student accounts
- **Anti-Replay Protection**: Each code can only be used once, preventing replay attacks
- **Credential Evidence**: MFA verification details are embedded in the credential as evidence
- **Audit Trail**: Enhanced logging of authentication events for security monitoring

#### Implementation

The TU Berlin Authenticator app follows TOTP standards (RFC 6238) and provides:

1. Secure registration process with QR code scanning
2. Offline code generation (no network connection needed)
3. Synchronization with university servers for clock drift correction
4. Biometric protection option for accessing the app
5. Backup and recovery procedures for device changes

### Student Data API

The `student_data_api.py` component provides a critical bridge between university backend systems and the credential issuance service:

```
┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
│                 │        │                 │        │                 │
│    Shibboleth   │───────▶│  Student Data   │───────▶│  Credential     │
│    Authentication│        │  API           │        │  Issuance       │
│                 │        │                 │        │                 │
└─────────────────┘        └─────────────────┘        └─────────────────┘
```

#### Key Features

- **Secure Authentication**: Validates Shibboleth sessions before allowing data access
- **Data Retrieval**: Connects to university student information systems to gather accurate data
- **Credential Formatting**: Structures data appropriately for credential issuance
- **Caching**: Reduces load on backend systems through intelligent caching
- **Employee Support**: Handles both student and employee data for different credential types

#### API Endpoints

- `GET /api/v1/student/data`: Main endpoint to retrieve student or employee data based on Shibboleth session
- `GET /api/v1/health`: Health check endpoint
- `POST /api/v1/clear-cache`: Administrative endpoint to clear cached data

#### Configuration

The API is configured through environment variables:

- `SHIBBOLETH_METADATA_URL`: URL to the Shibboleth metadata service
- `STUDENT_DB_API_URL`: URL to the university's student database API
- `STUDENT_DB_API_KEY`: API key for the student database
- `API_KEY`: API key for accessing the Student Data API
- `DEBUG_MODE`: Enable debugging features (set to "False" in production)
- `PORT`: Port number for the API server (default: 5000)

## End-to-End Security

StudentVC provides comprehensive end-to-end security:

1. **Authentication**: 
   - Shibboleth for secure institutional authentication
   - TU Berlin Authenticator for second-factor verification

2. **Credential Issuance**:
   - X.509 certificates with embedded DIDs for issuer authentication
   - BBS+ signatures for cryptographic integrity
   - Evidence of multi-factor authentication embedded in credentials

3. **Presentation and Verification**:
   - Selective disclosure of only necessary attributes
   - Challenge-response protocols for presentation verification
   - Full certificate chain validation to trusted roots
   - BBS+ signature verification for credential integrity

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure environment variables
4. Run the tests: `python -m unittest discover tests`

## Development

For development and testing purposes, you can run the Student Data API with mock data:

```bash
export DEBUG_MODE=true
export PORT=8080
python -m api.student_data_api
```

Then access the API with:

```bash
curl -X GET -H "X-API-Key: test_api_key_for_studentvc_system" -H "X-Shibboleth-Session: SHIB_SESSION_12345" http://localhost:8080/api/v1/student/data
```

## Testing

Run the comprehensive test suite with:

```bash
python -m unittest discover tests
```

For specific component tests:

```bash
python -m tests.integration.test_student_data_api
```

### End-to-End Testing

We've implemented comprehensive end-to-end tests that demonstrate complete flows of the StudentVC system, including:

#### X.509 Certificate and Shibboleth Authentication Flow

This test demonstrates the full credential lifecycle with X.509 certificates and Shibboleth authentication:

```bash
python -m tests.integration.test_end_to_end_x509_shibboleth
```

The flow includes:

1. **X.509 Certificate Creation**: University creates X.509 certificates with embedded DIDs
2. **Shibboleth Authentication**: Student authenticates to university systems via Shibboleth
3. **Student Data Retrieval**: University retrieves verified student data
4. **Credential Issuance**: University issues verifiable credentials signed with BBS+ and backed by X.509
5. **Credential Storage**: Student stores credentials in their wallet
6. **Portal Authentication**: Student logs into university portal with Shibboleth
7. **Credential Presentation**: Student presents their credential to gain resource access
8. **Verification**: Portal verifies the credential using both X.509 chain and BBS+ signature
9. **Access Control**: Student accesses protected resources based on credential type

This demonstrates how X.509 certificates provide a trusted root for credential issuance while BBS+ signatures enable privacy-preserving selective disclosure.

## Production Deployment

For production deployment, the following is recommended:

1. Set `DEBUG_MODE=False`
2. Use a WSGI server like Gunicorn or uWSGI
3. Set up proper TLS encryption
4. Implement proper logging with log rotation
5. Use a reverse proxy for additional security