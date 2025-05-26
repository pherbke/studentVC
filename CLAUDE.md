# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

StudentVC is a cross-platform verifiable credentials system implementing W3C VC Data Model 2.0 with BBS+ signatures for selective disclosure. The system integrates X.509 certificates with DIDs following the HAVID specification, enabling dual-path verification through traditional PKI and decentralized identity systems.

## Development Commands

### Backend Setup and Development
```bash
# Initial setup
cd backend
docker compose up --build

# Development mode (without Docker)
pip install -r requirements.txt
python main.py

# Run tests
python -m unittest discover tests
python -m pytest tests/integration/  # For specific test suites

# X.509 end-to-end testing
./run_x509_tests.sh
python e2e_x509_detailed_simulation.py

# Security analysis
bandit -r src/ -f json -o bandit_report.json
```

### BBS Core Library
```bash
cd bbs-core/python
./build.sh  # Builds Rust library and Python bindings
python main.py  # Run benchmarks
```

### Mobile Applications
```bash
# Android
cd android
./gradlew build
./gradlew installDebug
./gradlew test

# iOS  
cd ios
xcodebuild -scheme "Student Wallet" -configuration Debug build
xcodebuild test -scheme "Student Wallet"
```

## Architecture Overview

### Core System Components

**Flask Backend** (`/backend/src/`):
- **Modular Blueprint Architecture**: Each major function (issuer, verifier, validate, x509) is implemented as a separate Flask blueprint
- **OID4VC/OID4VP Protocol Implementation**: Complete OpenID for Verifiable Credentials issuance and presentation flows
- **X.509 Integration Layer**: Bidirectional binding between X.509 certificates and DIDs with full certificate lifecycle management
- **BBS+ Cryptographic Engine**: Rust-based core providing selective disclosure capabilities via UniFFI bindings

**Mobile Wallets**:
- **Android**: Kotlin/Jetpack Compose with MVVM architecture, Android Keystore integration
- **iOS**: SwiftUI/MVVM with CryptoKit and Keychain integration
- **Shared Protocol Logic**: Both platforms implement identical OID4VC/VP flows with native security storage

### Key Architectural Patterns

1. **Dual Trust Model**: Credentials can be verified through both X.509 certificate chains AND DID-based verification methods
2. **Selective Disclosure**: BBS+ signatures enable zero-knowledge proofs for privacy-preserving credential presentation
3. **Certificate-DID Binding**: X.509 certificates embed DIDs in SubjectAlternativeName extensions with bidirectional verification
4. **Modular Authentication**: Pluggable authentication (Shibboleth, Keycloak, TU Berlin Authenticator MFA)

### Critical Integration Points

**X.509Manager** (`backend/src/x509/manager.py`):
- Central coordinator for certificate operations, DID binding, and trust chain verification
- Manages certificate lifecycle, monitoring, and invalidation
- Integrates with issuer blueprint for credential metadata embedding

**BBS Core Integration**:
- Rust library compiled to native binaries (`.so`, `.dylib`, `.dll`)
- Python bindings via UniFFI for backend
- JNI bindings for Android, Swift Package for iOS
- Key operations: signing, proof generation, verification

**OID4VC Protocol Flow**:
1. **Offer Generation** → **Authorization** → **Token Exchange** → **Credential Issuance**
2. **Presentation Request** → **VP Token Submission** → **Multi-layer Verification**

## Development Guidelines

### Working with X.509 Integration
- X.509 certificates MUST have embedded DIDs in SAN extensions
- Always verify both PKI trust chain AND DID verification methods
- Use `X509Manager` for all certificate operations to ensure proper binding
- Test with `e2e_x509_detailed_simulation.py` for complete flows

### BBS+ Cryptographic Operations
- Never directly call Rust functions - use the generated Python/mobile bindings
- Rebuild BBS core after any Rust changes: `cd bbs-core/python && ./build.sh`
- Test selective disclosure with `tests/integration/test_bbs_selective_disclosure.py`

### OID4VC/VP Protocol Compliance
- Follow OpenID Foundation specifications strictly
- Use PKCE for authorization flows
- Implement proper state management and nonce validation
- Test protocol compliance with `tests/integration/test_oid4vc_protocol.py`

### Mobile Development
- **Android**: Credential storage uses Android Keystore, QR scanning with CameraX
- **iOS**: Credentials stored in Keychain, CryptoKit for cryptographic operations
- Both platforms share identical JSON protocol structures

### Testing Strategy
- **Unit Tests**: Individual component testing
- **Integration Tests**: Cross-component flows (`tests/integration/`)
- **End-to-End Tests**: Complete credential lifecycle (`test_end_to_end_x509_shibboleth.py`)
- **Security Tests**: Cryptographic validation and attack resistance
- **Performance Tests**: Load testing and benchmarking

## File Structure Notes

### Backend Module Organization
- `issuer/`: OID4VC credential issuance endpoints and logic
- `verifier/`: OID4VP presentation verification
- `validate/`: Credential status and validation management  
- `x509/`: Complete X.509 certificate and DID binding system
- `auth/`: Authentication providers (Shibboleth, Keycloak)

### Mobile App Structure
- **Android**: Activity-based with Fragment navigation, Compose UI
- **iOS**: SwiftUI with NavigationStack, MVVM coordinators
- Shared QR code handling for OID4VC protocol initiation

### Testing Organization
- `backend/tests/`: Backend-specific unit tests
- `tests/integration/`: Cross-system integration tests
- Mock infrastructure for X.509, Shibboleth, and BBS+ operations

## Security Considerations

- All credentials use BBS+ signatures for integrity and selective disclosure
- X.509 certificates provide traditional PKI trust anchors
- Mobile storage uses platform-specific secure storage (Keystore/Keychain)
- Multi-factor authentication support via TU Berlin Authenticator
- Complete certificate chain validation required for X.509 trust paths
- Zero-knowledge proofs prevent over-disclosure of credential attributes

## Common Development Tasks

### Adding New Credential Types
1. Update credential schema in `models.py`
2. Modify credential generation in `issuer/credential.py`
3. Update mobile app credential display logic
4. Add corresponding test cases

### Extending X.509 Support
1. Modify certificate templates in `x509/certificate.py`
2. Update DID binding logic in `x509/did_binding.py`
3. Test with multi-issuer simulation scripts

### Protocol Compliance Updates
1. Update endpoint implementations in respective blueprints
2. Modify mobile app protocol handlers
3. Run integration tests to verify compliance

Always run the full test suite before committing changes, especially for cryptographic or protocol modifications.