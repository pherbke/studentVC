# StudentVC Backend Tests

This directory contains the test suite for the StudentVC backend application.

## Test Organization

- `test_api.py`: Tests for the core API routes
- `test_crypto.py`: Tests for cryptographic functions
- `test_issuer.py`: Tests for the VC issuer functionality
- `test_verifier.py`: Tests for the VC verifier functionality
- `test_storage.py`: Tests for the storage layer
- `test_x509.py`: Tests for X.509 certificate integration
- `test_x509_e2e.py`: End-to-end tests for X.509 certificate functionality
- `test_havid.py`: Tests for HAVID specification compliance
- `test_oid4vc_integration.py`: Tests for OID4VC/OID4VP integration with X.509 certificates

## Running Tests

To run all tests:

```bash
cd backend
python -m pytest
```

To run a specific test file:

```bash
cd backend
python -m pytest tests/test_x509.py -v
```

To run X.509 related tests:

```bash
cd backend
./run_x509_tests.sh
```

## Test Coverage

To generate a test coverage report:

```bash
cd backend
python -m pytest --cov=src
```

## X.509 Certificate Tests

The X.509 certificate integration tests are divided into several categories:

### Core X.509 Integration (`test_x509.py`)

These tests verify the basic X.509 certificate functionality:
- Loading and parsing certificates
- Extracting information from certificates
- Generating certificate thumbprints
- Creating DID identifiers from certificates
- Certificate validation

### End-to-End X.509 Tests (`test_x509_e2e.py`)

These tests verify the complete flow of X.509 integration:
- Credential issuance with X.509 certificates
- Credential verification with X.509 trust chains
- Status list creation and validation
- Status transitions (active, revoked, suspended)

### HAVID Compliance Tests (`test_havid.py`)

These tests verify compliance with the High Assurance Verifiable Identifiers (HAVID) specification:
- Bidirectional linkage between X.509 certificates and DIDs
- Challenge-response protocol for proving cryptographic control
- Certificate lifecycle monitoring and rekeying detection
- CA-assisted DID creation from CSR key material

### OID4VC/OID4VP Integration Tests (`test_oid4vc_integration.py`)

These tests verify the integration with OpenID for Verifiable Credentials and Presentations:
- Enhanced issuer metadata with X.509 certificate information
- Dual-proof credential offers and presentations
- X.509 metadata embedding in verifiable credentials
- Verification of credentials using both DID and X.509 trust paths
- Selective disclosure of certificate attributes

## CI/CD Integration

The X.509 tests are integrated into our CI/CD pipeline using GitHub Actions. The workflow is defined in `.github/workflows/test-x509.yml` and runs automatically on pushes and pull requests that affect the X.509 integration code.

## Test Fixtures

Common test fixtures are defined in `conftest.py`. These include:
- Test certificates
- DID documents
- Mock HTTP responses
- Database setup/teardown

## Adding New Tests

When adding new tests:
1. Follow the existing naming conventions
2. Add proper test documentation
3. Include both positive and negative test cases
4. Update this README.md if necessary 