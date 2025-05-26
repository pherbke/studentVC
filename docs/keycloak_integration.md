# Keycloak Integration for StudentVC

## Overview

This document describes the integration of Keycloak with the StudentVC system, providing an alternative authentication method to Shibboleth while maintaining compatibility with the existing TU Berlin Authenticator for multi-factor authentication (MFA).

**Author:** StudentVC Team  
**Date:** April 5, 2025  
**Version:** 1.0

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture](#architecture)
3. [Setup Instructions](#setup-instructions)
4. [Configuration Options](#configuration-options)
5. [Authentication Flow](#authentication-flow)
6. [MFA Integration](#mfa-integration)
7. [API Reference](#api-reference)
8. [Examples](#examples)
9. [Security Considerations](#security-considerations)
10. [Troubleshooting](#troubleshooting)

## Introduction

Keycloak is an open-source Identity and Access Management (IAM) solution that provides single sign-on (SSO), identity federation, social login, and user management capabilities. This integration allows universities to use Keycloak as an alternative to Shibboleth for authentication in the StudentVC system, with support for:

- Authentication of students and employees using Keycloak credentials
- Multi-factor authentication through the TU Berlin Authenticator app
- Secure attribute passing from Keycloak to credential issuance services
- Mapping of Keycloak sessions to credential issuance processes
- Role-based access control for credential issuance and management

## Architecture

The Keycloak integration consists of three main components:

1. **KeycloakClient**: Core client for interacting with Keycloak APIs
2. **KeycloakAdapter**: Adapter integrating Keycloak with StudentVC
3. **CredentialIssuerKeycloakAdapter**: Interface for credential issuance

```
┌─────────────────┐      ┌────────────────┐      ┌─────────────────┐
│                 │      │                │      │                 │
│    Keycloak     │<─────│  KeycloakAdapter│<─────│  StudentVC      │
│    Server       │─────>│                │─────>│  System         │
│                 │      │                │      │                 │
└─────────────────┘      └────────────────┘      └─────────────────┘
                               │
                               │
                               ▼
                         ┌────────────────┐
                         │                │
                         │  TU Berlin     │
                         │  Authenticator │
                         │                │
                         └────────────────┘
```

This architecture allows for:

- Clear separation of concerns between components
- Easy replacement or update of individual components
- Flexibility to support different authentication methods
- Integration with existing TU Berlin Authenticator for MFA

## Setup Instructions

### Prerequisites

- Keycloak server (version 17.0.0 or higher)
- Python 3.8+
- Required Python packages: `requests`, `cryptography`

### Installation

1. Install required packages:

```bash
pip install requests cryptography
```

2. Copy the Keycloak integration files to your StudentVC installation:

```bash
cp src/keycloak_integration.py /path/to/studentvc/
```

### Keycloak Server Configuration

1. **Create a new realm** for your university (e.g., "university")

2. **Create a client** for StudentVC:
   - Client ID: `student-vc`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`
   - Standard Flow Enabled: `ON`
   - Direct Access Grants Enabled: `ON`
   - Service Accounts Enabled: `ON`

3. **Configure client scope** to include the required attributes:
   - Navigate to Client Scopes > Create
   - Add mapper for university attributes (StudentID, EnrollmentDate, etc.)

4. **Set up roles** for different user types:
   - student: Basic student role
   - faculty: Faculty member role
   - alumni: Alumni role

5. **Configure Authentication Flow** to include MFA:
   - Navigate to Authentication > Flows
   - Create a copy of the Browser flow
   - Add the OTP Form as a required action

## Configuration Options

The Keycloak integration can be configured using the following options:

```python
# Example configuration
keycloak_config = {
    'keycloak_url': 'https://keycloak.example.org/auth',
    'realm': 'university',
    'client_id': 'student-vc',
    'client_secret': 'your-client-secret',
    'use_mfa': True
}
```

| Option | Description | Default |
|--------|-------------|---------|
| `keycloak_url` | Base URL of your Keycloak server | `https://keycloak.example.org/auth` |
| `realm` | Realm name in Keycloak | `university` |
| `client_id` | Client ID configured in Keycloak | `student-vc` |
| `client_secret` | Client secret from Keycloak | (required) |
| `use_mfa` | Whether to use multi-factor authentication | `True` |

## Authentication Flow

The authentication flow with Keycloak integration consists of the following steps:

1. **Initial Authentication**:
   - User provides username and password to StudentVC
   - StudentVC authenticates with Keycloak using these credentials
   - Keycloak returns a token and session information

2. **MFA Verification** (if enabled):
   - User is prompted to enter a code from the TU Berlin Authenticator
   - Code is verified against the registered device for the user
   - Upon successful verification, the session is marked as MFA-complete

3. **Session Management**:
   - Authenticated sessions are managed by the KeycloakAdapter
   - Sessions have an expiration time and MFA status
   - Session information is used for credential issuance and verification

4. **Credential Issuance**:
   - User attributes are retrieved from the Keycloak session
   - Authentication evidence (including MFA status) is included in the credential
   - Credential is issued with appropriate security level based on authentication

```
┌─────────────────┐      ┌────────────────┐      ┌─────────────────┐
│    User         │─────>│  Keycloak      │─────>│  Session        │
│  Authentication │      │  Validation    │      │  Creation       │
└─────────────────┘      └────────────────┘      └─────────────────┘
                                                          │
                                                          ▼
┌─────────────────┐      ┌────────────────┐      ┌─────────────────┐
│  Credential     │<─────│  Attribute     │<─────│  MFA            │
│  Issuance       │      │  Retrieval     │      │  Verification   │
└─────────────────┘      └────────────────┘      └─────────────────┘
```

## MFA Integration

The Keycloak integration supports multi-factor authentication through the TU Berlin Authenticator app, which implements the Time-based One-Time Password (TOTP) algorithm according to RFC 6238.

### MFA Setup Flow

1. **Device Registration**:
   - User registers their device with the TU Berlin Authenticator
   - A secret key is generated and stored in Keycloak
   - QR code is displayed for the user to scan with the authenticator app

2. **Code Generation and Verification**:
   - TOTP codes are generated based on the secret key and current time
   - Codes change every 30 seconds to prevent replay attacks
   - Verification includes a time window to account for clock differences

3. **MFA Evidence in Credentials**:
   - When a credential is issued, the MFA status is included as evidence
   - This provides an audit trail and allows verifiers to check authentication strength
   - Credentials include whether "basic" (username/password) or "strong" (with MFA) authentication was used

## API Reference

### `KeycloakClient`

Core client for interacting with Keycloak APIs.

```python
client = KeycloakClient(base_url, realm, client_id, client_secret)
```

**Methods**:
- `authenticate_user(username, password)`: Authenticate user with username and password
- `get_user_info(access_token)`: Get user information using access token
- `initiate_totp_setup(user_id)`: Initiate TOTP setup for a user
- `verify_totp(user_id, code)`: Verify TOTP code for a user

### `TOTPAuthenticator`

Implementation of Time-based One-Time Password (TOTP) authenticator.

```python
totp = TOTPAuthenticator(time_step=30, digits=6, algorithm='sha1')
```

**Methods**:
- `generate_secret()`: Generate a new secret key
- `generate_code(secret, time_offset=0)`: Generate TOTP code for a secret
- `verify_code(secret, code, window=1)`: Verify TOTP code

### `KeycloakAdapter`

Adapter to integrate Keycloak with StudentVC system.

```python
adapter = KeycloakAdapter(keycloak_url, realm, client_id, client_secret, use_mfa=True)
```

**Methods**:
- `authenticate_user(username, password)`: Authenticate user with Keycloak
- `setup_mfa(session_id)`: Set up MFA for a user session
- `verify_mfa(session_id, code)`: Verify MFA code for a session
- `get_user_attributes(session_id)`: Get user attributes from a session
- `has_completed_mfa(session_id)`: Check if a session has completed MFA
- `is_session_valid(session_id)`: Check if a session is valid
- `logout(session_id)`: Logout a session

### `CredentialIssuerKeycloakAdapter`

Adapter for credential issuance using Keycloak authentication.

```python
issuer_adapter = CredentialIssuerKeycloakAdapter(keycloak_adapter)
```

**Methods**:
- `get_credential_subject_data(session_id, credential_type)`: Get credential subject data
- `get_authentication_evidence(session_id)`: Get authentication evidence for a credential

### Helper Functions

- `create_keycloak_adapter(config=None)`: Create a Keycloak adapter with given configuration
- `create_credential_issuer_adapter(keycloak_adapter)`: Create a credential issuer adapter

## Examples

### Basic Authentication

```python
from src.keycloak_integration import create_keycloak_adapter

# Create Keycloak adapter
adapter = create_keycloak_adapter({
    'keycloak_url': 'https://keycloak.example.org/auth',
    'realm': 'university',
    'client_id': 'student-vc',
    'client_secret': 'your-client-secret'
})

# Authenticate user
auth_result = adapter.authenticate_user('alice', 'password123')

if auth_result:
    print(f"Authentication successful: {auth_result['session_id']}")
    
    # Check if MFA is required
    if auth_result['mfa_required']:
        print("MFA is required")
        
        # In a real application, prompt the user for MFA code
        mfa_code = input("Enter MFA code: ")
        
        # Verify MFA
        if adapter.verify_mfa(auth_result['session_id'], mfa_code):
            print("MFA verification successful")
        else:
            print("MFA verification failed")
    else:
        print("MFA not required")
else:
    print("Authentication failed")
```

### Credential Issuance

```python
from src.keycloak_integration import create_keycloak_adapter, create_credential_issuer_adapter

# Create Keycloak adapter
keycloak_adapter = create_keycloak_adapter()

# Create credential issuer adapter
issuer_adapter = create_credential_issuer_adapter(keycloak_adapter)

# Authenticate user (assume this was done earlier)
session_id = "example-session-id"

# Get credential subject data
subject_data = issuer_adapter.get_credential_subject_data(session_id, "StudentIDCredential")

if subject_data:
    # Get authentication evidence
    evidence = issuer_adapter.get_authentication_evidence(session_id)
    
    # Create and issue credential
    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "urn:uuid:example-credential-id",
        "type": ["VerifiableCredential", "StudentIDCredential"],
        "issuer": "did:web:edu:tu-berlin",
        "issuanceDate": "2025-04-05T12:00:00Z",
        "credentialSubject": subject_data,
        "evidence": [evidence]
    }
    
    print(f"Credential issued: {credential['id']}")
else:
    print("Failed to get credential subject data")
```

## Security Considerations

When implementing the Keycloak integration, consider the following security aspects:

1. **Transport Security**:
   - Always use HTTPS for all communication with Keycloak
   - Verify TLS certificates to prevent man-in-the-middle attacks

2. **Token Handling**:
   - Never expose access tokens or refresh tokens to end users
   - Store tokens securely and never log them
   - Validate tokens before trusting them

3. **MFA Implementation**:
   - Use secure random number generation for TOTP secrets
   - Implement rate limiting for authentication attempts
   - Consider adding additional factors like IP-based restrictions

4. **Session Management**:
   - Set appropriate session timeouts
   - Implement session revocation mechanisms
   - Clear session data when no longer needed

5. **Client Secret Protection**:
   - Never hardcode client secrets in source code
   - Use environment variables or secure vaults for secrets
   - Rotate client secrets periodically

## Troubleshooting

### Common Issues

#### Authentication Fails

- **Check client credentials**: Verify that client ID and secret are correct
- **Check user credentials**: Ensure username and password are valid
- **Check network connectivity**: Ensure Keycloak server is reachable
- **Check logs**: Look for error messages in Keycloak and application logs

#### MFA Verification Fails

- **Check time synchronization**: Ensure server and client clocks are synchronized
- **Check secret key**: Verify that the correct secret key is being used
- **Check code format**: Ensure the code format matches (e.g., 6 digits)
- **Check time window**: Try adjusting the time window for verification

#### Session Management Issues

- **Check token expiration**: Tokens may have expired
- **Check session storage**: Ensure sessions are being stored correctly
- **Check logout mechanism**: Verify that sessions are properly removed on logout

### Logging and Debugging

Enable detailed logging to troubleshoot issues:

```python
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

---

## Appendix: Migrating from Shibboleth to Keycloak

If you are migrating from Shibboleth to Keycloak, consider the following steps:

1. **Map attributes**: Ensure that all required attributes are properly mapped in Keycloak
2. **Test in parallel**: Run both authentication systems in parallel during migration
3. **Update client configuration**: Update clients to use Keycloak instead of Shibboleth
4. **Migrate user data**: Transfer user data from Shibboleth to Keycloak
5. **Update documentation**: Update all documentation to reflect the new authentication method

Example attribute mapping from Shibboleth to Keycloak:

| Shibboleth Attribute | Keycloak Attribute |
|----------------------|---------------------|
| `urn:mace:dir:attribute-def:uid` | `username` |
| `urn:mace:dir:attribute-def:mail` | `email` |
| `urn:mace:dir:attribute-def:cn` | `name` |
| `urn:mace:dir:attribute-def:givenName` | `given_name` |
| `urn:mace:dir:attribute-def:sn` | `family_name` |
| `urn:mace:dir:attribute-def:eduPersonPrincipalName` | `preferred_username` |
| `urn:mace:dir:attribute-def:eduPersonAffiliation` | `roles` | 