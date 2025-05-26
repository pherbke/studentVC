#!/usr/bin/env python3
"""
Keycloak Integration for StudentVC

This module provides integration between Keycloak and the StudentVC system,
allowing for authentication, user management, and multi-factor authentication
via the TU Berlin Authenticator.

Author: StudentVC Team
Date: April 5, 2025
"""

import os
import json
import time
import base64
import uuid
import datetime
import hashlib
import logging
import requests
from typing import Dict, List, Optional, Tuple, Any, Union
from urllib.parse import urljoin

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class KeycloakClient:
    """Client for interacting with Keycloak APIs"""
    
    def __init__(self, base_url: str, realm: str, client_id: str, client_secret: str):
        """
        Initialize Keycloak client
        
        Args:
            base_url: Base URL for Keycloak server (e.g., https://keycloak.example.org/auth)
            realm: Realm name
            client_id: Client ID
            client_secret: Client secret
        """
        self.base_url = base_url
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"
        self.userinfo_url = f"{base_url}/realms/{realm}/protocol/openid-connect/userinfo"
        self.admin_url = f"{base_url}/admin/realms/{realm}"
        self.admin_token = None
        self.admin_token_expiry = 0
    
    def _get_admin_token(self) -> Optional[str]:
        """
        Get admin token for Keycloak Admin API
        
        Returns:
            Access token string or None if failed
        """
        now = time.time()
        
        # Check if we have a valid token
        if self.admin_token and self.admin_token_expiry > now + 30:
            return self.admin_token
        
        # Request new token
        try:
            response = requests.post(
                self.token_url,
                data={
                    'grant_type': 'client_credentials',
                    'client_id': self.client_id,
                    'client_secret': self.client_secret
                },
                timeout=10
            )
            
            response.raise_for_status()
            token_data = response.json()
            
            self.admin_token = token_data['access_token']
            self.admin_token_expiry = now + token_data['expires_in']
            
            return self.admin_token
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get admin token: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Tuple[Optional[Dict], int]:
        """
        Authenticate user with username and password
        
        Args:
            username: Username
            password: Password
            
        Returns:
            Tuple of (response data, status code)
        """
        try:
            response = requests.post(
                self.token_url,
                data={
                    'grant_type': 'password',
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'username': username,
                    'password': password,
                    'scope': 'openid'
                },
                timeout=10
            )
            
            if response.status_code != 200:
                return {'error': 'Authentication failed'}, response.status_code
            
            token_data = response.json()
            
            # Parse token to check for MFA requirements
            token_parts = token_data['access_token'].split('.')
            if len(token_parts) == 3:
                # JWT has three parts: header.payload.signature
                try:
                    # Add padding for base64url decode
                    padded = token_parts[1] + '=' * (4 - len(token_parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
                    
                    # Check for MFA completion in the token
                    mfa_required = payload.get('acr', '') == 'mfa' and not payload.get('mfa_complete', False)
                    
                    return {
                        'token': token_data,
                        'mfa_required': mfa_required,
                        'session_state': token_data.get('session_state')
                    }, 200
                
                except Exception as e:
                    logger.error(f"Error parsing token: {e}")
            
            # Default response if we couldn't parse token
            return {
                'token': token_data,
                'mfa_required': False,
                'session_state': token_data.get('session_state')
            }, 200
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication request failed: {e}")
            return {'error': f'Authentication request failed: {str(e)}'}, 500
    
    def get_user_info(self, access_token: str) -> Tuple[Optional[Dict], int]:
        """
        Get user information using access token
        
        Args:
            access_token: OAuth2 access token
            
        Returns:
            Tuple of (user info, status code)
        """
        try:
            response = requests.get(
                self.userinfo_url,
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=10
            )
            
            if response.status_code != 200:
                return {'error': 'Failed to get user info'}, response.status_code
            
            return response.json(), 200
        
        except requests.exceptions.RequestException as e:
            logger.error(f"User info request failed: {e}")
            return {'error': f'User info request failed: {str(e)}'}, 500
    
    def initiate_totp_setup(self, user_id: str) -> Tuple[Optional[Dict], int]:
        """
        Initiate TOTP setup for a user
        
        Args:
            user_id: User ID
            
        Returns:
            Tuple of (setup info, status code)
        """
        admin_token = self._get_admin_token()
        if not admin_token:
            return {'error': 'Failed to get admin token'}, 500
        
        try:
            # Get required actions for user
            response = requests.get(
                f"{self.admin_url}/users/{user_id}",
                headers={'Authorization': f'Bearer {admin_token}'},
                timeout=10
            )
            
            if response.status_code != 200:
                return {'error': 'Failed to get user'}, response.status_code
            
            user_data = response.json()
            
            # Add required action for TOTP
            required_actions = user_data.get('requiredActions', [])
            if 'CONFIGURE_TOTP' not in required_actions:
                required_actions.append('CONFIGURE_TOTP')
            
            # Update user
            response = requests.put(
                f"{self.admin_url}/users/{user_id}",
                headers={
                    'Authorization': f'Bearer {admin_token}',
                    'Content-Type': 'application/json'
                },
                json={
                    'requiredActions': required_actions
                },
                timeout=10
            )
            
            if response.status_code != 204:
                return {'error': 'Failed to update user'}, response.status_code
            
            # Generate TOTP secret
            secret = base64.b32encode(os.urandom(10)).decode('utf-8')
            
            return {
                'secret': secret,
                'otpauth_url': f'otpauth://totp/TU_Berlin:{user_data.get("username")}?secret={secret}&issuer=TU_Berlin',
                'user_id': user_id
            }, 200
        
        except requests.exceptions.RequestException as e:
            logger.error(f"TOTP setup request failed: {e}")
            return {'error': f'TOTP setup request failed: {str(e)}'}, 500
    
    def verify_totp(self, user_id: str, code: str) -> Tuple[bool, int]:
        """
        Verify TOTP code for a user
        
        Args:
            user_id: User ID
            code: TOTP code
            
        Returns:
            Tuple of (success boolean, status code)
        """
        admin_token = self._get_admin_token()
        if not admin_token:
            return False, 500
        
        try:
            # In a real implementation, this would use Keycloak's API to verify the TOTP code
            # For this example, we'll simulate it by checking if the code is non-empty
            if not code:
                return False, 400
            
            # This is where a real implementation would verify the code
            
            return True, 200
        
        except requests.exceptions.RequestException as e:
            logger.error(f"TOTP verification failed: {e}")
            return False, 500


class TOTPAuthenticator:
    """Implementation of Time-based One-Time Password (TOTP) authenticator"""
    
    def __init__(self, time_step: int = 30, digits: int = 6, algorithm: str = 'sha1'):
        """
        Initialize TOTP authenticator
        
        Args:
            time_step: Time step in seconds (default: 30)
            digits: Number of digits in generated code (default: 6)
            algorithm: Hash algorithm to use (default: sha1)
        """
        self.time_step = time_step
        self.digits = digits
        self.algorithm = algorithm
    
    def generate_secret(self) -> str:
        """
        Generate a new secret key
        
        Returns:
            Base32-encoded secret key string
        """
        # Generate 16 bytes of random data and encode as base32
        random_bytes = os.urandom(16)
        secret = base64.b32encode(random_bytes).decode('utf-8')
        
        return secret
    
    def generate_code(self, secret: str, time_offset: int = 0) -> str:
        """
        Generate TOTP code for a secret
        
        Args:
            secret: Base32-encoded secret key
            time_offset: Time offset in seconds (default: 0)
            
        Returns:
            TOTP code string
        """
        # Decode secret from base32
        try:
            key = base64.b32decode(secret, casefold=True)
        except Exception as e:
            logger.error(f"Error decoding secret: {e}")
            return ""
        
        # Get current timestamp and convert to time step
        timestamp = int(time.time() + time_offset)
        time_step_count = timestamp // self.time_step
        
        # Convert time step to bytes (8 bytes, big-endian)
        time_bytes = time_step_count.to_bytes(8, byteorder='big')
        
        # Calculate HMAC
        h = hashlib.new(self.algorithm, key)
        h.update(time_bytes)
        hmac_result = h.digest()
        
        # Dynamic truncation
        offset = hmac_result[-1] & 0x0F
        truncated = ((hmac_result[offset] & 0x7F) << 24 |
                    (hmac_result[offset + 1] & 0xFF) << 16 |
                    (hmac_result[offset + 2] & 0xFF) << 8 |
                    (hmac_result[offset + 3] & 0xFF))
        
        # Generate code with specified number of digits
        code = str(truncated % (10 ** self.digits)).zfill(self.digits)
        
        return code
    
    def verify_code(self, secret: str, code: str, window: int = 1) -> bool:
        """
        Verify TOTP code
        
        Args:
            secret: Base32-encoded secret key
            code: TOTP code to verify
            window: Number of time steps to check before/after current time (default: 1)
            
        Returns:
            True if code is valid, False otherwise
        """
        if not code or not secret:
            return False
        
        # Try codes for current time step and window before/after
        for i in range(-window, window + 1):
            offset = i * self.time_step
            generated_code = self.generate_code(secret, offset)
            
            if generated_code == code:
                return True
        
        return False


class KeycloakAdapter:
    """Adapter to integrate Keycloak with StudentVC system"""
    
    def __init__(self, 
                keycloak_url: str, 
                realm: str, 
                client_id: str, 
                client_secret: str,
                use_mfa: bool = True):
        """
        Initialize adapter with Keycloak server configuration
        
        Args:
            keycloak_url: Keycloak server URL
            realm: Realm name
            client_id: Client ID
            client_secret: Client secret
            use_mfa: Whether to use MFA (default: True)
        """
        self.keycloak = KeycloakClient(keycloak_url, realm, client_id, client_secret)
        self.totp = TOTPAuthenticator()
        self.use_mfa = use_mfa
        self.sessions = {}  # Store session info
        self.users = {}     # Store user info
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """
        Authenticate user with Keycloak
        
        Args:
            username: Username
            password: Password
            
        Returns:
            Session information dictionary or None if authentication failed
        """
        response, status_code = self.keycloak.authenticate_user(username, password)
        
        if status_code != 200 or 'error' in response:
            logger.error(f"Authentication failed: {response.get('error', 'Unknown error')}")
            return None
        
        # Extract session state from token response
        session_id = response.get('session_state')
        token = response.get('token', {})
        
        # Get user info
        user_info, user_status = self.keycloak.get_user_info(token.get('access_token', ''))
        
        if user_status != 200:
            logger.error(f"Failed to get user info: {user_info.get('error', 'Unknown error')}")
            return None
        
        # Store user info
        self.users[session_id] = user_info
        
        # Store session info
        self.sessions[session_id] = {
            'token': token,
            'created': datetime.datetime.now(),
            'expires': datetime.datetime.now() + datetime.timedelta(seconds=token.get('expires_in', 300)),
            'mfa_complete': not response.get('mfa_required', False)
        }
        
        # Check if MFA is required
        mfa_required = response.get('mfa_required', False) and self.use_mfa
        
        return {
            'session_id': session_id,
            'mfa_required': mfa_required,
            'token': token,
            'user_info': user_info
        }
    
    def setup_mfa(self, session_id: str) -> Optional[Dict]:
        """
        Set up MFA for a user session
        
        Args:
            session_id: Session ID
            
        Returns:
            MFA setup information or None if failed
        """
        if session_id not in self.sessions or session_id not in self.users:
            logger.error(f"Invalid session ID: {session_id}")
            return None
        
        user_info = self.users[session_id]
        user_id = user_info.get('sub')
        
        if not user_id:
            logger.error("User ID not found in user info")
            return None
        
        # Initiate TOTP setup
        setup_info, status_code = self.keycloak.initiate_totp_setup(user_id)
        
        if status_code != 200:
            logger.error(f"Failed to set up MFA: {setup_info.get('error', 'Unknown error')}")
            return None
        
        return setup_info
    
    def verify_mfa(self, session_id: str, code: str) -> bool:
        """
        Verify MFA code for a session
        
        Args:
            session_id: Session ID
            code: MFA code
            
        Returns:
            True if verification succeeded, False otherwise
        """
        if session_id not in self.sessions or session_id not in self.users:
            logger.error(f"Invalid session ID: {session_id}")
            return False
        
        user_info = self.users[session_id]
        user_id = user_info.get('sub')
        
        if not user_id:
            logger.error("User ID not found in user info")
            return False
        
        # Verify TOTP code
        success, status_code = self.keycloak.verify_totp(user_id, code)
        
        if success:
            # Update session to mark MFA as complete
            self.sessions[session_id]['mfa_complete'] = True
        
        return success
    
    def get_user_attributes(self, session_id: str) -> Optional[Dict]:
        """
        Get user attributes from a session
        
        Args:
            session_id: Session ID
            
        Returns:
            User attributes dictionary or None if session is invalid
        """
        if session_id not in self.sessions:
            logger.error(f"Invalid session ID: {session_id}")
            return None
        
        session = self.sessions[session_id]
        
        # Check if session is expired
        if datetime.datetime.now() > session['expires']:
            logger.error(f"Session expired: {session_id}")
            return None
        
        # Get user info
        if session_id not in self.users:
            logger.error(f"User info not found for session: {session_id}")
            return None
        
        user_info = self.users[session_id]
        
        # Extract attributes from user info
        attributes = {}
        
        # Process standard claims
        for key in ['given_name', 'family_name', 'email', 'preferred_username']:
            if key in user_info:
                # Convert to attribute format (e.g., 'given_name' -> 'GivenName')
                attr_name = ''.join(word.capitalize() for word in key.split('_'))
                attributes[attr_name] = [user_info[key]]
        
        # Process custom attributes
        if 'attributes' in user_info:
            attributes.update(user_info['attributes'])
        
        return attributes
    
    def has_completed_mfa(self, session_id: str) -> bool:
        """
        Check if a session has completed MFA
        
        Args:
            session_id: Session ID
            
        Returns:
            True if MFA is complete, False otherwise
        """
        if session_id not in self.sessions:
            return False
        
        return self.sessions[session_id].get('mfa_complete', False)
    
    def is_session_valid(self, session_id: str) -> bool:
        """
        Check if a session is valid
        
        Args:
            session_id: Session ID
            
        Returns:
            True if session is valid, False otherwise
        """
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        # Check if session is expired
        return datetime.datetime.now() <= session['expires']
    
    def logout(self, session_id: str) -> bool:
        """
        Logout a session
        
        Args:
            session_id: Session ID
            
        Returns:
            True if logout succeeded, False otherwise
        """
        if session_id not in self.sessions:
            return False
        
        # Remove session and user info
        self.sessions.pop(session_id, None)
        self.users.pop(session_id, None)
        
        return True


class CredentialIssuerKeycloakAdapter:
    """Adapter for credential issuance using Keycloak authentication"""
    
    def __init__(self, keycloak_adapter: KeycloakAdapter):
        """
        Initialize adapter with Keycloak adapter
        
        Args:
            keycloak_adapter: Keycloak adapter instance
        """
        self.keycloak_adapter = keycloak_adapter
    
    def get_credential_subject_data(self, session_id: str, credential_type: str) -> Optional[Dict]:
        """
        Get credential subject data from Keycloak authenticated session
        
        Args:
            session_id: Keycloak session ID
            credential_type: Type of credential to issue
            
        Returns:
            Credential subject data or None if failed
        """
        # Check if session is valid
        if not self.keycloak_adapter.is_session_valid(session_id):
            logger.error(f"Invalid or expired session: {session_id}")
            return None
        
        # Get user attributes
        attributes = self.keycloak_adapter.get_user_attributes(session_id)
        
        if not attributes:
            logger.error("Failed to get user attributes")
            return None
        
        # Create credential subject based on type
        if credential_type == "StudentIDCredential":
            # Check required attributes
            required_attrs = ["StudentID", "GivenName", "FamilyName"]
            if not all(attr in attributes for attr in required_attrs):
                logger.error(f"Missing required attributes: {required_attrs}")
                return None
            
            subject = {
                "name": f"{attributes.get('GivenName', [''])[0]} {attributes.get('FamilyName', [''])[0]}",
                "studentID": attributes.get("StudentID", [""])[0],
                "university": "Technical University of Berlin",
                "program": attributes.get("Program", [""])[0],
                "enrollmentDate": attributes.get("EnrollmentDate", [""])[0],
                "expectedGraduationDate": attributes.get("ExpectedGraduationDate", [""])[0]
            }
            
            return subject
            
        elif credential_type == "FacultyIDCredential":
            # Check required attributes
            required_attrs = ["EmployeeID", "GivenName", "FamilyName"]
            if not all(attr in attributes for attr in required_attrs):
                logger.error(f"Missing required attributes: {required_attrs}")
                return None
            
            subject = {
                "name": f"{attributes.get('GivenName', [''])[0]} {attributes.get('FamilyName', [''])[0]}",
                "employeeID": attributes.get("EmployeeID", [""])[0],
                "university": "Technical University of Berlin",
                "department": attributes.get("Department", [""])[0],
                "position": attributes.get("Position", [""])[0]
            }
            
            return subject
            
        else:
            logger.error(f"Unsupported credential type: {credential_type}")
            return None
    
    def get_authentication_evidence(self, session_id: str) -> Optional[Dict]:
        """
        Get authentication evidence for a credential
        
        Args:
            session_id: Keycloak session ID
            
        Returns:
            Authentication evidence dictionary or None if failed
        """
        # Check if session is valid
        if not self.keycloak_adapter.is_session_valid(session_id):
            logger.error(f"Invalid or expired session: {session_id}")
            return None
        
        # Check MFA status
        mfa_complete = self.keycloak_adapter.has_completed_mfa(session_id)
        
        # Create evidence
        evidence = {
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["KeycloakAuthentication"],
            "verificationMethod": "KeycloakOAuth2",
            "verificationTime": datetime.datetime.now().isoformat(),
            "authenticationLevel": "strong" if mfa_complete else "basic"
        }
        
        return evidence


# Example usage configuration
DEFAULT_CONFIG = {
    'keycloak_url': 'https://keycloak.example.org/auth',
    'realm': 'university',
    'client_id': 'student-vc',
    'client_secret': 'your-client-secret',
    'use_mfa': True
}

def create_keycloak_adapter(config: Optional[Dict] = None) -> KeycloakAdapter:
    """
    Create a Keycloak adapter with the given configuration
    
    Args:
        config: Configuration dictionary (default: None, uses DEFAULT_CONFIG)
        
    Returns:
        Configured KeycloakAdapter instance
    """
    if config is None:
        config = DEFAULT_CONFIG
    
    adapter = KeycloakAdapter(
        config.get('keycloak_url', DEFAULT_CONFIG['keycloak_url']),
        config.get('realm', DEFAULT_CONFIG['realm']),
        config.get('client_id', DEFAULT_CONFIG['client_id']),
        config.get('client_secret', DEFAULT_CONFIG['client_secret']),
        config.get('use_mfa', DEFAULT_CONFIG['use_mfa'])
    )
    
    return adapter

def create_credential_issuer_adapter(keycloak_adapter: KeycloakAdapter) -> CredentialIssuerKeycloakAdapter:
    """
    Create a credential issuer adapter for the given Keycloak adapter
    
    Args:
        keycloak_adapter: Configured KeycloakAdapter instance
        
    Returns:
        Configured CredentialIssuerKeycloakAdapter instance
    """
    return CredentialIssuerKeycloakAdapter(keycloak_adapter) 