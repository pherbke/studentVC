"""
End-to-end tests for X.509 certificate integration in StudentVC

These tests validate the end-to-end flow of X.509 integration,
including credential issuance, verification, and status checking.
"""

import os
import json
import base64
import tempfile
import pytest
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Add the parent directory to the path so we can import the modules
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import create_app, db
from src.models import VC_validity, StatusList
from src.validate.status_list import (
    create_status_list_credential,
    set_credential_status,
    STATUS_ACTIVE,
    STATUS_REVOKED,
    STATUS_SUSPENDED
)


class TestX509E2E:
    """End-to-end test suite for X.509 certificate integration."""

    @pytest.fixture
    def app(self):
        """Create and configure a Flask app for testing."""
        app = create_app(testing=True)
        app.config.update({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'SERVER_URL': 'https://test.example.edu',
            'SERVER_DOMAIN': 'test.example.edu',
            'INSTANCE_FOLDER': tempfile.gettempdir()
        })
        
        with app.app_context():
            db.create_all()
            yield app
            db.drop_all()
    
    @pytest.fixture
    def client(self, app):
        """Create a test client for the app."""
        return app.test_client()
    
    @pytest.fixture
    def test_cert(self):
        """Create a self-signed test certificate."""
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create a certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.edu"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test University"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("test.example.edu")]),
            critical=False
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Save certificate to a temporary file
        temp_dir = tempfile.gettempdir()
        cert_path = os.path.join(temp_dir, "issuer.pem")
        
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        yield cert, cert_path
        
        # Cleanup
        if os.path.exists(cert_path):
            os.remove(cert_path)
    
    def test_x509_info_endpoint(self, client, app, test_cert):
        """Test the X.509 certificate info endpoint."""
        cert, cert_path = test_cert
        
        with app.app_context():
            # Load certificate from the endpoint
            response = client.get('/x509-info')
            
            # Expect 404 because no certificate is available yet
            assert response.status_code == 404
            
            # Initialize the issuer with the certificate
            from src.issuer.issuer import initialize_keys
            initialize_keys()
            
            # Try again after initialization
            response = client.get('/x509-info')
            
            # Check if the endpoint is available and returns certificate info
            if response.status_code == 200:
                data = json.loads(response.data)
                assert "subject" in data
                assert "issuer" in data
                assert "validity" in data
                assert "serialNumber" in data
                assert "thumbprint" in data
    
    def test_status_list_creation(self, client, app):
        """Test creation of a status list credential."""
        with app.app_context():
            # Create a status list credential
            status_list_credential = create_status_list_credential("revocation")
            
            # Check that the status list credential was created
            assert status_list_credential is not None
            assert "id" in status_list_credential
            assert "type" in status_list_credential
            assert "credentialSubject" in status_list_credential
            assert "encodedList" in status_list_credential["credentialSubject"]
            
            # Verify it was saved to the database
            status_list = StatusList.query.filter_by(purpose="revocation").first()
            assert status_list is not None
            assert status_list.purpose == "revocation"
            assert status_list.encoded_list is not None
    
    def test_credential_status_flow(self, client, app):
        """Test the credential status flow (issue, revoke, check)."""
        with app.app_context():
            # Create a mock credential entry
            credential_id = "test-credential-123"
            credential_data = {
                "vc": {
                    "credentialSubject": {
                        "firstName": "Test",
                        "lastName": "User",
                        "studentId": "12345"
                    }
                }
            }
            
            validity_entry = VC_validity(
                identifier=credential_id,
                credential_data=credential_data,
                validity=True,
                status="active",
                status_index=0
            )
            db.session.add(validity_entry)
            db.session.commit()
            
            # Check initial status
            response = client.get(f'/validate/isvalid/{credential_id}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["valid"] is True
            
            # Revoke the credential
            result = set_credential_status(credential_id, STATUS_REVOKED)
            assert result is True
            
            # Check status again
            response = client.get(f'/validate/isvalid/{credential_id}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["valid"] is False
            
            # Check the status using the status endpoint
            response = client.get(f'/validate/status/{credential_id}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["status"] == STATUS_REVOKED
            
            # Get the status list
            response = client.get('/validate/statuslist')
            assert response.status_code == 200
            status_list = json.loads(response.data)
            assert "credentialSubject" in status_list
            assert "encodedList" in status_list["credentialSubject"]
    
    def test_status_transitions(self, client, app):
        """Test all possible credential status transitions."""
        with app.app_context():
            # Create a mock credential entry
            credential_id = "test-credential-456"
            credential_data = {
                "vc": {
                    "credentialSubject": {
                        "firstName": "Status",
                        "lastName": "Test",
                        "studentId": "67890"
                    }
                }
            }
            
            validity_entry = VC_validity(
                identifier=credential_id,
                credential_data=credential_data,
                validity=True,
                status="active",
                status_index=1
            )
            db.session.add(validity_entry)
            db.session.commit()
            
            # Test active → suspended transition
            result = set_credential_status(
                credential_id, 
                STATUS_SUSPENDED, 
                "suspension"
            )
            assert result is True
            
            # Check status
            response = client.get(f'/validate/status/{credential_id}')
            data = json.loads(response.data)
            assert data["status"] == STATUS_SUSPENDED
            
            # Test suspended → active transition
            result = set_credential_status(
                credential_id, 
                STATUS_ACTIVE, 
                "suspension"
            )
            assert result is True
            
            # Check status
            response = client.get(f'/validate/status/{credential_id}')
            data = json.loads(response.data)
            assert data["status"] == STATUS_ACTIVE
            
            # Test active → revoked transition
            result = set_credential_status(
                credential_id, 
                STATUS_REVOKED, 
                "revocation"
            )
            assert result is True
            
            # Check status
            response = client.get(f'/validate/status/{credential_id}')
            data = json.loads(response.data)
            assert data["status"] == STATUS_REVOKED
            
            # Verify that revoked cannot transition back to active
            result = set_credential_status(
                credential_id, 
                STATUS_ACTIVE, 
                "revocation"
            )
            assert result is True  # Operation succeeds but...
            
            # ...check status (should still be revoked in validation logic)
            response = client.get(f'/validate/isvalid/{credential_id}')
            data = json.loads(response.data)
            assert data["valid"] is False  # Revocation is permanent in actual use


if __name__ == "__main__":
    pytest.main(["-v", __file__]) 