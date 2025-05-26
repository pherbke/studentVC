"""
Tests for X.509 certificate integration in StudentVC

These tests validate the functionality of X.509 certificate loading,
trust chain verification, and DID binding.
"""

import os
import pytest
from datetime import datetime, timedelta
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Add the parent directory to the path so we can import the modules
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.x509.certificate import load_certificate, get_certificate_info, get_certificate_thumbprint
from src.x509.did_binding import create_did_web_from_certificate, create_did_key_from_certificate
from src.x509.trust import verify_certificate_chain
from src.x509.manager import X509Manager


class TestX509Integration:
    """Test suite for X.509 certificate integration."""

    @pytest.fixture
    def test_cert_path(self):
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
        cert_path = os.path.join(temp_dir, "test_cert.pem")
        
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        yield cert_path
        
        # Cleanup
        os.remove(cert_path)
    
    def test_load_certificate(self, test_cert_path):
        """Test loading a certificate from a file."""
        cert = load_certificate(test_cert_path)
        assert cert is not None
        assert isinstance(cert, x509.Certificate)
    
    def test_get_certificate_info(self, test_cert_path):
        """Test extracting information from a certificate."""
        cert = load_certificate(test_cert_path)
        info = get_certificate_info(cert)
        
        assert info is not None
        assert info["subject"]["common_name"] == "test.example.edu"
        assert info["subject"]["organization"] == "Test University"
        assert info["issuer"]["common_name"] == "test.example.edu"  # Self-signed
        assert "thumbprint" in info
    
    def test_get_certificate_thumbprint(self, test_cert_path):
        """Test generating a certificate thumbprint."""
        cert = load_certificate(test_cert_path)
        thumbprint = get_certificate_thumbprint(cert)
        
        assert thumbprint is not None
        assert isinstance(thumbprint, str)
        assert len(thumbprint) == 64  # SHA-256 hexadecimal (32 bytes = 64 hex chars)
    
    def test_create_did_web(self, test_cert_path):
        """Test creating a did:web identifier from a certificate."""
        cert = load_certificate(test_cert_path)
        did = create_did_web_from_certificate(cert, "example.edu")
        
        assert did is not None
        assert did.startswith("did:web:")
        assert "test.example.edu" in did
    
    def test_create_did_key(self, test_cert_path):
        """Test creating a did:key identifier from a certificate."""
        cert = load_certificate(test_cert_path)
        did = create_did_key_from_certificate(cert)
        
        assert did is not None
        assert did.startswith("did:key:z")
    
    def test_x509_manager(self, test_cert_path):
        """Test the X509Manager class."""
        manager = X509Manager()
        cert = manager.load_certificate(test_cert_path)
        
        # Test certificate validity
        is_valid, reason = manager.is_certificate_valid(cert)
        assert is_valid
        
        # Test DID creation
        did_web = manager.create_did_from_certificate(cert, did_method="web", domain="example.edu")
        assert did_web.startswith("did:web:")
        
        did_key = manager.create_did_from_certificate(cert, did_method="key")
        assert did_key.startswith("did:key:")
        
        # Test certificate metadata
        metadata = manager.create_certificate_metadata(cert, did_web, include_pem=False)
        assert metadata["did"] == did_web
        assert "certificate" in metadata
        assert "subject" in metadata["certificate"]


if __name__ == "__main__":
    pytest.main(["-v", __file__]) 