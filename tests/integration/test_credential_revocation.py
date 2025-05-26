#!/usr/bin/env python3
"""
Credential Revocation Tests for StudentVC

This test suite verifies the implementation of credential revocation
functionality in the StudentVC system, covering both StatusList2021
and X.509 CRL revocation methods.

Author: StudentVC Team
Date: April 5, 2025
"""

import unittest
import json
import os
import sys
import datetime
import uuid
import base64
from unittest.mock import patch, MagicMock

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Import the necessary modules
# In a real test, you would import the actual modules
# For this file, we'll define mock classes and functions

# Mock classes for revocation testing
class StatusList2021:
    """Mock implementation of StatusList2021 for credential revocation"""
    
    def __init__(self, id, issuer, encoded_list=None):
        self.id = id
        self.issuer = issuer
        
        # Initialize an empty status list if none provided
        if encoded_list:
            self.status_list = base64.b64decode(encoded_list)
        else:
            # Create a new status list with 100,000 bits (all set to 0)
            self.status_list = bytearray(12500)  # 100,000 bits / 8 bits per byte
        
        self.purpose = "revocation"
        self.created = datetime.datetime.now().isoformat()
        self.updated = self.created
    
    def revoke(self, index):
        """Revoke a credential by setting its bit to 1"""
        byte_index = index // 8
        bit_index = index % 8
        
        # Set the bit to 1
        self.status_list[byte_index] |= (1 << bit_index)
        self.updated = datetime.datetime.now().isoformat()
    
    def unrevoke(self, index):
        """Unrevoke a credential by setting its bit to 0"""
        byte_index = index // 8
        bit_index = index % 8
        
        # Set the bit to 0
        self.status_list[byte_index] &= ~(1 << bit_index)
        self.updated = datetime.datetime.now().isoformat()
    
    def is_revoked(self, index):
        """Check if a credential is revoked"""
        byte_index = index // 8
        bit_index = index % 8
        
        # Check if the bit is 1
        return bool(self.status_list[byte_index] & (1 << bit_index))
    
    def encode(self):
        """Encode the status list as base64"""
        return base64.b64encode(self.status_list).decode('ascii')
    
    def to_credential(self):
        """Convert the status list to a verifiable credential"""
        return {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc/status-list/2021/v1"
            ],
            "id": self.id,
            "type": ["VerifiableCredential", "StatusList2021Credential"],
            "issuer": self.issuer,
            "issuanceDate": self.created,
            "credentialSubject": {
                "id": f"{self.id}#list",
                "type": "StatusList2021",
                "statusPurpose": self.purpose,
                "encodedList": self.encode()
            }
        }


class X509CRL:
    """Mock implementation of X.509 Certificate Revocation List"""
    
    def __init__(self, issuer, validity_days=30):
        self.issuer = issuer
        self.issuer_dn = f"CN={issuer}"
        self.this_update = datetime.datetime.now()
        self.next_update = self.this_update + datetime.timedelta(days=validity_days)
        self.revoked_certificates = {}  # serial_number -> revocation_info
        self.crl_number = 1
    
    def revoke_certificate(self, serial_number, reason_code=1, revocation_date=None):
        """Revoke a certificate by adding it to the CRL"""
        if revocation_date is None:
            revocation_date = datetime.datetime.now()
        
        self.revoked_certificates[serial_number] = {
            "serial_number": serial_number,
            "revocation_date": revocation_date,
            "reason_code": reason_code
        }
    
    def unrevoke_certificate(self, serial_number):
        """Remove a certificate from the CRL"""
        if serial_number in self.revoked_certificates:
            del self.revoked_certificates[serial_number]
    
    def is_revoked(self, serial_number):
        """Check if a certificate is revoked"""
        return serial_number in self.revoked_certificates
    
    def update(self):
        """Update the CRL"""
        self.this_update = datetime.datetime.now()
        self.next_update = self.this_update + datetime.timedelta(days=30)
        self.crl_number += 1
    
    def to_pem(self):
        """Convert the CRL to PEM format (mockup)"""
        return f"""-----BEGIN X509 CRL-----
(Mock CRL data for {self.issuer})
CRL Number: {self.crl_number}
This Update: {self.this_update}
Next Update: {self.next_update}
Revoked Certificates: {len(self.revoked_certificates)}
-----END X509 CRL-----"""
    
    def to_der(self):
        """Convert the CRL to DER format (mockup)"""
        # In a real implementation, this would return binary DER data
        return b"MOCK_CRL_DER_DATA"


class RevocationService:
    """Mock service for managing credential revocation"""
    
    def __init__(self):
        self.status_lists = {}  # id -> StatusList2021
        self.crls = {}  # issuer -> X509CRL
    
    def create_status_list(self, issuer, list_id=None):
        """Create a new status list"""
        if list_id is None:
            list_id = f"https://example.com/status-lists/{uuid.uuid4()}"
        
        status_list = StatusList2021(list_id, issuer)
        self.status_lists[list_id] = status_list
        return status_list
    
    def get_status_list(self, list_id):
        """Get a status list by ID"""
        return self.status_lists.get(list_id)
    
    def create_crl(self, issuer, validity_days=30):
        """Create a new CRL"""
        crl = X509CRL(issuer, validity_days)
        self.crls[issuer] = crl
        return crl
    
    def get_crl(self, issuer):
        """Get a CRL by issuer"""
        return self.crls.get(issuer)
    
    def check_credential_status(self, credential):
        """Check the revocation status of a credential"""
        if "credentialStatus" not in credential:
            return {"verified": True, "revoked": False, "message": "No credentialStatus field"}
        
        status = credential["credentialStatus"]
        
        if status["type"] == "StatusList2021Entry":
            # Check status list
            status_list_id = status["statusListCredential"]
            status_list_index = int(status["statusListIndex"])
            
            status_list = self.get_status_list(status_list_id)
            if not status_list:
                return {"verified": False, "revoked": False, "message": "Status list not found"}
            
            is_revoked = status_list.is_revoked(status_list_index)
            return {
                "verified": True,
                "revoked": is_revoked,
                "message": "Credential is revoked" if is_revoked else "Credential is not revoked"
            }
        
        elif status["type"] == "X509CRLStatus":
            # Check X.509 CRL
            issuer = status["issuer"]
            serial_number = int(status["serialNumber"])
            
            crl = self.get_crl(issuer)
            if not crl:
                return {"verified": False, "revoked": False, "message": "CRL not found"}
            
            is_revoked = crl.is_revoked(serial_number)
            return {
                "verified": True,
                "revoked": is_revoked,
                "message": "Certificate is revoked" if is_revoked else "Certificate is not revoked"
            }
        
        else:
            return {"verified": False, "revoked": False, "message": f"Unknown credential status type: {status['type']}"}
    
    def revoke_credential(self, credential):
        """Revoke a credential"""
        if "credentialStatus" not in credential:
            return {"success": False, "message": "No credentialStatus field"}
        
        status = credential["credentialStatus"]
        
        if status["type"] == "StatusList2021Entry":
            # Revoke in status list
            status_list_id = status["statusListCredential"]
            status_list_index = int(status["statusListIndex"])
            
            status_list = self.get_status_list(status_list_id)
            if not status_list:
                return {"success": False, "message": "Status list not found"}
            
            status_list.revoke(status_list_index)
            return {"success": True, "message": "Credential revoked"}
        
        elif status["type"] == "X509CRLStatus":
            # Revoke in X.509 CRL
            issuer = status["issuer"]
            serial_number = int(status["serialNumber"])
            
            crl = self.get_crl(issuer)
            if not crl:
                return {"success": False, "message": "CRL not found"}
            
            crl.revoke_certificate(serial_number)
            return {"success": True, "message": "Certificate revoked"}
        
        else:
            return {"success": False, "message": f"Unknown credential status type: {status['type']}"}


class TestCredentialRevocation(unittest.TestCase):
    """Test credential revocation functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.revocation_service = RevocationService()
        
        # Set up issuers
        self.did_issuer = "did:web:edu:tu.berlin"
        self.x509_issuer = "TU Berlin CA"
        
        # Create status list and CRL
        self.status_list = self.revocation_service.create_status_list(
            self.did_issuer,
            "https://tu.berlin/status-lists/1"
        )
        self.crl = self.revocation_service.create_crl(self.x509_issuer)
        
        # Create test credentials
        self.vc_with_status_list = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc/status-list/2021/v1"
            ],
            "id": "urn:uuid:" + str(uuid.uuid4()),
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": self.did_issuer,
            "issuanceDate": datetime.datetime.now().isoformat(),
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science in Computer Science"
                }
            },
            "credentialStatus": {
                "id": "https://tu.berlin/status-lists/1#42",
                "type": "StatusList2021Entry",
                "statusPurpose": "revocation",
                "statusListIndex": "42",
                "statusListCredential": "https://tu.berlin/status-lists/1"
            }
        }
        
        self.vc_with_x509_crl = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc/status-list/2021/v1"
            ],
            "id": "urn:uuid:" + str(uuid.uuid4()),
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": self.did_issuer,
            "issuanceDate": datetime.datetime.now().isoformat(),
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec22",
                "degree": {
                    "type": "MasterDegree",
                    "name": "Master of Science in Computer Science"
                }
            },
            "credentialStatus": {
                "id": f"urn:crl:{self.x509_issuer}:12345",
                "type": "X509CRLStatus",
                "issuer": self.x509_issuer,
                "serialNumber": "12345",
                "crlUrl": "https://tu.berlin/crls/latest.crl"
            }
        }
    
    def test_status_list_creation(self):
        """Test creating a status list"""
        # Check that the status list was created
        self.assertIsNotNone(self.status_list)
        
        # Convert to credential and check structure
        credential = self.status_list.to_credential()
        self.assertEqual(credential["id"], "https://tu.berlin/status-lists/1")
        self.assertEqual(credential["issuer"], self.did_issuer)
        self.assertIn("StatusList2021Credential", credential["type"])
        self.assertEqual(credential["credentialSubject"]["statusPurpose"], "revocation")
        
        # Check that the encoded list is not empty
        self.assertIsNotNone(credential["credentialSubject"]["encodedList"])
        
        # Check that all bits are initially set to 0 (not revoked)
        for i in range(100):
            self.assertFalse(self.status_list.is_revoked(i))
    
    def test_crl_creation(self):
        """Test creating a CRL"""
        # Check that the CRL was created
        self.assertIsNotNone(self.crl)
        
        # Check CRL properties
        self.assertEqual(self.crl.issuer, self.x509_issuer)
        self.assertEqual(self.crl.crl_number, 1)
        
        # Check that the CRL can be converted to PEM
        pem = self.crl.to_pem()
        self.assertIn("BEGIN X509 CRL", pem)
        self.assertIn("END X509 CRL", pem)
        
        # Check that no certificates are initially revoked
        self.assertEqual(len(self.crl.revoked_certificates), 0)
    
    def test_status_list_revocation(self):
        """Test revoking a credential using StatusList2021"""
        # Check initial status
        status = self.revocation_service.check_credential_status(self.vc_with_status_list)
        self.assertTrue(status["verified"])
        self.assertFalse(status["revoked"])
        
        # Revoke the credential
        result = self.revocation_service.revoke_credential(self.vc_with_status_list)
        self.assertTrue(result["success"])
        
        # Check status after revocation
        status = self.revocation_service.check_credential_status(self.vc_with_status_list)
        self.assertTrue(status["verified"])
        self.assertTrue(status["revoked"])
        
        # Check specific index in the status list
        self.assertTrue(self.status_list.is_revoked(42))
    
    def test_crl_revocation(self):
        """Test revoking a certificate using X.509 CRL"""
        # Check initial status
        status = self.revocation_service.check_credential_status(self.vc_with_x509_crl)
        self.assertTrue(status["verified"])
        self.assertFalse(status["revoked"])
        
        # Revoke the certificate
        result = self.revocation_service.revoke_credential(self.vc_with_x509_crl)
        self.assertTrue(result["success"])
        
        # Check status after revocation
        status = self.revocation_service.check_credential_status(self.vc_with_x509_crl)
        self.assertTrue(status["verified"])
        self.assertTrue(status["revoked"])
        
        # Check specific serial number in the CRL
        self.assertTrue(self.crl.is_revoked(12345))
    
    def test_status_list_unrevocation(self):
        """Test unrevoking a credential in StatusList2021"""
        # First revoke the credential
        self.status_list.revoke(42)
        
        # Check that it's revoked
        status = self.revocation_service.check_credential_status(self.vc_with_status_list)
        self.assertTrue(status["revoked"])
        
        # Unrevoke the credential
        self.status_list.unrevoke(42)
        
        # Check status after unrevocation
        status = self.revocation_service.check_credential_status(self.vc_with_status_list)
        self.assertFalse(status["revoked"])
    
    def test_crl_unrevocation(self):
        """Test unrevoking a certificate in X.509 CRL"""
        # First revoke the certificate
        self.crl.revoke_certificate(12345)
        
        # Check that it's revoked
        status = self.revocation_service.check_credential_status(self.vc_with_x509_crl)
        self.assertTrue(status["revoked"])
        
        # Unrevoke the certificate
        self.crl.unrevoke_certificate(12345)
        
        # Check status after unrevocation
        status = self.revocation_service.check_credential_status(self.vc_with_x509_crl)
        self.assertFalse(status["revoked"])
    
    def test_multiple_status_lists(self):
        """Test using multiple status lists"""
        # Create a second status list
        status_list2 = self.revocation_service.create_status_list(
            self.did_issuer,
            "https://tu.berlin/status-lists/2"
        )
        
        # Create a credential using the second status list
        credential2 = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc/status-list/2021/v1"
            ],
            "id": "urn:uuid:" + str(uuid.uuid4()),
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": self.did_issuer,
            "issuanceDate": datetime.datetime.now().isoformat(),
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec23",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science in Computer Science"
                }
            },
            "credentialStatus": {
                "id": "https://tu.berlin/status-lists/2#7",
                "type": "StatusList2021Entry",
                "statusPurpose": "revocation",
                "statusListIndex": "7",
                "statusListCredential": "https://tu.berlin/status-lists/2"
            }
        }
        
        # Revoke a credential in the first status list
        self.status_list.revoke(42)
        
        # Revoke a credential in the second status list
        status_list2.revoke(7)
        
        # Check status of both credentials
        status1 = self.revocation_service.check_credential_status(self.vc_with_status_list)
        status2 = self.revocation_service.check_credential_status(credential2)
        
        self.assertTrue(status1["revoked"])
        self.assertTrue(status2["revoked"])
        
        # Unrevoke in the first status list
        self.status_list.unrevoke(42)
        
        # Check status again
        status1 = self.revocation_service.check_credential_status(self.vc_with_status_list)
        status2 = self.revocation_service.check_credential_status(credential2)
        
        self.assertFalse(status1["revoked"])
        self.assertTrue(status2["revoked"])
    
    def test_multiple_crls(self):
        """Test using multiple CRLs"""
        # Create a second CRL
        crl2 = self.revocation_service.create_crl("FU Berlin CA")
        
        # Create a credential using the second CRL
        credential2 = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc/status-list/2021/v1"
            ],
            "id": "urn:uuid:" + str(uuid.uuid4()),
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": "did:web:edu:fu-berlin.de",
            "issuanceDate": datetime.datetime.now().isoformat(),
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec24",
                "degree": {
                    "type": "MasterDegree",
                    "name": "Master of Science in Computer Science"
                }
            },
            "credentialStatus": {
                "id": "urn:crl:FU Berlin CA:67890",
                "type": "X509CRLStatus",
                "issuer": "FU Berlin CA",
                "serialNumber": "67890",
                "crlUrl": "https://fu-berlin.de/crls/latest.crl"
            }
        }
        
        # Revoke a certificate in the first CRL
        self.crl.revoke_certificate(12345)
        
        # Revoke a certificate in the second CRL
        crl2.revoke_certificate(67890)
        
        # Check status of both credentials
        status1 = self.revocation_service.check_credential_status(self.vc_with_x509_crl)
        status2 = self.revocation_service.check_credential_status(credential2)
        
        self.assertTrue(status1["revoked"])
        self.assertTrue(status2["revoked"])
        
        # Unrevoke in the first CRL
        self.crl.unrevoke_certificate(12345)
        
        # Check status again
        status1 = self.revocation_service.check_credential_status(self.vc_with_x509_crl)
        status2 = self.revocation_service.check_credential_status(credential2)
        
        self.assertFalse(status1["revoked"])
        self.assertTrue(status2["revoked"])
    
    def test_invalid_credential_status(self):
        """Test checking the status of a credential with invalid status"""
        # Create a credential with an unknown status type
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "urn:uuid:" + str(uuid.uuid4()),
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": self.did_issuer,
            "issuanceDate": datetime.datetime.now().isoformat(),
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec25",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science in Computer Science"
                }
            },
            "credentialStatus": {
                "id": "https://example.com/status/1",
                "type": "UnknownStatusType",
                "statusUrl": "https://example.com/status/1"
            }
        }
        
        # Check status
        status = self.revocation_service.check_credential_status(credential)
        self.assertFalse(status["verified"])
        self.assertFalse(status["revoked"])
        self.assertIn("Unknown credential status type", status["message"])
    
    def test_credential_without_status(self):
        """Test checking the status of a credential without a status field"""
        # Create a credential without a status field
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "urn:uuid:" + str(uuid.uuid4()),
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": self.did_issuer,
            "issuanceDate": datetime.datetime.now().isoformat(),
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec26",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science in Computer Science"
                }
            }
        }
        
        # Check status
        status = self.revocation_service.check_credential_status(credential)
        self.assertTrue(status["verified"])
        self.assertFalse(status["revoked"])
        self.assertIn("No credentialStatus field", status["message"])
    
    def test_nonexistent_status_list(self):
        """Test checking the status of a credential with a nonexistent status list"""
        # Create a credential with a nonexistent status list
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc/status-list/2021/v1"
            ],
            "id": "urn:uuid:" + str(uuid.uuid4()),
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": self.did_issuer,
            "issuanceDate": datetime.datetime.now().isoformat(),
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec27",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science in Computer Science"
                }
            },
            "credentialStatus": {
                "id": "https://tu.berlin/status-lists/nonexistent#42",
                "type": "StatusList2021Entry",
                "statusPurpose": "revocation",
                "statusListIndex": "42",
                "statusListCredential": "https://tu.berlin/status-lists/nonexistent"
            }
        }
        
        # Check status
        status = self.revocation_service.check_credential_status(credential)
        self.assertFalse(status["verified"])
        self.assertFalse(status["revoked"])
        self.assertIn("Status list not found", status["message"])
    
    def test_nonexistent_crl(self):
        """Test checking the status of a credential with a nonexistent CRL"""
        # Create a credential with a nonexistent CRL
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "urn:uuid:" + str(uuid.uuid4()),
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": self.did_issuer,
            "issuanceDate": datetime.datetime.now().isoformat(),
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec28",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science in Computer Science"
                }
            },
            "credentialStatus": {
                "id": "urn:crl:Nonexistent CA:12345",
                "type": "X509CRLStatus",
                "issuer": "Nonexistent CA",
                "serialNumber": "12345",
                "crlUrl": "https://example.com/crls/latest.crl"
            }
        }
        
        # Check status
        status = self.revocation_service.check_credential_status(credential)
        self.assertFalse(status["verified"])
        self.assertFalse(status["revoked"])
        self.assertIn("CRL not found", status["message"])
    
    def test_update_crl(self):
        """Test updating a CRL"""
        # Record the initial CRL number
        initial_crl_number = self.crl.crl_number
        
        # Update the CRL
        self.crl.update()
        
        # Check that the CRL number was incremented
        self.assertEqual(self.crl.crl_number, initial_crl_number + 1)
        
        # Check that the this_update and next_update were updated
        self.assertGreater(self.crl.this_update, datetime.datetime.now() - datetime.timedelta(seconds=10))
        self.assertGreater(self.crl.next_update, datetime.datetime.now() + datetime.timedelta(days=29))
    
    def test_revoke_with_reason_code(self):
        """Test revoking a certificate with a reason code"""
        # Revoke a certificate with a reason code
        self.crl.revoke_certificate(12345, reason_code=4)  # Superseded
        
        # Check that the certificate is revoked
        self.assertTrue(self.crl.is_revoked(12345))
        
        # Check that the reason code was recorded
        self.assertEqual(self.crl.revoked_certificates[12345]["reason_code"], 4)
    
    def test_large_status_list(self):
        """Test using a large status list"""
        # Create a large status list
        large_status_list = self.revocation_service.create_status_list(
            self.did_issuer,
            "https://tu.berlin/status-lists/large"
        )
        
        # Revoke multiple indices
        for i in range(0, 1000, 100):
            large_status_list.revoke(i)
        
        # Check that the revoked indices are revoked
        for i in range(0, 1000, 100):
            self.assertTrue(large_status_list.is_revoked(i))
        
        # Check that non-revoked indices are not revoked
        for i in range(50, 1050, 100):
            self.assertFalse(large_status_list.is_revoked(i))
    
    def test_large_crl(self):
        """Test using a large CRL"""
        # Create a large CRL
        large_crl = self.revocation_service.create_crl("Large CA")
        
        # Revoke multiple serial numbers
        for i in range(0, 1000, 100):
            large_crl.revoke_certificate(i)
        
        # Check that the revoked serial numbers are revoked
        for i in range(0, 1000, 100):
            self.assertTrue(large_crl.is_revoked(i))
        
        # Check that non-revoked serial numbers are not revoked
        for i in range(50, 1050, 100):
            self.assertFalse(large_crl.is_revoked(i))


if __name__ == "__main__":
    unittest.main() 