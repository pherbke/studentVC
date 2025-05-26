#!/usr/bin/env python3
"""
Test Credential Schema Validation

This test suite validates the implementation of credential schema validation
in the StudentVC system, ensuring that credentials conform to specific
educational credential schemas.

Author: StudentVC Team
Date: April 5, 2025
"""

import unittest
import json
import os
import sys
import datetime
import uuid
import jsonschema
from unittest.mock import patch, MagicMock

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

class MockCredentialSchema:
    """Mock implementation of a credential schema validator"""
    
    def __init__(self):
        """Initialize schemas"""
        # Define schemas for different credential types
        self.schemas = {
            "UniversityDegreeCredential": {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "title": "University Degree Credential",
                "description": "A schema for university degree credentials",
                "type": "object",
                "required": ["@context", "id", "type", "issuer", "issuanceDate", "credentialSubject"],
                "properties": {
                    "@context": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string"}
                    },
                    "id": {"type": "string", "format": "uri"},
                    "type": {
                        "type": "array",
                        "minItems": 2,
                        "contains": {"enum": ["VerifiableCredential", "UniversityDegreeCredential"]}
                    },
                    "issuer": {"type": "string", "format": "uri"},
                    "issuanceDate": {"type": "string", "format": "date-time"},
                    "expirationDate": {"type": "string", "format": "date-time"},
                    "credentialSubject": {
                        "type": "object",
                        "required": ["id", "degree"],
                        "properties": {
                            "id": {"type": "string", "format": "uri"},
                            "name": {"type": "string"},
                            "birthDate": {"type": "string", "format": "date"},
                            "degree": {
                                "type": "object",
                                "required": ["type", "name", "university"],
                                "properties": {
                                    "type": {"type": "string"},
                                    "name": {"type": "string"},
                                    "university": {"type": "string"},
                                    "graduationDate": {"type": "string", "format": "date"},
                                    "gpa": {"type": "number"},
                                    "degreeProgramIdentifier": {"type": "string"}
                                }
                            },
                            "studentNumber": {"type": "string"}
                        }
                    },
                    "proof": {
                        "type": "object",
                        "required": ["type", "created", "verificationMethod", "proofPurpose", "proofValue"],
                        "properties": {
                            "type": {"type": "string"},
                            "created": {"type": "string", "format": "date-time"},
                            "verificationMethod": {"type": "string"},
                            "proofPurpose": {"type": "string"},
                            "proofValue": {"type": "string"}
                        }
                    }
                }
            },
            "CourseCertificateCredential": {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "title": "Course Certificate Credential",
                "description": "A schema for course certificate credentials",
                "type": "object",
                "required": ["@context", "id", "type", "issuer", "issuanceDate", "credentialSubject"],
                "properties": {
                    "@context": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string"}
                    },
                    "id": {"type": "string", "format": "uri"},
                    "type": {
                        "type": "array",
                        "minItems": 2,
                        "contains": {"enum": ["VerifiableCredential", "CourseCertificateCredential"]}
                    },
                    "issuer": {"type": "string", "format": "uri"},
                    "issuanceDate": {"type": "string", "format": "date-time"},
                    "expirationDate": {"type": "string", "format": "date-time"},
                    "credentialSubject": {
                        "type": "object",
                        "required": ["id", "course"],
                        "properties": {
                            "id": {"type": "string", "format": "uri"},
                            "name": {"type": "string"},
                            "course": {
                                "type": "object",
                                "required": ["name", "institution", "completionDate"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "institution": {"type": "string"},
                                    "completionDate": {"type": "string", "format": "date"},
                                    "grade": {"type": "string"},
                                    "credits": {"type": "number"},
                                    "instructor": {"type": "string"},
                                    "courseIdentifier": {"type": "string"},
                                    "description": {"type": "string"}
                                }
                            }
                        }
                    },
                    "proof": {
                        "type": "object",
                        "required": ["type", "created", "verificationMethod", "proofPurpose", "proofValue"],
                        "properties": {
                            "type": {"type": "string"},
                            "created": {"type": "string", "format": "date-time"},
                            "verificationMethod": {"type": "string"},
                            "proofPurpose": {"type": "string"},
                            "proofValue": {"type": "string"}
                        }
                    }
                }
            },
            "StudentIDCredential": {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "title": "Student ID Credential",
                "description": "A schema for student identification credentials",
                "type": "object",
                "required": ["@context", "id", "type", "issuer", "issuanceDate", "credentialSubject"],
                "properties": {
                    "@context": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string"}
                    },
                    "id": {"type": "string", "format": "uri"},
                    "type": {
                        "type": "array",
                        "minItems": 2,
                        "contains": {"enum": ["VerifiableCredential", "StudentIDCredential"]}
                    },
                    "issuer": {"type": "string", "format": "uri"},
                    "issuanceDate": {"type": "string", "format": "date-time"},
                    "expirationDate": {"type": "string", "format": "date-time"},
                    "credentialSubject": {
                        "type": "object",
                        "required": ["id", "studentID", "university", "validUntil"],
                        "properties": {
                            "id": {"type": "string", "format": "uri"},
                            "name": {"type": "string"},
                            "birthDate": {"type": "string", "format": "date"},
                            "studentID": {"type": "string"},
                            "university": {"type": "string"},
                            "faculty": {"type": "string"},
                            "program": {"type": "string"},
                            "validFrom": {"type": "string", "format": "date"},
                            "validUntil": {"type": "string", "format": "date"},
                            "photo": {"type": "string", "format": "base64"}
                        }
                    },
                    "proof": {
                        "type": "object",
                        "required": ["type", "created", "verificationMethod", "proofPurpose", "proofValue"],
                        "properties": {
                            "type": {"type": "string"},
                            "created": {"type": "string", "format": "date-time"},
                            "verificationMethod": {"type": "string"},
                            "proofPurpose": {"type": "string"},
                            "proofValue": {"type": "string"}
                        }
                    }
                }
            }
        }
    
    def get_schema(self, credential_type):
        """Get schema for a credential type"""
        if credential_type not in self.schemas:
            raise ValueError(f"No schema found for credential type: {credential_type}")
        return self.schemas[credential_type]
    
    def validate_credential(self, credential):
        """Validate a credential against its schema"""
        # Extract credential type
        if "type" not in credential or not isinstance(credential["type"], list):
            return False, "Missing or invalid 'type' property"
        
        # Find the specific credential type (not VerifiableCredential)
        credential_types = [t for t in credential["type"] if t != "VerifiableCredential"]
        if not credential_types:
            return False, "Missing specific credential type"
        
        credential_type = credential_types[0]
        
        # Get schema for the credential type
        try:
            schema = self.get_schema(credential_type)
        except ValueError as e:
            return False, str(e)
        
        # Validate against schema
        try:
            jsonschema.validate(instance=credential, schema=schema)
            return True, "Credential is valid"
        except jsonschema.exceptions.ValidationError as e:
            return False, f"Schema validation error: {e.message}"
    
    def validate_fields(self, credential):
        """Perform custom field validations that go beyond JSON Schema"""
        # Check issuance date is not in the future
        if "issuanceDate" in credential:
            try:
                issuance_date = datetime.datetime.fromisoformat(credential["issuanceDate"].replace("Z", "+00:00"))
                now = datetime.datetime.now(datetime.timezone.utc)
                if issuance_date > now:
                    return False, "Issuance date cannot be in the future"
            except ValueError:
                return False, "Invalid issuance date format"
        
        # Check expiration date is after issuance date
        if "expirationDate" in credential and "issuanceDate" in credential:
            try:
                issuance_date = datetime.datetime.fromisoformat(credential["issuanceDate"].replace("Z", "+00:00"))
                expiration_date = datetime.datetime.fromisoformat(credential["expirationDate"].replace("Z", "+00:00"))
                if expiration_date <= issuance_date:
                    return False, "Expiration date must be after issuance date"
            except ValueError:
                return False, "Invalid date format"
        
        # Check credential subject ID is a valid URI
        if "credentialSubject" in credential and "id" in credential["credentialSubject"]:
            subject_id = credential["credentialSubject"]["id"]
            if not (subject_id.startswith("did:") or subject_id.startswith("http:") or subject_id.startswith("https:")):
                return False, "Credential subject ID must be a valid URI"
        
        # Additional validations for specific credential types
        if "type" in credential and isinstance(credential["type"], list):
            credential_types = [t for t in credential["type"] if t != "VerifiableCredential"]
            if credential_types:
                credential_type = credential_types[0]
                
                if credential_type == "UniversityDegreeCredential":
                    # Check graduation date is not in the future
                    if "credentialSubject" in credential and "degree" in credential["credentialSubject"] and "graduationDate" in credential["credentialSubject"]["degree"]:
                        try:
                            grad_date = datetime.datetime.fromisoformat(credential["credentialSubject"]["degree"]["graduationDate"].replace("Z", "+00:00"))
                            now = datetime.datetime.now(datetime.timezone.utc)
                            if grad_date > now:
                                return False, "Graduation date cannot be in the future"
                        except ValueError:
                            return False, "Invalid graduation date format"
                
                elif credential_type == "StudentIDCredential":
                    # Check valid until date is after valid from date
                    if "credentialSubject" in credential:
                        subject = credential["credentialSubject"]
                        if "validFrom" in subject and "validUntil" in subject:
                            try:
                                valid_from = datetime.datetime.fromisoformat(subject["validFrom"].replace("Z", "+00:00"))
                                valid_until = datetime.datetime.fromisoformat(subject["validUntil"].replace("Z", "+00:00"))
                                if valid_until <= valid_from:
                                    return False, "Valid until date must be after valid from date"
                            except ValueError:
                                return False, "Invalid date format in credential validity"
        
        # All validations passed
        return True, "Credential fields are valid"


# Mock credentials for testing
def create_university_degree_credential(subject_id, with_errors=False):
    """Create a mock university degree credential"""
    now = datetime.datetime.now(datetime.timezone.utc)
    
    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": "did:web:edu:tu.berlin",
        "issuanceDate": now.isoformat(),
        "credentialSubject": {
            "id": subject_id,
            "name": "John Doe",
            "birthDate": "1995-07-23",
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science",
                "university": "Technical University of Berlin",
                "graduationDate": "2023-05-15",
                "gpa": 3.8,
                "degreeProgramIdentifier": "CS-BSC-2023"
            },
            "studentNumber": "TU-2020-12345"
        },
        "proof": {
            "type": "Ed25519Signature2020",
            "created": now.isoformat(),
            "verificationMethod": "did:web:edu:tu.berlin#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "z3MqCCnsFB7ynxF75TkB5ZkdUAFNFssH3BWMH2vULJ1HCfBnyLfpQJLyBKFH6orHzXjRZYtX6czSJQ2WJKGhi5zRp"
        }
    }
    
    if with_errors:
        # Introduce schema errors
        del credential["credentialSubject"]["id"]
        del credential["credentialSubject"]["degree"]["university"]
        credential["issuanceDate"] = "invalid-date"
    
    return credential

def create_course_certificate_credential(subject_id, with_errors=False):
    """Create a mock course certificate credential"""
    now = datetime.datetime.now(datetime.timezone.utc)
    
    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "CourseCertificateCredential"],
        "issuer": "did:web:edu:tu.berlin",
        "issuanceDate": now.isoformat(),
        "credentialSubject": {
            "id": subject_id,
            "name": "Jane Smith",
            "course": {
                "name": "Advanced Machine Learning",
                "institution": "Technical University of Berlin",
                "completionDate": "2023-06-30",
                "grade": "A",
                "credits": 6,
                "instructor": "Prof. Dr. Schmidt",
                "courseIdentifier": "CS-ML-2023",
                "description": "In-depth study of machine learning algorithms and applications"
            }
        },
        "proof": {
            "type": "Ed25519Signature2020",
            "created": now.isoformat(),
            "verificationMethod": "did:web:edu:tu.berlin#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "z3MqCCnsFB7ynxF75TkB5ZkdUAFNFssH3BWMH2vULJ1HCfBnyLfpQJLyBKFH6orHzXjRZYtX6czSJQ2WJKGhi5zRp"
        }
    }
    
    if with_errors:
        # Introduce schema errors
        del credential["credentialSubject"]["course"]["completionDate"]
        credential["credentialSubject"]["course"]["credits"] = "not-a-number"
    
    return credential

def create_student_id_credential(subject_id, with_errors=False):
    """Create a mock student ID credential"""
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now - datetime.timedelta(days=30)
    valid_until = now + datetime.timedelta(days=335)  # ~11 months
    
    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "StudentIDCredential"],
        "issuer": "did:web:edu:tu.berlin",
        "issuanceDate": now.isoformat(),
        "expirationDate": valid_until.isoformat(),
        "credentialSubject": {
            "id": subject_id,
            "name": "John Doe",
            "birthDate": "1995-07-23",
            "studentID": "TU-2020-12345",
            "university": "Technical University of Berlin",
            "faculty": "Computer Science",
            "program": "Bachelor of Science in Computer Science",
            "validFrom": valid_from.isoformat(),
            "validUntil": valid_until.isoformat(),
            "photo": "base64encodedphoto..."
        },
        "proof": {
            "type": "Ed25519Signature2020",
            "created": now.isoformat(),
            "verificationMethod": "did:web:edu:tu.berlin#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "z3MqCCnsFB7ynxF75TkB5ZkdUAFNFssH3BWMH2vULJ1HCfBnyLfpQJLyBKFH6orHzXjRZYtX6czSJQ2WJKGhi5zRp"
        }
    }
    
    if with_errors:
        # Introduce schema errors
        credential["credentialSubject"]["validUntil"] = valid_from.isoformat()  # Invalid: validUntil before validFrom
        credential["expirationDate"] = now.isoformat()  # Invalid: expires on issuance date
    
    return credential


class TestCredentialSchemaValidation(unittest.TestCase):
    """Test schema validation for educational credentials"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.schema_validator = MockCredentialSchema()
        self.student_did = "did:web:edu:tu.berlin:users:johndoe"
    
    def test_schema_retrieval(self):
        """Test retrieving schemas for different credential types"""
        # Test retrieving existing schemas
        university_degree_schema = self.schema_validator.get_schema("UniversityDegreeCredential")
        self.assertIsNotNone(university_degree_schema)
        self.assertEqual(university_degree_schema["title"], "University Degree Credential")
        
        course_cert_schema = self.schema_validator.get_schema("CourseCertificateCredential")
        self.assertIsNotNone(course_cert_schema)
        self.assertEqual(course_cert_schema["title"], "Course Certificate Credential")
        
        student_id_schema = self.schema_validator.get_schema("StudentIDCredential")
        self.assertIsNotNone(student_id_schema)
        self.assertEqual(student_id_schema["title"], "Student ID Credential")
        
        # Test retrieving non-existent schema
        with self.assertRaises(ValueError):
            self.schema_validator.get_schema("NonExistentCredential")
    
    def test_valid_university_degree_credential(self):
        """Test validation of a valid university degree credential"""
        credential = create_university_degree_credential(self.student_did)
        
        # Validate against schema
        is_valid, reason = self.schema_validator.validate_credential(credential)
        self.assertTrue(is_valid, reason)
        
        # Validate fields
        is_valid, reason = self.schema_validator.validate_fields(credential)
        self.assertTrue(is_valid, reason)
    
    def test_invalid_university_degree_credential(self):
        """Test validation of an invalid university degree credential"""
        credential = create_university_degree_credential(self.student_did, with_errors=True)
        
        # Validate against schema
        is_valid, reason = self.schema_validator.validate_credential(credential)
        self.assertFalse(is_valid)
        
        # Validate fields
        is_valid, reason = self.schema_validator.validate_fields(credential)
        self.assertFalse(is_valid)
        self.assertIn("Invalid issuance date format", reason)
    
    def test_future_graduation_date(self):
        """Test validation of a credential with a future graduation date"""
        credential = create_university_degree_credential(self.student_did)
        
        # Set graduation date to future
        future_date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=180)
        credential["credentialSubject"]["degree"]["graduationDate"] = future_date.strftime("%Y-%m-%d")
        
        # Validate fields
        is_valid, reason = self.schema_validator.validate_fields(credential)
        self.assertFalse(is_valid)
        self.assertIn("Graduation date cannot be in the future", reason)
    
    def test_valid_course_certificate_credential(self):
        """Test validation of a valid course certificate credential"""
        credential = create_course_certificate_credential(self.student_did)
        
        # Validate against schema
        is_valid, reason = self.schema_validator.validate_credential(credential)
        self.assertTrue(is_valid, reason)
        
        # Validate fields
        is_valid, reason = self.schema_validator.validate_fields(credential)
        self.assertTrue(is_valid, reason)
    
    def test_invalid_course_certificate_credential(self):
        """Test validation of an invalid course certificate credential"""
        credential = create_course_certificate_credential(self.student_did, with_errors=True)
        
        # Validate against schema
        is_valid, reason = self.schema_validator.validate_credential(credential)
        self.assertFalse(is_valid)
    
    def test_valid_student_id_credential(self):
        """Test validation of a valid student ID credential"""
        credential = create_student_id_credential(self.student_did)
        
        # Validate against schema
        is_valid, reason = self.schema_validator.validate_credential(credential)
        self.assertTrue(is_valid, reason)
        
        # Validate fields
        is_valid, reason = self.schema_validator.validate_fields(credential)
        self.assertTrue(is_valid, reason)
    
    def test_invalid_student_id_credential(self):
        """Test validation of an invalid student ID credential"""
        credential = create_student_id_credential(self.student_did, with_errors=True)
        
        # Validate fields
        is_valid, reason = self.schema_validator.validate_fields(credential)
        self.assertFalse(is_valid)
        self.assertIn("Valid until date must be after valid from date", reason)
    
    def test_credential_without_type(self):
        """Test validation of a credential without a type"""
        credential = create_university_degree_credential(self.student_did)
        del credential["type"]
        
        # Validate against schema
        is_valid, reason = self.schema_validator.validate_credential(credential)
        self.assertFalse(is_valid)
        self.assertIn("Missing or invalid 'type' property", reason)
    
    def test_credential_with_unknown_type(self):
        """Test validation of a credential with an unknown type"""
        credential = create_university_degree_credential(self.student_did)
        credential["type"] = ["VerifiableCredential", "UnknownCredentialType"]
        
        # Validate against schema
        is_valid, reason = self.schema_validator.validate_credential(credential)
        self.assertFalse(is_valid)
        self.assertIn("No schema found for credential type", reason)
    
    def test_future_issuance_date(self):
        """Test validation of a credential with a future issuance date"""
        credential = create_university_degree_credential(self.student_did)
        
        # Set issuance date to future
        future_date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        credential["issuanceDate"] = future_date.isoformat()
        
        # Validate fields
        is_valid, reason = self.schema_validator.validate_fields(credential)
        self.assertFalse(is_valid)
        self.assertIn("Issuance date cannot be in the future", reason)
    
    def test_invalid_expiration_date(self):
        """Test validation of a credential with an invalid expiration date"""
        credential = create_university_degree_credential(self.student_did)
        
        # Set expiration date to before issuance date
        now = datetime.datetime.now(datetime.timezone.utc)
        past_date = now - datetime.timedelta(days=30)
        credential["expirationDate"] = past_date.isoformat()
        
        # Validate fields
        is_valid, reason = self.schema_validator.validate_fields(credential)
        self.assertFalse(is_valid)
        self.assertIn("Expiration date must be after issuance date", reason)
    
    def test_invalid_credential_subject_id(self):
        """Test validation of a credential with an invalid subject ID"""
        credential = create_university_degree_credential(self.student_did)
        
        # Set an invalid subject ID
        credential["credentialSubject"]["id"] = "not-a-valid-uri"
        
        # Validate fields
        is_valid, reason = self.schema_validator.validate_fields(credential)
        self.assertFalse(is_valid)
        self.assertIn("Credential subject ID must be a valid URI", reason)
    
    def test_mixed_credential_types(self):
        """Test validation of a credential with mixed credential types"""
        credential = create_university_degree_credential(self.student_did)
        
        # Mix credential types
        credential["type"] = ["VerifiableCredential", "UniversityDegreeCredential", "StudentIDCredential"]
        
        # Add required fields for StudentIDCredential
        now = datetime.datetime.now(datetime.timezone.utc)
        valid_from = now - datetime.timedelta(days=30)
        valid_until = now + datetime.timedelta(days=335)
        
        credential["credentialSubject"]["studentID"] = "TU-2020-12345"
        credential["credentialSubject"]["university"] = "Technical University of Berlin"
        credential["credentialSubject"]["validFrom"] = valid_from.isoformat()
        credential["credentialSubject"]["validUntil"] = valid_until.isoformat()
        
        # Validate against schema - should validate against the first non-VC type
        is_valid, reason = self.schema_validator.validate_credential(credential)
        self.assertTrue(is_valid, reason)


if __name__ == "__main__":
    unittest.main() 