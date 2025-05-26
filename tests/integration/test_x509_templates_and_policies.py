#!/usr/bin/env python3
"""
Test X.509 Certificate Templates and Path Validation Policies

This test suite validates the implementation of X.509 certificate templates
and path validation policies in the StudentVC system, focusing on educational
certificate profiles, constraints, and policies.

Author: StudentVC Team
Date: April 5, 2025
"""

import unittest
import json
import os
import sys
import datetime
import uuid
from unittest.mock import patch, MagicMock

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

class MockX509CertificateManager:
    """
    Mock implementation of the X.509 certificate manager
    """
    
    def __init__(self):
        """Initialize certificate templates and policy constraints"""
        # Define certificate templates
        self.templates = {
            "university_root_ca": {
                "subject_fields": ["CN", "O", "C"],
                "validity_period": 3650,  # 10 years
                "key_usage": ["keyCertSign", "cRLSign"],
                "basic_constraints": {
                    "ca": True,
                    "path_length": 2
                },
                "key_size": 4096,
                "signature_algorithm": "sha384WithRSAEncryption"
            },
            "university_intermediate_ca": {
                "subject_fields": ["CN", "O", "OU", "C"],
                "validity_period": 1825,  # 5 years
                "key_usage": ["keyCertSign", "cRLSign"],
                "basic_constraints": {
                    "ca": True,
                    "path_length": 1
                },
                "name_constraints": {
                    "permitted_dns": [".edu", ".ac.uk", ".edu.de"]
                },
                "key_size": 3072,
                "signature_algorithm": "sha256WithRSAEncryption"
            },
            "university_issuing_ca": {
                "subject_fields": ["CN", "O", "OU", "L", "C"],
                "validity_period": 1095,  # 3 years
                "key_usage": ["keyCertSign", "cRLSign"],
                "basic_constraints": {
                    "ca": True,
                    "path_length": 0
                },
                "certificate_policies": [
                    "2.16.840.1.114545.1.2.1"  # Example OID for academic credential issuance
                ],
                "crl_distribution_points": ["http://{DOMAIN}/crl/issuing.crl"],
                "key_size": 3072,
                "signature_algorithm": "sha256WithRSAEncryption"
            },
            "student_certificate": {
                "subject_fields": ["CN", "O", "OU", "L", "C", "E"],
                "validity_period": 365,  # 1 year
                "key_usage": ["digitalSignature", "keyEncipherment"],
                "extended_key_usage": ["clientAuth", "emailProtection"],
                "subject_alt_name_types": ["email", "did"],
                "certificate_policies": [
                    "2.16.840.1.114545.1.2.2"  # Example OID for student certificates
                ],
                "crl_distribution_points": ["http://{DOMAIN}/crl/students.crl"],
                "ocsp_responders": ["http://ocsp.{DOMAIN}/"],
                "key_size": 2048,
                "signature_algorithm": "sha256WithRSAEncryption"
            },
            "faculty_certificate": {
                "subject_fields": ["CN", "O", "OU", "L", "C", "E"],
                "validity_period": 730,  # 2 years
                "key_usage": ["digitalSignature", "keyEncipherment", "keyAgreement"],
                "extended_key_usage": ["clientAuth", "emailProtection", "serverAuth"],
                "subject_alt_name_types": ["email", "did", "dns"],
                "certificate_policies": [
                    "2.16.840.1.114545.1.2.3"  # Example OID for faculty certificates
                ],
                "crl_distribution_points": ["http://{DOMAIN}/crl/faculty.crl"],
                "ocsp_responders": ["http://ocsp.{DOMAIN}/"],
                "key_size": 2048,
                "signature_algorithm": "sha256WithRSAEncryption"
            }
        }
        
        # Define validation policies
        self.validation_policies = {
            "standard": {
                "require_complete_chain": True,
                "check_revocation": True,
                "max_chain_length": 4,
                "require_policy_match": False,
                "require_critical_extensions_understood": True,
                "allowed_signature_algorithms": [
                    "sha256WithRSAEncryption",
                    "sha384WithRSAEncryption",
                    "sha512WithRSAEncryption",
                    "ecdsa-with-SHA256",
                    "ecdsa-with-SHA384"
                ]
            },
            "strict": {
                "require_complete_chain": True,
                "check_revocation": True,
                "max_chain_length": 4,
                "require_policy_match": True,
                "require_critical_extensions_understood": True,
                "allowed_signature_algorithms": [
                    "sha384WithRSAEncryption",
                    "sha512WithRSAEncryption",
                    "ecdsa-with-SHA384"
                ],
                "trust_anchors": ["CN=StudentVC Root CA"],
                "require_dns_name_match": True,
                "require_did_match": True,
                "max_validity_period": 365,  # maximum validity period in days
                "enforce_key_usage": True
            },
            "credential_issuance": {
                "require_complete_chain": True,
                "check_revocation": True,
                "max_chain_length": 4,
                "require_policy_match": True,
                "require_critical_extensions_understood": True,
                "allowed_signature_algorithms": [
                    "sha256WithRSAEncryption",
                    "sha384WithRSAEncryption",
                    "sha512WithRSAEncryption"
                ],
                "trust_anchors": ["CN=StudentVC Root CA"],
                "require_basic_constraints_ca": True,
                "allowed_policies": [
                    "2.16.840.1.114545.1.2.1",  # Academic credential issuance
                    "2.16.840.1.114545.1.2.2",  # Student certificates
                    "2.16.840.1.114545.1.2.3"   # Faculty certificates
                ]
            }
        }
    
    def get_template(self, template_name):
        """Get a certificate template by name"""
        if template_name not in self.templates:
            raise ValueError(f"Certificate template '{template_name}' not found")
        return self.templates[template_name]
    
    def get_validation_policy(self, policy_name):
        """Get a validation policy by name"""
        if policy_name not in self.validation_policies:
            raise ValueError(f"Validation policy '{policy_name}' not found")
        return self.validation_policies[policy_name]
    
    def create_certificate_from_template(self, template_name, subject_dn, issuer_dn, 
                                        subject_public_key, issuer_private_key,
                                        serial_number=None, not_before=None, 
                                        not_after=None, extensions=None):
        """
        Create a certificate using a template
        
        Args:
            template_name: Name of the template to use
            subject_dn: Subject distinguished name
            issuer_dn: Issuer distinguished name
            subject_public_key: Subject's public key
            issuer_private_key: Issuer's private key for signing
            serial_number: Optional serial number (generated if None)
            not_before: Optional validity start date (now if None)
            not_after: Optional validity end date (calculated from template if None)
            extensions: Optional additional extensions
            
        Returns:
            A dictionary representing the certificate
        """
        template = self.get_template(template_name)
        
        # Generate serial number if not provided
        if serial_number is None:
            serial_number = str(uuid.uuid4().int)
        
        # Set validity period
        if not_before is None:
            not_before = datetime.datetime.now()
        
        if not_after is None:
            not_after = not_before + datetime.timedelta(days=template["validity_period"])
        
        # Create basic certificate structure
        certificate = {
            "serialNumber": serial_number,
            "subject": subject_dn,
            "issuer": issuer_dn,
            "notBefore": not_before.isoformat(),
            "notAfter": not_after.isoformat(),
            "template": template_name,
            "subjectPublicKeyInfo": {
                "algorithm": "RSA",
                "keySize": template["key_size"],
                "publicKey": subject_public_key
            },
            "signatureAlgorithm": template["signature_algorithm"],
            "extensions": []
        }
        
        # Add standard extensions from template
        if "key_usage" in template:
            certificate["extensions"].append({
                "oid": "2.5.29.15",  # Key Usage
                "critical": True,
                "value": template["key_usage"]
            })
        
        if "extended_key_usage" in template:
            certificate["extensions"].append({
                "oid": "2.5.29.37",  # Extended Key Usage
                "critical": False,
                "value": template["extended_key_usage"]
            })
        
        if "basic_constraints" in template:
            certificate["extensions"].append({
                "oid": "2.5.29.19",  # Basic Constraints
                "critical": True,
                "value": template["basic_constraints"]
            })
        
        if "certificate_policies" in template:
            certificate["extensions"].append({
                "oid": "2.5.29.32",  # Certificate Policies
                "critical": False,
                "value": template["certificate_policies"]
            })
        
        if "crl_distribution_points" in template:
            certificate["extensions"].append({
                "oid": "2.5.29.31",  # CRL Distribution Points
                "critical": False,
                "value": [point.replace("{DOMAIN}", subject_dn.split("O=")[1].split(",")[0]) 
                          for point in template["crl_distribution_points"]]
            })
        
        # Add custom extensions if provided
        if extensions:
            for extension in extensions:
                # Check if extension already exists
                existing = [ext for ext in certificate["extensions"] if ext["oid"] == extension["oid"]]
                if existing:
                    # Replace existing extension
                    for ext in certificate["extensions"]:
                        if ext["oid"] == extension["oid"]:
                            ext["value"] = extension["value"]
                            ext["critical"] = extension.get("critical", ext["critical"])
                else:
                    # Add new extension
                    certificate["extensions"].append(extension)
        
        # In a real implementation, we would sign the certificate here using the issuer's private key
        certificate["signature"] = "MOCK_SIGNATURE"
        
        return certificate
    
    def validate_certificate_chain(self, certificate_chain, policy_name="standard"):
        """
        Validate a certificate chain against a policy
        
        Args:
            certificate_chain: List of certificates (root CA first)
            policy_name: Name of the validation policy to use
            
        Returns:
            (is_valid, reason) tuple
        """
        policy = self.get_validation_policy(policy_name)
        
        # Check chain length
        if len(certificate_chain) < 2:
            return False, "Chain too short"
        
        if len(certificate_chain) > policy["max_chain_length"]:
            return False, f"Chain too long (max {policy['max_chain_length']})"
        
        # Check if the root CA is in the trust anchors (if policy specifies trust anchors)
        if "trust_anchors" in policy:
            root_ca = certificate_chain[0]
            if root_ca["subject"] not in policy["trust_anchors"]:
                return False, f"Root CA '{root_ca['subject']}' not in trust anchors"
        
        # Verify that the root CA is self-signed
        root_ca = certificate_chain[0]
        if root_ca["subject"] != root_ca["issuer"]:
            return False, "Root CA is not self-signed"
        
        # Check certificate relationships in the chain
        for i in range(1, len(certificate_chain)):
            cert = certificate_chain[i]
            issuer_cert = certificate_chain[i-1]
            
            # Check that the issuer of this certificate matches the subject of the previous certificate
            if cert["issuer"] != issuer_cert["subject"]:
                return False, f"Certificate at position {i} has incorrect issuer"
            
            # Check signature algorithm against allowed list
            if cert["signatureAlgorithm"] not in policy["allowed_signature_algorithms"]:
                return False, f"Certificate at position {i} uses disallowed signature algorithm '{cert['signatureAlgorithm']}'"
            
            # Check validity period
            not_before = datetime.datetime.fromisoformat(cert["notBefore"])
            not_after = datetime.datetime.fromisoformat(cert["notAfter"])
            now = datetime.datetime.now()
            
            if now < not_before:
                return False, f"Certificate at position {i} is not yet valid"
            
            if now > not_after:
                return False, f"Certificate at position {i} has expired"
            
            # Check max validity period
            if "max_validity_period" in policy:
                validity_days = (not_after - not_before).days
                if validity_days > policy["max_validity_period"]:
                    return False, f"Certificate at position {i} exceeds maximum validity period"
            
            # Check basic constraints for CA certificates (except the end-entity certificate)
            if i < len(certificate_chain) - 1:
                bc_ext = next((ext for ext in cert["extensions"] if ext["oid"] == "2.5.29.19"), None)
                if not bc_ext:
                    return False, f"Intermediate certificate at position {i} is missing basic constraints"
                
                if not bc_ext["value"]["ca"]:
                    return False, f"Intermediate certificate at position {i} is not a CA certificate"
                
                # Check path length constraint
                if "path_length" in bc_ext["value"]:
                    path_length = bc_ext["value"]["path_length"]
                    remaining_length = len(certificate_chain) - i - 2  # -2 because we don't count end-entity cert
                    if remaining_length > path_length:
                        return False, f"Certificate at position {i} has path length constraint {path_length}, but {remaining_length} CA certificates follow"
            
            # For credential issuance policy, check if the certificate has the required policy
            if policy_name == "credential_issuance" and i == len(certificate_chain) - 1:
                policy_ext = next((ext for ext in cert["extensions"] if ext["oid"] == "2.5.29.32"), None)
                if not policy_ext:
                    return False, "End-entity certificate is missing certificate policies extension"
                
                # Check if any of the certificate's policies are in the allowed list
                cert_policies = policy_ext["value"]
                allowed_policies = policy["allowed_policies"]
                if not any(p in allowed_policies for p in cert_policies):
                    return False, "End-entity certificate does not have an allowed policy for credential issuance"
        
        # Everything checks out
        return True, "Valid certificate chain"
    
    def check_template_compliance(self, certificate, template_name):
        """
        Check if a certificate complies with a template
        
        Args:
            certificate: The certificate to check
            template_name: The name of the template
            
        Returns:
            (is_compliant, reason) tuple
        """
        template = self.get_template(template_name)
        
        # Check key size
        if certificate["subjectPublicKeyInfo"]["keySize"] < template["key_size"]:
            return False, f"Key size too small (min {template['key_size']})"
        
        # Check signature algorithm
        if certificate["signatureAlgorithm"] != template["signature_algorithm"]:
            return False, f"Signature algorithm does not match template"
        
        # Check validity period
        not_before = datetime.datetime.fromisoformat(certificate["notBefore"])
        not_after = datetime.datetime.fromisoformat(certificate["notAfter"])
        validity_days = (not_after - not_before).days
        
        if validity_days > template["validity_period"]:
            return False, f"Validity period exceeds template maximum"
        
        # Check subject fields
        subject_parts = certificate["subject"].split(",")
        subject_fields = set()
        for part in subject_parts:
            if "=" in part:
                field = part.split("=")[0].strip()
                subject_fields.add(field)
        
        for required_field in template["subject_fields"]:
            if required_field not in subject_fields:
                return False, f"Missing required subject field '{required_field}'"
        
        # Check key usage
        if "key_usage" in template:
            key_usage_ext = next((ext for ext in certificate["extensions"] if ext["oid"] == "2.5.29.15"), None)
            if not key_usage_ext:
                return False, "Missing key usage extension"
            
            template_usages = set(template["key_usage"])
            cert_usages = set(key_usage_ext["value"])
            
            if not template_usages.issubset(cert_usages):
                missing = template_usages - cert_usages
                return False, f"Missing required key usages: {', '.join(missing)}"
        
        # Check extended key usage
        if "extended_key_usage" in template:
            ext_key_usage_ext = next((ext for ext in certificate["extensions"] if ext["oid"] == "2.5.29.37"), None)
            if not ext_key_usage_ext:
                return False, "Missing extended key usage extension"
            
            template_ext_usages = set(template["extended_key_usage"])
            cert_ext_usages = set(ext_key_usage_ext["value"])
            
            if not template_ext_usages.issubset(cert_ext_usages):
                missing = template_ext_usages - cert_ext_usages
                return False, f"Missing required extended key usages: {', '.join(missing)}"
        
        # Check basic constraints
        if "basic_constraints" in template:
            bc_ext = next((ext for ext in certificate["extensions"] if ext["oid"] == "2.5.29.19"), None)
            if not bc_ext:
                return False, "Missing basic constraints extension"
            
            template_bc = template["basic_constraints"]
            cert_bc = bc_ext["value"]
            
            if template_bc["ca"] != cert_bc["ca"]:
                return False, f"Basic constraints CA flag does not match template"
            
            if "path_length" in template_bc:
                if "path_length" not in cert_bc or cert_bc["path_length"] > template_bc["path_length"]:
                    return False, f"Path length constraint does not match template"
        
        # Everything checks out
        return True, "Certificate complies with template"


class TestX509TemplatesAndPolicies(unittest.TestCase):
    """Test X.509 certificate templates and path validation policies"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.cert_manager = MockX509CertificateManager()
        
        # Create a sample certificate chain for testing
        # Generate self-signed root CA certificate
        self.root_ca = self.cert_manager.create_certificate_from_template(
            "university_root_ca",
            "CN=StudentVC Root CA,O=StudentVC Authority,C=DE",
            "CN=StudentVC Root CA,O=StudentVC Authority,C=DE",
            "MOCK_ROOT_CA_PUBLIC_KEY",
            "MOCK_ROOT_CA_PRIVATE_KEY"
        )
        
        # Generate intermediate CA certificate
        self.intermediate_ca = self.cert_manager.create_certificate_from_template(
            "university_intermediate_ca",
            "CN=StudentVC Intermediate CA,O=StudentVC Authority,OU=Certificate Authority,C=DE",
            "CN=StudentVC Root CA,O=StudentVC Authority,C=DE",
            "MOCK_INTERMEDIATE_CA_PUBLIC_KEY",
            "MOCK_ROOT_CA_PRIVATE_KEY"
        )
        
        # Generate TU Berlin issuing CA certificate
        self.tu_berlin_ca = self.cert_manager.create_certificate_from_template(
            "university_issuing_ca",
            "CN=TU Berlin Issuing CA,O=TU Berlin,OU=IT Services,L=Berlin,C=DE",
            "CN=StudentVC Intermediate CA,O=StudentVC Authority,OU=Certificate Authority,C=DE",
            "MOCK_TU_BERLIN_CA_PUBLIC_KEY",
            "MOCK_INTERMEDIATE_CA_PRIVATE_KEY"
        )
        
        # Generate student certificate
        self.student_cert = self.cert_manager.create_certificate_from_template(
            "student_certificate",
            "CN=John Doe,O=TU Berlin,OU=Computer Science,L=Berlin,C=DE,E=john.doe@tu-berlin.de",
            "CN=TU Berlin Issuing CA,O=TU Berlin,OU=IT Services,L=Berlin,C=DE",
            "MOCK_STUDENT_PUBLIC_KEY",
            "MOCK_TU_BERLIN_CA_PRIVATE_KEY",
            extensions=[
                {
                    "oid": "2.5.29.17",  # Subject Alternative Name
                    "critical": False,
                    "value": [
                        "email:john.doe@tu-berlin.de",
                        "did:web:edu:tu.berlin:users:johndoe"
                    ]
                }
            ]
        )
        
        # Generate faculty certificate
        self.faculty_cert = self.cert_manager.create_certificate_from_template(
            "faculty_certificate",
            "CN=Dr. Jane Smith,O=TU Berlin,OU=Faculty of Computer Science,L=Berlin,C=DE,E=jane.smith@tu-berlin.de",
            "CN=TU Berlin Issuing CA,O=TU Berlin,OU=IT Services,L=Berlin,C=DE",
            "MOCK_FACULTY_PUBLIC_KEY",
            "MOCK_TU_BERLIN_CA_PRIVATE_KEY",
            extensions=[
                {
                    "oid": "2.5.29.17",  # Subject Alternative Name
                    "critical": False,
                    "value": [
                        "email:jane.smith@tu-berlin.de",
                        "did:web:edu:tu.berlin:faculty:janesmith",
                        "dns:faculty.cs.tu-berlin.de"
                    ]
                }
            ]
        )
        
        # Create certificate chains
        self.standard_chain = [
            self.root_ca,
            self.intermediate_ca,
            self.tu_berlin_ca,
            self.student_cert
        ]
        
        self.faculty_chain = [
            self.root_ca,
            self.intermediate_ca,
            self.tu_berlin_ca,
            self.faculty_cert
        ]
    
    def test_template_retrieval(self):
        """Test retrieval of certificate templates"""
        # Test retrieving a valid template
        template = self.cert_manager.get_template("student_certificate")
        self.assertIsNotNone(template)
        self.assertEqual(template["validity_period"], 365)
        
        # Test retrieving a non-existent template
        with self.assertRaises(ValueError):
            self.cert_manager.get_template("nonexistent_template")
    
    def test_policy_retrieval(self):
        """Test retrieval of validation policies"""
        # Test retrieving a valid policy
        policy = self.cert_manager.get_validation_policy("standard")
        self.assertIsNotNone(policy)
        self.assertTrue(policy["require_complete_chain"])
        
        # Test retrieving a non-existent policy
        with self.assertRaises(ValueError):
            self.cert_manager.get_validation_policy("nonexistent_policy")
    
    def test_certificate_creation_from_template(self):
        """Test creation of certificates from templates"""
        # Test creating a student certificate
        cert = self.cert_manager.create_certificate_from_template(
            "student_certificate",
            "CN=Test Student,O=TU Berlin,OU=Computer Science,L=Berlin,C=DE,E=test.student@tu-berlin.de",
            "CN=TU Berlin Issuing CA,O=TU Berlin,OU=IT Services,L=Berlin,C=DE",
            "MOCK_STUDENT_PUBLIC_KEY_2",
            "MOCK_TU_BERLIN_CA_PRIVATE_KEY"
        )
        
        self.assertEqual(cert["template"], "student_certificate")
        self.assertEqual(cert["subject"], "CN=Test Student,O=TU Berlin,OU=Computer Science,L=Berlin,C=DE,E=test.student@tu-berlin.de")
        self.assertEqual(cert["issuer"], "CN=TU Berlin Issuing CA,O=TU Berlin,OU=IT Services,L=Berlin,C=DE")
        
        # Check that key usage extension is present and has the correct values
        key_usage_ext = next((ext for ext in cert["extensions"] if ext["oid"] == "2.5.29.15"), None)
        self.assertIsNotNone(key_usage_ext)
        self.assertIn("digitalSignature", key_usage_ext["value"])
        self.assertIn("keyEncipherment", key_usage_ext["value"])
        
        # Check that extended key usage extension is present and has the correct values
        ext_key_usage_ext = next((ext for ext in cert["extensions"] if ext["oid"] == "2.5.29.37"), None)
        self.assertIsNotNone(ext_key_usage_ext)
        self.assertIn("clientAuth", ext_key_usage_ext["value"])
        self.assertIn("emailProtection", ext_key_usage_ext["value"])
        
        # Check CRL distribution points
        crl_dp_ext = next((ext for ext in cert["extensions"] if ext["oid"] == "2.5.29.31"), None)
        self.assertIsNotNone(crl_dp_ext)
        self.assertIn("http://TU Berlin/crl/students.crl", crl_dp_ext["value"])
    
    def test_template_customization(self):
        """Test customizing templates with additional extensions"""
        # Create a certificate with custom extensions
        cert = self.cert_manager.create_certificate_from_template(
            "student_certificate",
            "CN=Custom Student,O=TU Berlin,OU=Computer Science,L=Berlin,C=DE,E=custom.student@tu-berlin.de",
            "CN=TU Berlin Issuing CA,O=TU Berlin,OU=IT Services,L=Berlin,C=DE",
            "MOCK_STUDENT_PUBLIC_KEY_3",
            "MOCK_TU_BERLIN_CA_PRIVATE_KEY",
            extensions=[
                {
                    "oid": "2.5.29.17",  # Subject Alternative Name
                    "critical": False,
                    "value": [
                        "email:custom.student@tu-berlin.de",
                        "did:web:edu:tu.berlin:users:customstudent",
                        "uri:https://profile.tu-berlin.de/custom.student"
                    ]
                },
                {
                    "oid": "2.5.29.37",  # Extended Key Usage (overriding the template)
                    "critical": False,
                    "value": ["clientAuth", "emailProtection", "codeSigning"]
                },
                {
                    "oid": "1.3.6.1.4.1.11129.2.4.2",  # SCT List (CT)
                    "critical": False,
                    "value": "MOCK_SCT_LIST"
                }
            ]
        )
        
        # Check that the subject alternative name extension has the custom values
        san_ext = next((ext for ext in cert["extensions"] if ext["oid"] == "2.5.29.17"), None)
        self.assertIsNotNone(san_ext)
        self.assertIn("email:custom.student@tu-berlin.de", san_ext["value"])
        self.assertIn("did:web:edu:tu.berlin:users:customstudent", san_ext["value"])
        self.assertIn("uri:https://profile.tu-berlin.de/custom.student", san_ext["value"])
        
        # Check that the extended key usage extension has been overridden
        ext_key_usage_ext = next((ext for ext in cert["extensions"] if ext["oid"] == "2.5.29.37"), None)
        self.assertIsNotNone(ext_key_usage_ext)
        self.assertIn("codeSigning", ext_key_usage_ext["value"])
        
        # Check that the custom SCT List extension is present
        sct_ext = next((ext for ext in cert["extensions"] if ext["oid"] == "1.3.6.1.4.1.11129.2.4.2"), None)
        self.assertIsNotNone(sct_ext)
        self.assertEqual(sct_ext["value"], "MOCK_SCT_LIST")
    
    def test_standard_chain_validation(self):
        """Test validation of a standard certificate chain"""
        # Validate the standard chain with the standard policy
        is_valid, reason = self.cert_manager.validate_certificate_chain(self.standard_chain, "standard")
        self.assertTrue(is_valid, reason)
        
        # Validate the standard chain with the strict policy
        is_valid, reason = self.cert_manager.validate_certificate_chain(self.standard_chain, "strict")
        # This might fail because the student_certificate validity is longer than the strict policy allows
        self.assertFalse(is_valid)
        self.assertIn("exceeds maximum validity period", reason)
        
        # Modify the certificate to have a shorter validity period
        shorter_validity_cert = dict(self.student_cert)
        not_before = datetime.datetime.fromisoformat(shorter_validity_cert["notBefore"])
        shorter_validity_cert["notAfter"] = (not_before + datetime.timedelta(days=180)).isoformat()
        
        modified_chain = [
            self.root_ca,
            self.intermediate_ca,
            self.tu_berlin_ca,
            shorter_validity_cert
        ]
        
        # Validate the modified chain with the strict policy
        is_valid, reason = self.cert_manager.validate_certificate_chain(modified_chain, "strict")
        self.assertTrue(is_valid, reason)
    
    def test_credential_issuance_policy(self):
        """Test validation with the credential issuance policy"""
        # Validate the standard chain with the credential issuance policy
        is_valid, reason = self.cert_manager.validate_certificate_chain(self.standard_chain, "credential_issuance")
        self.assertTrue(is_valid, reason)
        
        # Create a certificate without the required policy
        cert_without_policy = dict(self.student_cert)
        cert_without_policy["extensions"] = [
            ext for ext in cert_without_policy["extensions"] if ext["oid"] != "2.5.29.32"
        ]
        
        chain_without_policy = [
            self.root_ca,
            self.intermediate_ca,
            self.tu_berlin_ca,
            cert_without_policy
        ]
        
        # Validate the chain without policy
        is_valid, reason = self.cert_manager.validate_certificate_chain(chain_without_policy, "credential_issuance")
        self.assertFalse(is_valid)
        self.assertIn("missing certificate policies extension", reason)
        
        # Create a certificate with an incorrect policy
        cert_with_wrong_policy = dict(self.student_cert)
        for ext in cert_with_wrong_policy["extensions"]:
            if ext["oid"] == "2.5.29.32":
                ext["value"] = ["1.2.3.4.5.6.7.8"]  # Not in allowed policies
        
        chain_with_wrong_policy = [
            self.root_ca,
            self.intermediate_ca,
            self.tu_berlin_ca,
            cert_with_wrong_policy
        ]
        
        # Validate the chain with wrong policy
        is_valid, reason = self.cert_manager.validate_certificate_chain(chain_with_wrong_policy, "credential_issuance")
        self.assertFalse(is_valid)
        self.assertIn("does not have an allowed policy", reason)
    
    def test_path_length_constraints(self):
        """Test validation of path length constraints"""
        # Create a longer chain that exceeds path length constraints
        extra_intermediate = self.cert_manager.create_certificate_from_template(
            "university_intermediate_ca",
            "CN=StudentVC Extra Intermediate CA,O=StudentVC Authority,OU=Certificate Authority,C=DE",
            "CN=StudentVC Intermediate CA,O=StudentVC Authority,OU=Certificate Authority,C=DE",
            "MOCK_EXTRA_INTERMEDIATE_CA_PUBLIC_KEY",
            "MOCK_INTERMEDIATE_CA_PRIVATE_KEY"
        )
        
        long_chain = [
            self.root_ca,
            self.intermediate_ca,
            extra_intermediate,  # This exceeds the path length constraint of the intermediate CA
            self.tu_berlin_ca,
            self.student_cert
        ]
        
        # Validate the long chain
        is_valid, reason = self.cert_manager.validate_certificate_chain(long_chain, "standard")
        self.assertFalse(is_valid)
        self.assertIn("path length constraint", reason)
    
    def test_template_compliance(self):
        """Test checking certificate compliance with templates"""
        # Check a compliant certificate
        is_compliant, reason = self.cert_manager.check_template_compliance(self.student_cert, "student_certificate")
        self.assertTrue(is_compliant, reason)
        
        # Check a certificate with the wrong template
        is_compliant, reason = self.cert_manager.check_template_compliance(self.student_cert, "faculty_certificate")
        self.assertFalse(is_compliant)
        
        # Create a non-compliant certificate (missing key usage)
        non_compliant_cert = dict(self.student_cert)
        non_compliant_cert["extensions"] = [
            ext for ext in non_compliant_cert["extensions"] if ext["oid"] != "2.5.29.15"
        ]
        
        is_compliant, reason = self.cert_manager.check_template_compliance(non_compliant_cert, "student_certificate")
        self.assertFalse(is_compliant)
        self.assertIn("Missing key usage extension", reason)
        
        # Create a certificate with insufficient key size
        weak_key_cert = dict(self.student_cert)
        weak_key_cert["subjectPublicKeyInfo"]["keySize"] = 1024
        
        is_compliant, reason = self.cert_manager.check_template_compliance(weak_key_cert, "student_certificate")
        self.assertFalse(is_compliant)
        self.assertIn("Key size too small", reason)
    
    def test_chain_with_missing_intermediate(self):
        """Test validation of a chain with a missing intermediate certificate"""
        # Create a chain with a missing intermediate
        incomplete_chain = [
            self.root_ca,
            # intermediate_ca is missing
            self.tu_berlin_ca,
            self.student_cert
        ]
        
        # Validate the incomplete chain
        is_valid, reason = self.cert_manager.validate_certificate_chain(incomplete_chain, "standard")
        self.assertFalse(is_valid)
        self.assertIn("incorrect issuer", reason)
    
    def test_chain_with_different_algorithms(self):
        """Test validation of a chain with different signature algorithms"""
        # Create a chain with a certificate using a different algorithm
        different_algo_cert = dict(self.student_cert)
        different_algo_cert["signatureAlgorithm"] = "md5WithRSAEncryption"  # Weak algorithm
        
        mixed_algo_chain = [
            self.root_ca,
            self.intermediate_ca,
            self.tu_berlin_ca,
            different_algo_cert
        ]
        
        # Validate the mixed algorithm chain
        is_valid, reason = self.cert_manager.validate_certificate_chain(mixed_algo_chain, "standard")
        self.assertFalse(is_valid)
        self.assertIn("disallowed signature algorithm", reason)
    
    def test_expired_certificate(self):
        """Test validation of a chain with an expired certificate"""
        # Create a chain with an expired certificate
        expired_cert = dict(self.student_cert)
        not_before = datetime.datetime.fromisoformat(expired_cert["notBefore"])
        expired_cert["notAfter"] = (not_before + datetime.timedelta(days=-1)).isoformat()
        
        expired_chain = [
            self.root_ca,
            self.intermediate_ca,
            self.tu_berlin_ca,
            expired_cert
        ]
        
        # Validate the expired chain
        is_valid, reason = self.cert_manager.validate_certificate_chain(expired_chain, "standard")
        self.assertFalse(is_valid)
        self.assertIn("has expired", reason)


if __name__ == "__main__":
    unittest.main() 