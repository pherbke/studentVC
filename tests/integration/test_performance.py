#!/usr/bin/env python3
"""
Performance Tests for StudentVC

This test suite measures the performance of critical operations
in the StudentVC system, including certificate validation,
credential operations, and selective disclosure.

Author: StudentVC Team
Date: April 5, 2025
"""

import unittest
import json
import os
import sys
import time
import datetime
import uuid
import base64
import statistics
import psutil
import gc
from unittest.mock import patch, MagicMock

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Mock classes and functions for performance testing

class PerformanceMonitor:
    """Utility class for monitoring performance metrics"""
    
    def __init__(self):
        self.process = psutil.Process(os.getpid())
    
    def start_measurement(self):
        """Start measuring performance metrics"""
        # Clear any cached objects
        gc.collect()
        
        # Record starting metrics
        self.start_time = time.time()
        self.start_memory = self.process.memory_info().rss
    
    def end_measurement(self):
        """End measuring performance metrics and return results"""
        # Record ending metrics
        self.end_time = time.time()
        self.end_memory = self.process.memory_info().rss
        
        # Calculate metrics
        elapsed_time = self.end_time - self.start_time
        memory_used = self.end_memory - self.start_memory
        
        return {
            "elapsed_time": elapsed_time,
            "memory_used": memory_used,
            "memory_used_mb": memory_used / (1024 * 1024)
        }
    
    def measure_function(self, func, *args, **kwargs):
        """Measure the performance of a function call"""
        self.start_measurement()
        result = func(*args, **kwargs)
        metrics = self.end_measurement()
        
        return result, metrics
    
    def measure_function_repeated(self, func, iterations, *args, **kwargs):
        """Measure the performance of repeated function calls"""
        times = []
        memory_usages = []
        
        for _ in range(iterations):
            self.start_measurement()
            result = func(*args, **kwargs)
            metrics = self.end_measurement()
            
            times.append(metrics["elapsed_time"])
            memory_usages.append(metrics["memory_used"])
        
        # Calculate statistics
        stats = {
            "iterations": iterations,
            "total_time": sum(times),
            "avg_time": statistics.mean(times),
            "median_time": statistics.median(times),
            "min_time": min(times),
            "max_time": max(times),
            "stddev_time": statistics.stdev(times) if iterations > 1 else 0,
            "avg_memory_used": statistics.mean(memory_usages),
            "avg_memory_used_mb": statistics.mean(memory_usages) / (1024 * 1024),
            "total_memory_used_mb": sum(memory_usages) / (1024 * 1024)
        }
        
        return result, stats


# Mock implementations of credential operations for testing

def generate_credential(issuer, subject):
    """Generate a mock credential"""
    return {
        "@context": [
            "https://www.w3.org/2018/credentials/v1"
        ],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": issuer,
        "issuanceDate": datetime.datetime.now().isoformat(),
        "credentialSubject": {
            "id": subject,
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science"
            }
        },
        "proof": {
            "type": "Ed25519Signature2020",
            "created": datetime.datetime.now().isoformat(),
            "verificationMethod": f"{issuer}#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "z3MqCCnsFB7ynxF75TkB5ZkdUAFNFssH3BWMH2vULJ1HCfBnyLfpQJLyBKFH6orHzXjRZYtX6czSJQ2WJKGhi5zRp"
        }
    }

def generate_bbs_credential(issuer, subject):
    """Generate a mock BBS+ credential"""
    return {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/bbs/v1"
        ],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": issuer,
        "issuanceDate": datetime.datetime.now().isoformat(),
        "credentialSubject": {
            "id": subject,
            "name": "Max Mustermann",
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science",
                "university": "Technical University of Berlin",
                "graduationDate": "2023-05-15"
            },
            "address": {
                "streetAddress": "123 Main St",
                "postalCode": "10001",
                "city": "Berlin",
                "country": "Germany"
            },
            "email": "max.mustermann@example.com",
            "birthDate": "1995-07-23",
            "studentNumber": "TU-2020-12345"
        },
        "proof": {
            "type": "BbsBlsSignature2020",
            "created": datetime.datetime.now().isoformat(),
            "verificationMethod": f"{issuer}#bbs-key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "kTTbA1xL6P1nKbkpnZ8CJAcHNA7/GcCFdDj1jTgwq8YUkKKyyuwQQKqfoPmlos0rVPzWY/FXykz3w4YzxDmZ35LhWU3zFLxLbF36cZ642DTZ4TCTXqqYeWyoJJkU9EwbJR==+"
        }
    }

def generate_x509_certificate():
    """Generate a mock X.509 certificate"""
    # Create a mock certificate
    serial_number = str(uuid.uuid4().int)
    not_before = datetime.datetime.now()
    not_after = not_before + datetime.timedelta(days=365)
    
    return {
        "serialNumber": serial_number,
        "subject": "CN=John Doe,O=TU Berlin,C=DE",
        "issuer": "CN=StudentVC Root CA",
        "notBefore": not_before.isoformat(),
        "notAfter": not_after.isoformat(),
        "subjectPublicKeyInfo": {
            "algorithm": "RSA",
            "keySize": 2048,
            "publicKey": "MOCK_PUBLIC_KEY"
        },
        "extensions": [{
            "oid": "2.5.29.17",  # Subject Alternative Name
            "critical": False,
            "value": "DID:did:web:edu:tu.berlin:users:johndoe"
        }]
    }

def generate_x509_certificate_chain(length=3):
    """Generate a mock X.509 certificate chain"""
    chain = []
    
    # Generate root CA certificate
    root_ca = {
        "serialNumber": str(uuid.uuid4().int),
        "subject": "CN=StudentVC Root CA",
        "issuer": "CN=StudentVC Root CA",
        "notBefore": datetime.datetime.now().isoformat(),
        "notAfter": (datetime.datetime.now() + datetime.timedelta(days=3650)).isoformat(),
        "subjectPublicKeyInfo": {
            "algorithm": "RSA",
            "keySize": 4096,
            "publicKey": "MOCK_ROOT_CA_PUBLIC_KEY"
        }
    }
    chain.append(root_ca)
    
    # Generate intermediate CA certificates
    for i in range(1, length - 1):
        intermediate_ca = {
            "serialNumber": str(uuid.uuid4().int),
            "subject": f"CN=StudentVC Intermediate CA {i}",
            "issuer": "CN=StudentVC Root CA" if i == 1 else f"CN=StudentVC Intermediate CA {i-1}",
            "notBefore": datetime.datetime.now().isoformat(),
            "notAfter": (datetime.datetime.now() + datetime.timedelta(days=1825)).isoformat(),
            "subjectPublicKeyInfo": {
                "algorithm": "RSA",
                "keySize": 3072,
                "publicKey": f"MOCK_INTERMEDIATE_CA_{i}_PUBLIC_KEY"
            }
        }
        chain.append(intermediate_ca)
    
    # Generate end-entity certificate
    end_entity = {
        "serialNumber": str(uuid.uuid4().int),
        "subject": "CN=John Doe,O=TU Berlin,C=DE",
        "issuer": f"CN=StudentVC Intermediate CA {length-2}" if length > 2 else "CN=StudentVC Root CA",
        "notBefore": datetime.datetime.now().isoformat(),
        "notAfter": (datetime.datetime.now() + datetime.timedelta(days=365)).isoformat(),
        "subjectPublicKeyInfo": {
            "algorithm": "RSA",
            "keySize": 2048,
            "publicKey": "MOCK_END_ENTITY_PUBLIC_KEY"
        },
        "extensions": [{
            "oid": "2.5.29.17",  # Subject Alternative Name
            "critical": False,
            "value": "DID:did:web:edu:tu.berlin:users:johndoe"
        }]
    }
    chain.append(end_entity)
    
    return chain

def validate_x509_certificate_chain(chain):
    """Validate a mock X.509 certificate chain"""
    # Check chain length
    if len(chain) < 2:
        return False, "Chain too short"
    
    # Check that the root CA is self-signed
    root_ca = chain[0]
    if root_ca["subject"] != root_ca["issuer"]:
        return False, "Root CA is not self-signed"
    
    # Check certificate relationships in the chain
    for i in range(1, len(chain)):
        cert = chain[i]
        issuer_cert = chain[i-1]
        
        # Check that the issuer of this certificate matches the subject of the previous certificate
        if cert["issuer"] != issuer_cert["subject"]:
            return False, f"Certificate at position {i} has incorrect issuer"
        
        # Check validity period
        not_before = datetime.datetime.fromisoformat(cert["notBefore"])
        not_after = datetime.datetime.fromisoformat(cert["notAfter"])
        now = datetime.datetime.now()
        
        if now < not_before:
            return False, f"Certificate at position {i} is not yet valid"
        
        if now > not_after:
            return False, f"Certificate at position {i} has expired"
    
    # Check end-entity certificate extensions
    end_entity = chain[-1]
    if "extensions" not in end_entity:
        return False, "End-entity certificate missing extensions"
    
    # Everything checks out
    return True, "Valid certificate chain"

def verify_credential(credential):
    """Verify a mock credential"""
    # Check required fields
    if "id" not in credential:
        return False, "Missing id"
    
    if "type" not in credential:
        return False, "Missing type"
    
    if "issuer" not in credential:
        return False, "Missing issuer"
    
    if "issuanceDate" not in credential:
        return False, "Missing issuanceDate"
    
    if "credentialSubject" not in credential:
        return False, "Missing credentialSubject"
    
    if "proof" not in credential:
        return False, "Missing proof"
    
    # Check proof
    proof = credential["proof"]
    if "type" not in proof:
        return False, "Missing proof type"
    
    if "proofValue" not in proof:
        return False, "Missing proofValue"
    
    # Everything checks out (in a real implementation, we would verify the cryptographic proof)
    return True, "Valid credential"

def create_selective_disclosure(credential, disclosure_frame):
    """Create a selective disclosure from a BBS+ credential"""
    # Check that the credential has a BBS+ proof
    if "proof" not in credential or credential["proof"]["type"] != "BbsBlsSignature2020":
        return None, "Not a BBS+ credential"
    
    # Extract the fields to disclose based on the frame
    disclosed_fields = {}
    for field, value in disclosure_frame.items():
        if field in credential["credentialSubject"]:
            if isinstance(value, dict):
                # Handle nested fields
                if isinstance(credential["credentialSubject"][field], dict):
                    disclosed_fields[field] = {}
                    for sub_field, sub_value in value.items():
                        if sub_field in credential["credentialSubject"][field]:
                            disclosed_fields[field][sub_field] = credential["credentialSubject"][field][sub_field]
            else:
                # Handle direct fields
                disclosed_fields[field] = credential["credentialSubject"][field]
    
    # Create a new credential with only the disclosed fields
    disclosed_credential = {
        **credential,
        "credentialSubject": disclosed_fields,
        "proof": {
            "type": "BbsBlsSignatureProof2020",
            "created": datetime.datetime.now().isoformat(),
            "verificationMethod": credential["proof"]["verificationMethod"],
            "proofPurpose": "assertionMethod",
            "nonce": str(uuid.uuid4()),
            "proofValue": "kTTbA1xL6P1nKbkpnZ8CJAcHNA7/GcCFdDj1jTgwq8YUkKKyyuwQQKqfoPmlos0rVPzWY/FXykz3w4YzxDmZ35LhWU3zFLxLbF36cZ642DTZ4TCTXqqYeWyoJJkU9EwbJR==+"
        }
    }
    
    return disclosed_credential, "Disclosure created successfully"

def verify_selective_disclosure(disclosed_credential):
    """Verify a selectively disclosed credential"""
    # Check that the credential has a BBS+ disclosure proof
    if "proof" not in disclosed_credential or disclosed_credential["proof"]["type"] != "BbsBlsSignatureProof2020":
        return False, "Not a BBS+ disclosure"
    
    # Check required fields
    if "id" not in disclosed_credential:
        return False, "Missing id"
    
    if "type" not in disclosed_credential:
        return False, "Missing type"
    
    if "issuer" not in disclosed_credential:
        return False, "Missing issuer"
    
    if "issuanceDate" not in disclosed_credential:
        return False, "Missing issuanceDate"
    
    if "credentialSubject" not in disclosed_credential:
        return False, "Missing credentialSubject"
    
    # Check proof
    proof = disclosed_credential["proof"]
    if "type" not in proof:
        return False, "Missing proof type"
    
    if "proofValue" not in proof:
        return False, "Missing proofValue"
    
    # Everything checks out (in a real implementation, we would verify the cryptographic proof)
    return True, "Valid selective disclosure"


class TestPerformance(unittest.TestCase):
    """Test performance of critical operations"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.monitor = PerformanceMonitor()
        
        # Create test data
        self.issuer_did = "did:web:edu:tu.berlin"
        self.subject_did = "did:web:edu:tu.berlin:users:johndoe"
        
        # Generate test credentials
        self.credential = generate_credential(self.issuer_did, self.subject_did)
        self.bbs_credential = generate_bbs_credential(self.issuer_did, self.subject_did)
        
        # Generate test certificates
        self.certificate = generate_x509_certificate()
        self.certificate_chain = generate_x509_certificate_chain()
    
    def test_credential_generation_performance(self):
        """Test the performance of credential generation"""
        # Measure single credential generation
        _, metrics = self.monitor.measure_function(
            generate_credential,
            self.issuer_did,
            self.subject_did
        )
        
        # Log metrics
        print(f"\nSingle credential generation:")
        print(f"  Time: {metrics['elapsed_time']:.6f} seconds")
        print(f"  Memory: {metrics['memory_used_mb']:.2f} MB")
        
        # Measure repeated credential generation
        iterations = 100
        _, stats = self.monitor.measure_function_repeated(
            generate_credential,
            iterations,
            self.issuer_did,
            self.subject_did
        )
        
        # Log statistics
        print(f"\nRepeated credential generation ({iterations} iterations):")
        print(f"  Total time: {stats['total_time']:.6f} seconds")
        print(f"  Average time: {stats['avg_time']:.6f} seconds")
        print(f"  Median time: {stats['median_time']:.6f} seconds")
        print(f"  Min time: {stats['min_time']:.6f} seconds")
        print(f"  Max time: {stats['max_time']:.6f} seconds")
        print(f"  Stddev time: {stats['stddev_time']:.6f} seconds")
        print(f"  Average memory: {stats['avg_memory_used_mb']:.2f} MB")
        
        # Performance assertions (adjust thresholds as needed)
        self.assertLess(stats['avg_time'], 0.01, "Average credential generation time exceeds threshold")
        self.assertLess(stats['max_time'], 0.05, "Maximum credential generation time exceeds threshold")
    
    def test_bbs_credential_generation_performance(self):
        """Test the performance of BBS+ credential generation"""
        # Measure single BBS+ credential generation
        _, metrics = self.monitor.measure_function(
            generate_bbs_credential,
            self.issuer_did,
            self.subject_did
        )
        
        # Log metrics
        print(f"\nSingle BBS+ credential generation:")
        print(f"  Time: {metrics['elapsed_time']:.6f} seconds")
        print(f"  Memory: {metrics['memory_used_mb']:.2f} MB")
        
        # Measure repeated BBS+ credential generation
        iterations = 50
        _, stats = self.monitor.measure_function_repeated(
            generate_bbs_credential,
            iterations,
            self.issuer_did,
            self.subject_did
        )
        
        # Log statistics
        print(f"\nRepeated BBS+ credential generation ({iterations} iterations):")
        print(f"  Total time: {stats['total_time']:.6f} seconds")
        print(f"  Average time: {stats['avg_time']:.6f} seconds")
        print(f"  Median time: {stats['median_time']:.6f} seconds")
        print(f"  Min time: {stats['min_time']:.6f} seconds")
        print(f"  Max time: {stats['max_time']:.6f} seconds")
        print(f"  Stddev time: {stats['stddev_time']:.6f} seconds")
        print(f"  Average memory: {stats['avg_memory_used_mb']:.2f} MB")
        
        # Performance assertions (adjust thresholds as needed)
        self.assertLess(stats['avg_time'], 0.02, "Average BBS+ credential generation time exceeds threshold")
        self.assertLess(stats['max_time'], 0.1, "Maximum BBS+ credential generation time exceeds threshold")
    
    def test_certificate_generation_performance(self):
        """Test the performance of X.509 certificate generation"""
        # Measure single certificate generation
        _, metrics = self.monitor.measure_function(generate_x509_certificate)
        
        # Log metrics
        print(f"\nSingle X.509 certificate generation:")
        print(f"  Time: {metrics['elapsed_time']:.6f} seconds")
        print(f"  Memory: {metrics['memory_used_mb']:.2f} MB")
        
        # Measure repeated certificate generation
        iterations = 100
        _, stats = self.monitor.measure_function_repeated(
            generate_x509_certificate,
            iterations
        )
        
        # Log statistics
        print(f"\nRepeated X.509 certificate generation ({iterations} iterations):")
        print(f"  Total time: {stats['total_time']:.6f} seconds")
        print(f"  Average time: {stats['avg_time']:.6f} seconds")
        print(f"  Median time: {stats['median_time']:.6f} seconds")
        print(f"  Min time: {stats['min_time']:.6f} seconds")
        print(f"  Max time: {stats['max_time']:.6f} seconds")
        print(f"  Stddev time: {stats['stddev_time']:.6f} seconds")
        print(f"  Average memory: {stats['avg_memory_used_mb']:.2f} MB")
        
        # Performance assertions (adjust thresholds as needed)
        self.assertLess(stats['avg_time'], 0.01, "Average certificate generation time exceeds threshold")
        self.assertLess(stats['max_time'], 0.05, "Maximum certificate generation time exceeds threshold")
    
    def test_certificate_chain_generation_performance(self):
        """Test the performance of X.509 certificate chain generation"""
        # Measure certificate chain generation with different lengths
        for length in [2, 3, 5]:
            # Measure single chain generation
            _, metrics = self.monitor.measure_function(
                generate_x509_certificate_chain,
                length
            )
            
            # Log metrics
            print(f"\nX.509 certificate chain generation (length {length}):")
            print(f"  Time: {metrics['elapsed_time']:.6f} seconds")
            print(f"  Memory: {metrics['memory_used_mb']:.2f} MB")
            
            # Performance assertions (adjust thresholds as needed)
            self.assertLess(
                metrics['elapsed_time'],
                0.05 * length,
                f"Certificate chain generation time (length {length}) exceeds threshold"
            )
    
    def test_certificate_chain_validation_performance(self):
        """Test the performance of X.509 certificate chain validation"""
        # Generate certificate chains with different lengths
        chains = {
            2: generate_x509_certificate_chain(2),
            3: generate_x509_certificate_chain(3),
            5: generate_x509_certificate_chain(5)
        }
        
        # Measure chain validation performance for each length
        for length, chain in chains.items():
            # Measure single validation
            _, metrics = self.monitor.measure_function(
                validate_x509_certificate_chain,
                chain
            )
            
            # Log metrics
            print(f"\nX.509 certificate chain validation (length {length}):")
            print(f"  Time: {metrics['elapsed_time']:.6f} seconds")
            print(f"  Memory: {metrics['memory_used_mb']:.2f} MB")
            
            # Measure repeated validation
            iterations = 100
            _, stats = self.monitor.measure_function_repeated(
                validate_x509_certificate_chain,
                iterations,
                chain
            )
            
            # Log statistics
            print(f"\nRepeated X.509 certificate chain validation (length {length}, {iterations} iterations):")
            print(f"  Total time: {stats['total_time']:.6f} seconds")
            print(f"  Average time: {stats['avg_time']:.6f} seconds")
            print(f"  Median time: {stats['median_time']:.6f} seconds")
            print(f"  Min time: {stats['min_time']:.6f} seconds")
            print(f"  Max time: {stats['max_time']:.6f} seconds")
            print(f"  Stddev time: {stats['stddev_time']:.6f} seconds")
            print(f"  Average memory: {stats['avg_memory_used_mb']:.2f} MB")
            
            # Performance assertions (adjust thresholds as needed)
            self.assertLess(
                stats['avg_time'],
                0.005 * length,
                f"Average certificate chain validation time (length {length}) exceeds threshold"
            )
    
    def test_credential_verification_performance(self):
        """Test the performance of credential verification"""
        # Measure single credential verification
        _, metrics = self.monitor.measure_function(
            verify_credential,
            self.credential
        )
        
        # Log metrics
        print(f"\nSingle credential verification:")
        print(f"  Time: {metrics['elapsed_time']:.6f} seconds")
        print(f"  Memory: {metrics['memory_used_mb']:.2f} MB")
        
        # Measure repeated credential verification
        iterations = 1000
        _, stats = self.monitor.measure_function_repeated(
            verify_credential,
            iterations,
            self.credential
        )
        
        # Log statistics
        print(f"\nRepeated credential verification ({iterations} iterations):")
        print(f"  Total time: {stats['total_time']:.6f} seconds")
        print(f"  Average time: {stats['avg_time']:.6f} seconds")
        print(f"  Median time: {stats['median_time']:.6f} seconds")
        print(f"  Min time: {stats['min_time']:.6f} seconds")
        print(f"  Max time: {stats['max_time']:.6f} seconds")
        print(f"  Stddev time: {stats['stddev_time']:.6f} seconds")
        print(f"  Average memory: {stats['avg_memory_used_mb']:.2f} MB")
        
        # Performance assertions (adjust thresholds as needed)
        self.assertLess(stats['avg_time'], 0.001, "Average credential verification time exceeds threshold")
        self.assertLess(stats['max_time'], 0.01, "Maximum credential verification time exceeds threshold")
    
    def test_selective_disclosure_performance(self):
        """Test the performance of selective disclosure generation and verification"""
        # Define disclosure frames with different sizes
        small_frame = {
            "name": True
        }
        
        medium_frame = {
            "name": True,
            "degree": {
                "type": True,
                "name": True
            },
            "email": True
        }
        
        large_frame = {
            "name": True,
            "degree": {
                "type": True,
                "name": True,
                "university": True,
                "graduationDate": True
            },
            "address": {
                "city": True,
                "country": True
            },
            "email": True,
            "birthDate": True
        }
        
        frames = {
            "small": small_frame,
            "medium": medium_frame,
            "large": large_frame
        }
        
        # Measure selective disclosure generation and verification for each frame size
        for size, frame in frames.items():
            # Measure disclosure generation
            _, metrics = self.monitor.measure_function(
                create_selective_disclosure,
                self.bbs_credential,
                frame
            )
            
            # Log metrics
            print(f"\nSelective disclosure generation ({size} frame):")
            print(f"  Time: {metrics['elapsed_time']:.6f} seconds")
            print(f"  Memory: {metrics['memory_used_mb']:.2f} MB")
            
            # Generate the disclosure for verification testing
            disclosure, _ = create_selective_disclosure(self.bbs_credential, frame)
            
            # Measure disclosure verification
            _, metrics = self.monitor.measure_function(
                verify_selective_disclosure,
                disclosure
            )
            
            # Log metrics
            print(f"\nSelective disclosure verification ({size} frame):")
            print(f"  Time: {metrics['elapsed_time']:.6f} seconds")
            print(f"  Memory: {metrics['memory_used_mb']:.2f} MB")
            
            # Measure repeated disclosure verification
            iterations = 100
            _, stats = self.monitor.measure_function_repeated(
                verify_selective_disclosure,
                iterations,
                disclosure
            )
            
            # Log statistics
            print(f"\nRepeated selective disclosure verification ({size} frame, {iterations} iterations):")
            print(f"  Total time: {stats['total_time']:.6f} seconds")
            print(f"  Average time: {stats['avg_time']:.6f} seconds")
            print(f"  Median time: {stats['median_time']:.6f} seconds")
            print(f"  Min time: {stats['min_time']:.6f} seconds")
            print(f"  Max time: {stats['max_time']:.6f} seconds")
            print(f"  Stddev time: {stats['stddev_time']:.6f} seconds")
            print(f"  Average memory: {stats['avg_memory_used_mb']:.2f} MB")
            
            # Performance assertions (adjust thresholds as needed)
            self.assertLess(
                stats['avg_time'],
                0.002,
                f"Average selective disclosure verification time ({size} frame) exceeds threshold"
            )
    
    def test_batch_credential_verification_performance(self):
        """Test the performance of batch credential verification"""
        # Generate multiple credentials
        batch_sizes = [10, 50, 100]
        
        for size in batch_sizes:
            credentials = [generate_credential(self.issuer_did, f"did:example:{i}") for i in range(size)]
            
            # Function to verify a batch of credentials
            def verify_batch(creds):
                results = []
                for cred in creds:
                    result, message = verify_credential(cred)
                    results.append({"verified": result, "message": message})
                return results
            
            # Measure batch verification
            _, metrics = self.monitor.measure_function(
                verify_batch,
                credentials
            )
            
            # Log metrics
            print(f"\nBatch credential verification ({size} credentials):")
            print(f"  Time: {metrics['elapsed_time']:.6f} seconds")
            print(f"  Time per credential: {metrics['elapsed_time'] / size:.6f} seconds")
            print(f"  Memory: {metrics['memory_used_mb']:.2f} MB")
            print(f"  Memory per credential: {metrics['memory_used_mb'] / size:.2f} MB")
            
            # Performance assertions (adjust thresholds as needed)
            self.assertLess(
                metrics['elapsed_time'],
                0.001 * size,
                f"Batch credential verification time ({size} credentials) exceeds threshold"
            )
    
    def test_memory_usage_for_large_operations(self):
        """Test memory usage for large operations"""
        # Generate many credentials to test memory usage
        num_credentials = 1000
        
        # Function to generate many credentials
        def generate_many_credentials(count):
            return [generate_credential(self.issuer_did, f"did:example:{i}") for i in range(count)]
        
        # Measure memory usage
        _, metrics = self.monitor.measure_function(
            generate_many_credentials,
            num_credentials
        )
        
        # Log metrics
        print(f"\nMemory usage for generating {num_credentials} credentials:")
        print(f"  Total memory: {metrics['memory_used_mb']:.2f} MB")
        print(f"  Memory per credential: {metrics['memory_used_mb'] / num_credentials:.2f} MB")
        
        # Performance assertions (adjust thresholds as needed)
        self.assertLess(
            metrics['memory_used_mb'] / num_credentials,
            0.05,
            f"Memory usage per credential exceeds threshold"
        )
    
    def test_concurrent_operations_performance(self):
        """Test performance of concurrent operations"""
        # This is a simplified simulation of concurrent operations using a synchronous approach
        # In a real implementation, we would use asyncio, threading, or multiprocessing
        
        # Function to simulate concurrent operations
        def simulate_concurrent_operations(num_operations):
            operations = []
            
            # Generate a mix of operations
            for i in range(num_operations):
                op_type = i % 4
                
                if op_type == 0:
                    # Generate credential
                    operations.append(("generate", lambda: generate_credential(self.issuer_did, f"did:example:{i}")))
                elif op_type == 1:
                    # Verify credential
                    operations.append(("verify", lambda: verify_credential(self.credential)))
                elif op_type == 2:
                    # Generate certificate
                    operations.append(("certificate", lambda: generate_x509_certificate()))
                else:
                    # Validate certificate chain
                    operations.append(("validate", lambda: validate_x509_certificate_chain(self.certificate_chain)))
            
            # Execute all operations and measure time for each
            results = []
            for op_name, op_func in operations:
                start_time = time.time()
                op_func()
                elapsed_time = time.time() - start_time
                results.append((op_name, elapsed_time))
            
            return results
        
        # Test with different numbers of concurrent operations
        for num_ops in [20, 50, 100]:
            # Measure performance
            _, metrics = self.monitor.measure_function(
                simulate_concurrent_operations,
                num_ops
            )
            
            # Log metrics
            print(f"\nSimulated {num_ops} concurrent operations:")
            print(f"  Total time: {metrics['elapsed_time']:.6f} seconds")
            print(f"  Time per operation: {metrics['elapsed_time'] / num_ops:.6f} seconds")
            print(f"  Total memory: {metrics['memory_used_mb']:.2f} MB")
            print(f"  Memory per operation: {metrics['memory_used_mb'] / num_ops:.2f} MB")
            
            # Performance assertions (adjust thresholds as needed)
            self.assertLess(
                metrics['elapsed_time'] / num_ops,
                0.01,
                f"Average time per operation in concurrent scenario ({num_ops} operations) exceeds threshold"
            )


if __name__ == "__main__":
    unittest.main() 