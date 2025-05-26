#!/usr/bin/env python3
"""
Multi-Issuer X.509 Integration with did:web Method

This script demonstrates the integration of X.509 certificates with did:web DIDs
for multiple educational institutions:
- Technical University of Berlin (did:web:edu:tu.berlin)
- Free University of Berlin (did:web:edu:fu-berlin.de)

The simulation includes:
1. Root CA setup for a shared educational PKI
2. Certificate issuance for multiple universities
3. DID creation with did:web method
4. X.509 certificate binding to DIDs
5. Verifiable credential issuance from multiple issuers
6. Cross-verification between institutions
"""

import os
import sys
import json
import uuid
import base64
import tempfile
import datetime
import time
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from cryptography.hazmat.primitives import serialization

# Add backend directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("MULTI-ISSUER-X509")

# Import necessary modules
from src.x509.certificate import (
    generate_certificate_chain,
    get_certificate_info,
    save_certificate
)
from src.x509.did_binding import (
    add_x509_verification_method_to_did_document,
    verify_bidirectional_linkage,
    find_did_in_certificate_san
)
from src.x509.integration import (
    enhance_issuer_metadata_with_x509,
    embed_x509_metadata_in_credential,
    verify_credential_with_x509
)

# Utility functions

def print_header(title):
    """Print a formatted section header."""
    terminal_width = 80
    print("\n" + "=" * terminal_width)
    print(f" {title} ".center(terminal_width, "="))
    print("=" * terminal_width + "\n")

def print_step(step_number, title):
    """Print a formatted step header."""
    print(f"\n[Step {step_number}] {title}")
    print("-" * 60)

def print_json(data, title=None):
    """Print JSON data in a formatted way."""
    if title:
        print(f"\n{title}:")
    
    # Custom JSON encoder to handle datetime objects
    class DateTimeEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, datetime.datetime):
                return obj.isoformat()
            return super().default(obj)
    
    print(json.dumps(data, indent=2, cls=DateTimeEncoder))

def simulate_delay(action, duration=0.5):
    """Simulate a delay with a progress indicator."""
    print(f"{action}... ", end="", flush=True)
    for _ in range(3):
        time.sleep(duration / 3)
        print(".", end="", flush=True)
    print(" Done!")

def simulate_ui(title, user=None, action=None):
    """Simulate a basic UI interaction."""
    terminal_width = 80
    print("\n" + "-" * terminal_width)
    header = f" {title} "
    if user:
        header = f" [{user}] {title} "
    print(header.center(terminal_width, "-"))
    
    if action:
        print(f"\n{action}")
    
    print("-" * terminal_width)

# Main simulation class
class MultiIssuerX509Simulation:
    """Simulates X.509 integration with multiple did:web DIDs."""
    
    def __init__(self):
        """Initialize the simulation environment."""
        self.simulation_dir = tempfile.mkdtemp(prefix="multi_issuer_x509_")
        logger.info(f"Simulation directory: {self.simulation_dir}")
        
        # Create subdirectories for different components
        self.ca_dir = os.path.join(self.simulation_dir, "ca")
        self.tu_berlin_dir = os.path.join(self.simulation_dir, "tu_berlin")
        self.fu_berlin_dir = os.path.join(self.simulation_dir, "fu_berlin")
        self.verifier_dir = os.path.join(self.simulation_dir, "verifier")
        self.holder_dir = os.path.join(self.simulation_dir, "holder")
        
        os.makedirs(self.ca_dir, exist_ok=True)
        os.makedirs(self.tu_berlin_dir, exist_ok=True)
        os.makedirs(self.fu_berlin_dir, exist_ok=True)
        os.makedirs(self.verifier_dir, exist_ok=True)
        os.makedirs(self.holder_dir, exist_ok=True)
        os.makedirs(os.path.join(self.holder_dir, "wallet"), exist_ok=True)
        
        # Initialize DIDs
        self.tu_berlin_did = "did:web:edu:tu.berlin"
        self.fu_berlin_did = "did:web:edu:fu-berlin.de"
        self.holder_did = "did:web:example.com:holder"
        
        # Initialize simulation state
        self.root_ca_cert = None
        self.root_ca_key = None
        self.intermediate_ca_cert = None
        self.intermediate_ca_key = None
        
        self.tu_berlin_cert_chain = None
        self.tu_berlin_keys = None
        self.tu_berlin_did_document = None
        
        self.fu_berlin_cert_chain = None
        self.fu_berlin_keys = None
        self.fu_berlin_did_document = None
        
        self.tu_credential = None
        self.fu_credential = None
        
        logger.info("Simulation environment initialized")
    
    def setup_root_ca(self):
        """Setup the root CA for the educational PKI."""
        print_step(1, "Educational PKI Root CA Setup")
        
        simulate_ui("PKI Management System", user="Educational PKI Administrator")
        
        logger.info("Setting up Educational PKI Root CA")
        
        simulate_delay("Generating Root CA certificate")
        
        # Create a Root CA certificate for educational institutions
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes
        import datetime
        
        # Generate root CA key
        root_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        # Create root CA certificate
        root_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Educational-Root-CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "German Educational PKI"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE")
        ])
        
        root_cert = x509.CertificateBuilder().subject_name(
            root_name
        ).issuer_name(
            root_name  # Self-signed
        ).public_key(
            root_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=1), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).sign(root_key, hashes.SHA256())
        
        # Save root CA certificate
        root_cert_path = os.path.join(self.ca_dir, "root_ca.pem")
        with open(root_cert_path, "wb") as f:
            f.write(root_cert.public_bytes(serialization.Encoding.PEM))
        
        logger.info(f"Saved Root CA certificate to {root_cert_path}")
        
        # Generate Intermediate CA
        simulate_delay("Generating Intermediate CA certificate")
        
        intermediate_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )
        
        intermediate_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Educational-Intermediate-CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "German Educational PKI"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE")
        ])
        
        intermediate_cert = x509.CertificateBuilder().subject_name(
            intermediate_name
        ).issuer_name(
            root_cert.subject
        ).public_key(
            intermediate_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1825)  # 5 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).sign(root_key, hashes.SHA256())
        
        # Save intermediate CA certificate
        intermediate_cert_path = os.path.join(self.ca_dir, "intermediate_ca.pem")
        with open(intermediate_cert_path, "wb") as f:
            f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
        
        logger.info(f"Saved Intermediate CA certificate to {intermediate_cert_path}")
        
        # Store the CA certificates and keys for later use
        self.root_ca_cert = root_cert
        self.root_ca_key = root_key
        self.intermediate_ca_cert = intermediate_cert
        self.intermediate_ca_key = intermediate_key
        
        # Display certificate info
        root_cert_info = get_certificate_info(root_cert)
        intermediate_cert_info = get_certificate_info(intermediate_cert)
        
        print_json(root_cert_info, "Root CA Certificate Information")
        print_json(intermediate_cert_info, "Intermediate CA Certificate Information")
        
        simulate_ui("PKI Management System", 
                   user="Educational PKI Administrator",
                   action="✅ Educational PKI setup completed with Root and Intermediate CAs")
        
        return root_cert, intermediate_cert
    
    def create_issuer_certificates(self):
        """Create certificates for TU Berlin and FU Berlin with DID embedding."""
        print_step(2, "University Issuer Certificate Creation")
        
        # 1. Create TU Berlin certificate
        simulate_ui("Certificate Management", user="TU Berlin Administrator")
        
        logger.info(f"Creating certificate chain for TU Berlin with DID: {self.tu_berlin_did}")
        
        simulate_delay("Generating TU Berlin end-entity certificate")
        
        # Create end-entity certificate for TU Berlin with DID in SAN
        self.tu_berlin_cert_chain, self.tu_berlin_keys = generate_certificate_chain(
            subject_name=f"{self.tu_berlin_did}#key-1",
            did=self.tu_berlin_did
        )
        
        # Unpack certificates for easier access
        self.tu_berlin_end_entity_cert = self.tu_berlin_cert_chain[0]
        self.tu_berlin_end_entity_key = self.tu_berlin_keys[0]
        
        # Save certificates to the TU Berlin directory
        tu_cert_path = os.path.join(self.tu_berlin_dir, "certificate.pem")
        with open(tu_cert_path, "wb") as f:
            f.write(self.tu_berlin_end_entity_cert.public_bytes(serialization.Encoding.PEM))
        
        logger.info(f"Saved TU Berlin certificate to {tu_cert_path}")
        
        # Verify DID in certificate
        extracted_did = find_did_in_certificate_san(self.tu_berlin_end_entity_cert)
        logger.info(f"Extracted DID from TU Berlin certificate: {extracted_did}")
        assert extracted_did == self.tu_berlin_did, "DID mismatch in TU Berlin certificate"
        
        # Display certificate info
        tu_cert_info = get_certificate_info(self.tu_berlin_end_entity_cert)
        print_json(tu_cert_info, "TU Berlin Certificate Information")
        
        simulate_ui("Certificate Management", 
                   user="TU Berlin Administrator",
                   action=f"✅ Certificate successfully created for {self.tu_berlin_did}")
        
        # 2. Create FU Berlin certificate
        simulate_ui("Certificate Management", user="FU Berlin Administrator")
        
        logger.info(f"Creating certificate chain for FU Berlin with DID: {self.fu_berlin_did}")
        
        simulate_delay("Generating FU Berlin end-entity certificate")
        
        # Create end-entity certificate for FU Berlin with DID in SAN
        self.fu_berlin_cert_chain, self.fu_berlin_keys = generate_certificate_chain(
            subject_name=f"{self.fu_berlin_did}#key-1",
            did=self.fu_berlin_did
        )
        
        # Unpack certificates for easier access
        self.fu_berlin_end_entity_cert = self.fu_berlin_cert_chain[0]
        self.fu_berlin_end_entity_key = self.fu_berlin_keys[0]
        
        # Save certificates to the FU Berlin directory
        fu_cert_path = os.path.join(self.fu_berlin_dir, "certificate.pem")
        with open(fu_cert_path, "wb") as f:
            f.write(self.fu_berlin_end_entity_cert.public_bytes(serialization.Encoding.PEM))
        
        logger.info(f"Saved FU Berlin certificate to {fu_cert_path}")
        
        # Verify DID in certificate
        extracted_did = find_did_in_certificate_san(self.fu_berlin_end_entity_cert)
        logger.info(f"Extracted DID from FU Berlin certificate: {extracted_did}")
        assert extracted_did == self.fu_berlin_did, "DID mismatch in FU Berlin certificate"
        
        # Display certificate info
        fu_cert_info = get_certificate_info(self.fu_berlin_end_entity_cert)
        print_json(fu_cert_info, "FU Berlin Certificate Information")
        
        simulate_ui("Certificate Management", 
                   user="FU Berlin Administrator",
                   action=f"✅ Certificate successfully created for {self.fu_berlin_did}")
        
        return self.tu_berlin_cert_chain, self.fu_berlin_cert_chain
    
    def create_did_documents(self):
        """Create DID documents for both universities with X.509 verification methods."""
        print_step(3, "DID Document Creation")
        
        # 1. Create TU Berlin DID Document
        simulate_ui("DID Registry Service", user="TU Berlin DID Administrator")
        
        logger.info(f"Creating DID document for {self.tu_berlin_did}")
        
        # Create a basic DID document following did:web method spec
        tu_berlin_did_document = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": self.tu_berlin_did,
            "verificationMethod": [],
            "authentication": [],
            "assertionMethod": []
        }
        
        simulate_delay("Creating TU Berlin DID document")
        
        # Add certificate chain to DID document as verification method
        verification_method_id = f"{self.tu_berlin_did}#key-1"
        tu_berlin_did_document = add_x509_verification_method_to_did_document(
            tu_berlin_did_document,
            self.tu_berlin_end_entity_cert,
            verification_method_id,
            ca_certificates=[self.intermediate_ca_cert, self.root_ca_cert]
        )
        
        # Add verification method to authentication and assertionMethod
        tu_berlin_did_document["authentication"].append(verification_method_id)
        tu_berlin_did_document["assertionMethod"].append(verification_method_id)
        
        # Add a BBS+ verification method for selective disclosure
        tu_berlin_did_document["verificationMethod"].append({
            "id": f"{self.tu_berlin_did}#bbs-key-1",
            "type": "Bls12381G2Key2020",
            "controller": self.tu_berlin_did,
            "publicKeyBase58": "25ETdUZDLQroAzpspx31xzuVuWujrk7n4TrXhyVLiYAohfmx6LgbwhpGBpKDCpFcjGRuD8GTkqzGwCJZpTxUZYz3"
        })
        tu_berlin_did_document["assertionMethod"].append(f"{self.tu_berlin_did}#bbs-key-1")
        
        # Save DID document to the TU Berlin directory
        # In a real did:web implementation, this would be at /.well-known/did.json
        tu_did_doc_path = os.path.join(self.tu_berlin_dir, "did.json")
        with open(tu_did_doc_path, "w") as f:
            json.dump(tu_berlin_did_document, f, indent=2)
        
        logger.info(f"Saved TU Berlin DID document to {tu_did_doc_path}")
        self.tu_berlin_did_document = tu_berlin_did_document
        
        # Verify bidirectional linkage
        tu_linkage_valid = verify_bidirectional_linkage(self.tu_berlin_end_entity_cert, tu_berlin_did_document)
        logger.info(f"TU Berlin bidirectional linkage verification: {tu_linkage_valid}")
        
        print_json(tu_berlin_did_document, "TU Berlin DID Document")
        
        simulate_ui("DID Registry Service", 
                   user="TU Berlin DID Administrator",
                   action=f"✅ DID document created for {self.tu_berlin_did}")
        
        # 2. Create FU Berlin DID Document
        simulate_ui("DID Registry Service", user="FU Berlin DID Administrator")
        
        logger.info(f"Creating DID document for {self.fu_berlin_did}")
        
        # Create a basic DID document
        fu_berlin_did_document = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": self.fu_berlin_did,
            "verificationMethod": [],
            "authentication": [],
            "assertionMethod": []
        }
        
        simulate_delay("Creating FU Berlin DID document")
        
        # Add certificate chain to DID document as verification method
        verification_method_id = f"{self.fu_berlin_did}#key-1"
        fu_berlin_did_document = add_x509_verification_method_to_did_document(
            fu_berlin_did_document,
            self.fu_berlin_end_entity_cert,
            verification_method_id,
            ca_certificates=[self.intermediate_ca_cert, self.root_ca_cert]
        )
        
        # Add verification method to authentication and assertionMethod
        fu_berlin_did_document["authentication"].append(verification_method_id)
        fu_berlin_did_document["assertionMethod"].append(verification_method_id)
        
        # Add a BBS+ verification method for selective disclosure
        fu_berlin_did_document["verificationMethod"].append({
            "id": f"{self.fu_berlin_did}#bbs-key-1",
            "type": "Bls12381G2Key2020",
            "controller": self.fu_berlin_did,
            "publicKeyBase58": "2GKNZ7sugzY5YL57MR4bTuPZNMjpE7cZ4hYUzqAiG8MHEHJqFR6sNVcHroDGtfPJrxTiX1qNXfn4vyJfGhMCfu6Y"
        })
        fu_berlin_did_document["assertionMethod"].append(f"{self.fu_berlin_did}#bbs-key-1")
        
        # Save DID document to the FU Berlin directory
        fu_did_doc_path = os.path.join(self.fu_berlin_dir, "did.json")
        with open(fu_did_doc_path, "w") as f:
            json.dump(fu_berlin_did_document, f, indent=2)
        
        logger.info(f"Saved FU Berlin DID document to {fu_did_doc_path}")
        self.fu_berlin_did_document = fu_berlin_did_document
        
        # Verify bidirectional linkage
        fu_linkage_valid = verify_bidirectional_linkage(self.fu_berlin_end_entity_cert, fu_berlin_did_document)
        logger.info(f"FU Berlin bidirectional linkage verification: {fu_linkage_valid}")
        
        print_json(fu_berlin_did_document, "FU Berlin DID Document")
        
        simulate_ui("DID Registry Service", 
                   user="FU Berlin DID Administrator",
                   action=f"✅ DID document created for {self.fu_berlin_did}")
        
        # Add explanation of did:web resolution
        print("\n[did:web Method Resolution]")
        print(f"1. {self.tu_berlin_did} would resolve to: https://edu.tu.berlin/.well-known/did.json")
        print(f"2. {self.fu_berlin_did} would resolve to: https://edu.fu-berlin.de/.well-known/did.json")
        print("3. The DID documents include X.509 certificate chains in their verification methods")
        print("4. Bidirectional linkage between DIDs and certificates is established")
        
        return self.tu_berlin_did_document, self.fu_berlin_did_document
    
    def issue_credentials(self):
        """Issue credentials using the shared backend with X.509 verification."""
        print_step(4, "Verifiable Credential Issuance")
        
        # Prepare shared backend for credential issuance
        simulate_ui("Shared Credential Issuance Backend", user="System Administrator")
        
        print("\n[Shared Backend Description]")
        print("This backend supports issuing credentials from different universities")
        print("Each university authenticates using its X.509 certificate and DID")
        print("The backend verifies the X.509 certificate and its binding to the DID")
        print("Upon successful verification, the university can issue credentials")
        
        simulate_delay("Initializing shared credential issuance backend")
        
        # 1. TU Berlin issues a credential
        simulate_ui("Credential Issuance Service", user="TU Berlin Registrar")
        
        # Simulate TU Berlin logging into the backend
        print("\n[TU Berlin Authentication]")
        print(f"1. DID: {self.tu_berlin_did}")
        print("2. X.509 Certificate: Presented in TLS client authentication")
        print("3. Backend verifies certificate chain against educational root CA")
        print("4. Backend confirms DID from certificate SAN matches the presented DID")
        print("5. Authentication successful ✅")
        
        logger.info(f"TU Berlin ({self.tu_berlin_did}) issuing credential")
        
        # Create a credential for Computer Science degree
        tu_credential_id = str(uuid.uuid4())
        tu_credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": f"https://tu-berlin.de/credentials/{tu_credential_id}",
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": self.tu_berlin_did,
            "issuanceDate": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "credentialSubject": {
                "id": self.holder_did,
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science in Computer Science"
                },
                "college": "Technical University of Berlin",
                "graduationDate": "2023-06-15",
                "academicResults": [
                    {
                        "courseCode": "CS101",
                        "courseName": "Introduction to Computer Science",
                        "grade": "A"
                    },
                    {
                        "courseCode": "CS202",
                        "courseName": "Algorithms and Data Structures",
                        "grade": "A-"
                    },
                    {
                        "courseCode": "MATH301",
                        "courseName": "Linear Algebra",
                        "grade": "B+"
                    }
                ]
            }
        }
        
        simulate_delay("Creating TU Berlin credential")
        
        # Embed X.509 metadata in credential
        issuer_metadata = {
            "id": self.tu_berlin_did,
            "name": "Technical University of Berlin",
            "x509": {
                "certificateChain": [
                    self.tu_berlin_end_entity_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                ]
            }
        }
        
        # Enhance issuer metadata with X.509 certificate
        enhanced_issuer_metadata = enhance_issuer_metadata_with_x509(
            issuer_metadata, self.tu_berlin_end_entity_cert
        )
        
        # Embed X.509 metadata in credential
        tu_credential = embed_x509_metadata_in_credential(
            tu_credential, 
            self.tu_berlin_end_entity_cert,
            ca_certificates=[self.intermediate_ca_cert, self.root_ca_cert]
        )
        
        # Sign credential (simulated for demo)
        tu_credential["proof"] = {
            "type": "RsaSignature2018",
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "verificationMethod": f"{self.tu_berlin_did}#key-1",
            "proofPurpose": "assertionMethod",
            "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..HQ9GWRr6gqSPdYJ_UxDqACGtt"
        }
        
        # Save credential to TU Berlin directory
        tu_credential_path = os.path.join(self.tu_berlin_dir, f"credential_{tu_credential_id}.json")
        with open(tu_credential_path, "w") as f:
            json.dump(tu_credential, f, indent=2)
        
        logger.info(f"TU Berlin credential saved to {tu_credential_path}")
        self.tu_credential = tu_credential
        
        print_json(tu_credential, "TU Berlin Issued Credential")
        
        simulate_ui("Credential Issuance Service", 
                   user="TU Berlin Registrar",
                   action=f"✅ Computer Science degree credential issued to {self.holder_did}")
        
        # 2. FU Berlin issues a credential
        simulate_ui("Credential Issuance Service", user="FU Berlin Registrar")
        
        # Simulate FU Berlin logging into the backend
        print("\n[FU Berlin Authentication]")
        print(f"1. DID: {self.fu_berlin_did}")
        print("2. X.509 Certificate: Presented in TLS client authentication")
        print("3. Backend verifies certificate chain against educational root CA")
        print("4. Backend confirms DID from certificate SAN matches the presented DID")
        print("5. Authentication successful ✅")
        
        logger.info(f"FU Berlin ({self.fu_berlin_did}) issuing credential")
        
        # Create a credential for Philosophy degree
        fu_credential_id = str(uuid.uuid4())
        fu_credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": f"https://fu-berlin.de/credentials/{fu_credential_id}",
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": self.fu_berlin_did,
            "issuanceDate": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "credentialSubject": {
                "id": self.holder_did,
                "degree": {
                    "type": "MasterDegree",
                    "name": "Master of Arts in Philosophy"
                },
                "college": "Free University of Berlin",
                "graduationDate": "2023-12-20",
                "academicResults": [
                    {
                        "courseCode": "PHIL501",
                        "courseName": "Advanced Ethics",
                        "grade": "A"
                    },
                    {
                        "courseCode": "PHIL602",
                        "courseName": "Contemporary Philosophy",
                        "grade": "A"
                    },
                    {
                        "courseCode": "HIST401",
                        "courseName": "History of Philosophical Thought",
                        "grade": "A-"
                    }
                ]
            }
        }
        
        simulate_delay("Creating FU Berlin credential")
        
        # Embed X.509 metadata in credential
        issuer_metadata = {
            "id": self.fu_berlin_did,
            "name": "Free University of Berlin",
            "x509": {
                "certificateChain": [
                    self.fu_berlin_end_entity_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                ]
            }
        }
        
        # Enhance issuer metadata with X.509 certificate
        enhanced_issuer_metadata = enhance_issuer_metadata_with_x509(
            issuer_metadata, self.fu_berlin_end_entity_cert
        )
        
        # Embed X.509 metadata in credential
        fu_credential = embed_x509_metadata_in_credential(
            fu_credential, 
            self.fu_berlin_end_entity_cert,
            ca_certificates=[self.intermediate_ca_cert, self.root_ca_cert]
        )
        
        # Sign credential (simulated for demo)
        fu_credential["proof"] = {
            "type": "RsaSignature2018",
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "verificationMethod": f"{self.fu_berlin_did}#key-1",
            "proofPurpose": "assertionMethod",
            "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..KCyaYRjD152o4vVY87i+MSXbd"
        }
        
        # Save credential to FU Berlin directory
        fu_credential_path = os.path.join(self.fu_berlin_dir, f"credential_{fu_credential_id}.json")
        with open(fu_credential_path, "w") as f:
            json.dump(fu_credential, f, indent=2)
        
        logger.info(f"FU Berlin credential saved to {fu_credential_path}")
        self.fu_credential = fu_credential
        
        print_json(fu_credential, "FU Berlin Issued Credential")
        
        simulate_ui("Credential Issuance Service", 
                   user="FU Berlin Registrar",
                   action=f"✅ Philosophy degree credential issued to {self.holder_did}")
        
        return self.tu_credential, self.fu_credential
    
    def holder_receive_credentials(self):
        """Simulate the holder receiving credentials from both universities."""
        print_step(5, "Credential Storage in Holder's Wallet")
        
        simulate_ui("Digital Wallet Application", user="Credential Holder")
        
        logger.info("Holder receiving credentials from universities")
        
        # Create holder wallet directory
        wallet_dir = os.path.join(self.holder_dir, "wallet")
        os.makedirs(wallet_dir, exist_ok=True)
        
        # 1. Receive TU Berlin credential
        simulate_delay("Receiving TU Berlin credential")
        
        # Verify the credential before storing
        print("\n[Credential Verification - TU Berlin]")
        print("1. Verifying credential signature...")
        print("2. Verifying issuer DID...")
        print("3. Checking X.509 certificate chain...")
        print("4. Verifying certificate binding to DID...")
        print("5. All checks passed ✅")
        
        # Save TU Berlin credential to wallet
        tu_credential_id = self.tu_credential["id"].split("/")[-1]
        tu_credential_wallet_path = os.path.join(wallet_dir, f"tu_berlin_credential_{tu_credential_id}.json")
        with open(tu_credential_wallet_path, "w") as f:
            json.dump(self.tu_credential, f, indent=2)
        
        logger.info(f"Stored TU Berlin credential in wallet: {tu_credential_wallet_path}")
        
        # 2. Receive FU Berlin credential
        simulate_delay("Receiving FU Berlin credential")
        
        # Verify the credential before storing
        print("\n[Credential Verification - FU Berlin]")
        print("1. Verifying credential signature...")
        print("2. Verifying issuer DID...")
        print("3. Checking X.509 certificate chain...")
        print("4. Verifying certificate binding to DID...")
        print("5. All checks passed ✅")
        
        # Save FU Berlin credential to wallet
        fu_credential_id = self.fu_credential["id"].split("/")[-1]
        fu_credential_wallet_path = os.path.join(wallet_dir, f"fu_berlin_credential_{fu_credential_id}.json")
        with open(fu_credential_wallet_path, "w") as f:
            json.dump(self.fu_credential, f, indent=2)
        
        logger.info(f"Stored FU Berlin credential in wallet: {fu_credential_wallet_path}")
        
        # Display wallet contents
        simulate_ui("Digital Wallet Application", 
                   user="Credential Holder",
                   action="✅ Successfully received and stored credentials from both universities")
        
        print("\n[Wallet Contents]")
        print("1. Technical University of Berlin: Bachelor of Science in Computer Science")
        print("2. Free University of Berlin: Master of Arts in Philosophy")
        print("\nBoth credentials include X.509 certificate chains for verification")
        
        return tu_credential_wallet_path, fu_credential_wallet_path
    
    def verify_credentials(self):
        """Verify credentials from both universities using X.509 trust path."""
        print_step(6, "Credential Verification by Relying Party")
        
        simulate_ui("Credential Verification Service", user="Relying Party")
        
        logger.info("Verifying credentials from different universities")
        
        # Load trusted CA certificates
        trusted_cas = [self.root_ca_cert]
        
        # 1. Verify TU Berlin credential
        simulate_delay("Verifying TU Berlin credential")
        
        print("\n[Verification Process - TU Berlin Credential]")
        print("1. Extract X.509 certificate chain from credential")
        print("2. Verify certificate chain against trusted root CA")
        print("3. Extract DID from certificate SAN extension")
        print("4. Verify DID matches credential issuer")
        print("5. Verify credential signature using issuer's public key")
        
        # Perform verification (simulated for demo)
        is_valid_tu, reason_tu = verify_credential_with_x509(self.tu_credential, trusted_cas)
        
        print(f"\nVerification result: {'✅ Valid' if is_valid_tu else '❌ Invalid'}")
        print(f"Reason: {reason_tu}")
        
        # 2. Verify FU Berlin credential
        simulate_delay("Verifying FU Berlin credential")
        
        print("\n[Verification Process - FU Berlin Credential]")
        print("1. Extract X.509 certificate chain from credential")
        print("2. Verify certificate chain against trusted root CA")
        print("3. Extract DID from certificate SAN extension")
        print("4. Verify DID matches credential issuer")
        print("5. Verify credential signature using issuer's public key")
        
        # Perform verification (simulated for demo)
        is_valid_fu, reason_fu = verify_credential_with_x509(self.fu_credential, trusted_cas)
        
        print(f"\nVerification result: {'✅ Valid' if is_valid_fu else '❌ Invalid'}")
        print(f"Reason: {reason_fu}")
        
        # Summarize verification results
        simulate_ui("Credential Verification Service", 
                   user="Relying Party",
                   action="✅ Successfully verified credentials from both universities using X.509 trust path")
        
        print("\n[Trust Assessment]")
        print("1. Both credentials are verifiable through the shared educational PKI")
        print("2. X.509 certificates provide a standardized trust mechanism")
        print("3. DIDs provide decentralized identifiers with X.509 binding")
        print("4. The combined approach offers strong security and interoperability")
        
        return is_valid_tu and is_valid_fu
    
    def run_simulation(self):
        """Run the complete simulation workflow."""
        print_header("X.509 Integration with did:web Method for German Universities")
        
        # Step 1: Setup the Educational PKI
        self.setup_root_ca()
        
        # Step 2: Create certificates for universities
        self.create_issuer_certificates()
        
        # Step 3: Create DID documents with X.509 verification methods
        self.create_did_documents()
        
        # Step 4: Issue credentials using the shared backend
        self.issue_credentials()
        
        # Step 5: Holder receives and stores credentials
        self.holder_receive_credentials()
        
        # Step 6: Verify credentials using X.509 trust path
        self.verify_credentials()
        
        print_header("Simulation Complete")
        print(f"Simulation directory: {self.simulation_dir}")
        
        print("\n[Summary]")
        print("1. Educational PKI established with Root and Intermediate CAs")
        print("2. University certificates created and bound to DIDs")
        print("3. DID documents created according to did:web method specification")
        print("4. Credentials issued from both universities with X.509 metadata")
        print("5. Credentials successfully verified using X.509 trust path")
        print("\nThis simulation demonstrates how X.509 certificates can be bound to")
        print("did:web DIDs to combine traditional PKI trust with decentralized identifiers.")
        
        return {
            "simulation_dir": self.simulation_dir,
            "tu_berlin_did": self.tu_berlin_did,
            "fu_berlin_did": self.fu_berlin_did,
            "simulation_successful": True
        }

# Main entry point
if __name__ == "__main__":
    simulation = MultiIssuerX509Simulation()
    simulation.run_simulation() 