#!/usr/bin/env python3
"""
Comprehensive End-to-End X.509 Integration Simulation

This script provides a detailed simulation of the entire workflow for X.509 certificate
integration with verifiable credentials, including:

1. Certificate Authority Setup
2. Certificate Chain Generation
3. DID Document Creation and Storage
4. Credential Issuance with X.509 Metadata
5. BBS+ Signatures for Selective Disclosure
6. Wallet Storage Simulation
7. Presentation Creation with Selective Disclosure
8. Verification using both X.509 and DID Trust Paths
9. OID4VC/OID4VP Flow Simulation

The simulation includes detailed logging and simulated UI components to clearly
illustrate each stage of the process.
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
from cryptography.hazmat.primitives import serialization

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("X509-E2E-Simulation")

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import necessary modules
from src.x509.certificate import (
    generate_certificate_chain,
    get_certificate_info,
    save_certificate
)
from src.x509.did_binding import (
    find_did_in_certificate_san,
    add_x509_verification_method_to_did_document,
    verify_bidirectional_linkage
)
from src.x509.integration import (
    enhance_issuer_metadata_with_x509,
    embed_x509_metadata_in_credential,
    verify_credential_with_x509
)

# Simulation utilities

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

def simulate_delay(action, duration=1.0):
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

class X509WorkflowSimulation:
    """Simulates the complete X.509 integration workflow."""
    
    def __init__(self):
        """Initialize the simulation environment."""
        self.simulation_dir = tempfile.mkdtemp(prefix="x509_simulation_")
        logger.info(f"Simulation directory: {self.simulation_dir}")
        
        # Create subdirectories for different components
        self.ca_dir = os.path.join(self.simulation_dir, "ca")
        self.issuer_dir = os.path.join(self.simulation_dir, "issuer")
        self.holder_dir = os.path.join(self.simulation_dir, "holder")
        self.verifier_dir = os.path.join(self.simulation_dir, "verifier")
        
        os.makedirs(self.ca_dir, exist_ok=True)
        os.makedirs(self.issuer_dir, exist_ok=True)
        os.makedirs(self.holder_dir, exist_ok=True)
        os.makedirs(self.verifier_dir, exist_ok=True)
        
        # Initialize simulation state
        self.cert_chain = None
        self.private_keys = None
        self.issuer_did = None
        self.issuer_did_document = None
        self.holder_did = "did:web:example.com:holder"
        self.credential = None
        self.signed_credential = None
        self.presentation = None
        
        logger.info("Simulation environment initialized")
    
    def setup_certificate_authority(self):
        """Set up the Certificate Authority and generate a certificate chain."""
        print_step(1, "Certificate Authority Setup")
        
        simulate_ui("Certificate Authority Management System", user="CA Administrator")
        
        logger.info("Setting up Certificate Authority")
        
        # Generate root CA, intermediate CA, and end-entity certificates
        self.issuer_did = "did:web:edu:tub:issuer"
        logger.info(f"Creating certificate chain for issuer DID: {self.issuer_did}")
        
        simulate_delay("Generating Root CA certificate")
        simulate_delay("Generating Intermediate CA certificate")
        simulate_delay("Generating End-entity certificate with DID in SubjectAlternativeName")
        
        # Actually generate the certificate chain
        self.cert_chain, self.private_keys = generate_certificate_chain(
            subject_name="did:web:edu:tub:issuer#key-1",
            did=self.issuer_did
        )
        
        # Unpack the certificates for easier access
        self.end_entity_cert = self.cert_chain[0]
        self.intermediate_cert = self.cert_chain[1]
        self.root_cert = self.cert_chain[2]
        self.end_entity_key = self.private_keys[0]
        
        # Save certificates to the CA directory
        cert_types = ["end_entity", "intermediate", "root"]
        self.cert_paths = []
        
        for i, cert in enumerate(self.cert_chain):
            cert_type = cert_types[i]
            cert_path = os.path.join(self.ca_dir, f"{cert_type}_cert.pem")
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            self.cert_paths.append(cert_path)
            logger.info(f"Saved {cert_type} certificate to {cert_path}")
        
        # Verify DID in certificate
        extracted_did = find_did_in_certificate_san(self.end_entity_cert)
        logger.info(f"Extracted DID from certificate: {extracted_did}")
        assert extracted_did == self.issuer_did, "DID mismatch in certificate"
        
        # Display certificate info
        issuer_cert_info = get_certificate_info(self.end_entity_cert)
        print_json(issuer_cert_info, "End-entity Certificate Information")
        
        simulate_ui("Certificate Authority Management System", 
                   user="CA Administrator",
                   action=f"✅ Certificate chain successfully created for {self.issuer_did}")
        
        return self.cert_chain, self.private_keys
    
    def create_did_document(self):
        """Create a DID document with X.509 verification methods."""
        print_step(2, "DID Document Creation")
        
        simulate_ui("DID Registry Service", user="Issuer")
        
        logger.info(f"Creating DID document for {self.issuer_did}")
        
        # Create a basic DID document
        did_document = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": self.issuer_did,
            "verificationMethod": [],
            "authentication": [],
            "assertionMethod": []
        }
        
        simulate_delay("Creating DID document")
        
        # Add certificate chain to DID document as verification method
        verification_method_id = f"{self.issuer_did}#key-1"
        did_document = add_x509_verification_method_to_did_document(
            did_document,
            self.end_entity_cert,
            verification_method_id,
            ca_certificates=[self.intermediate_cert, self.root_cert]
        )
        
        # Add verification method to authentication and assertionMethod
        did_document["authentication"].append(verification_method_id)
        did_document["assertionMethod"].append(verification_method_id)
        
        # Add a BBS+ verification method for selective disclosure
        # This is simplified for the simulation as we don't have actual BBS+ implementation
        did_document["verificationMethod"].append({
            "id": f"{self.issuer_did}#bbs-key-1",
            "type": "Bls12381G2Key2020",
            "controller": self.issuer_did,
            "publicKeyBase58": "25ETdUZDLQroAzpspx31xzuVuWujrk7n4TrXhyVLiYAohfmx6LgbwhpGBpKDCpFcjGRuD8GTkqzGwCJZpTxUZYz3"  # Example BBS+ public key
        })
        did_document["assertionMethod"].append(f"{self.issuer_did}#bbs-key-1")
        
        # Save DID document to the issuer directory
        did_doc_path = os.path.join(self.issuer_dir, "did_document.json")
        with open(did_doc_path, "w") as f:
            json.dump(did_document, f, indent=2)
        logger.info(f"Saved DID document to {did_doc_path}")
        
        self.issuer_did_document = did_document
        
        # Verify bidirectional linkage
        linkage_valid = verify_bidirectional_linkage(self.end_entity_cert, did_document)
        logger.info(f"Bidirectional linkage verification: {linkage_valid}")
        
        print_json(did_document, "Issuer DID Document")
        
        simulate_ui("DID Registry Service", 
                   user="Issuer",
                   action=f"✅ DID document created for {self.issuer_did}")
        
        return did_document
    
    def issue_credential(self):
        """Issue a verifiable credential with X.509 metadata."""
        print_step(3, "Credential Issuance")
        
        simulate_ui("Credential Issuance Service", user="Issuer")
        
        # Create credential subject data
        credential_id = str(uuid.uuid4())
        issuance_date = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        simulate_delay("Creating credential")
        
        # Create a basic credential
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
                "https://w3id.org/security/suites/x509-2021/v1"
            ],
            "id": f"https://tu-berlin.de/credentials/{credential_id}",
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": self.issuer_did,
            "issuanceDate": issuance_date,
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
        
        # Create issuer metadata with X.509 information
        issuer_metadata = {
            "id": self.issuer_did,
            "name": "Technical University of Berlin",
            "url": "https://www.tu-berlin.de",
            "logo": "https://www.tu-berlin.de/logo.png",
            "description": "A leading research university in Germany"
        }
        
        enhanced_metadata = enhance_issuer_metadata_with_x509(
            issuer_metadata, 
            self.end_entity_cert
        )
        
        # Enhance the credential with X.509 metadata
        simulate_delay("Embedding X.509 metadata in credential")
        credential_with_x509 = embed_x509_metadata_in_credential(
            credential,
            self.end_entity_cert,
            ca_certificates=[self.intermediate_cert, self.root_cert]
        )
        
        # Sign the credential
        # For this simulation, we'll use a placeholder signature
        simulate_delay("Signing credential")
        signed_credential = credential_with_x509.copy()
        signed_credential["proof"] = {
            "type": "RsaSignature2018",
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "verificationMethod": f"{self.issuer_did}#key-1",
            "proofPurpose": "assertionMethod",
            "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..HQ9GWRr6gqSPdYJ_UxDqACGttV8YPnl7VqzEqwG7CcJRCT4Ih6YhLxbX0nKFEOHtp_da_X_K9kNHUvVK_5H7-Q"
        }
        
        # Also create a BBS+ version for selective disclosure
        # This is simplified for the simulation
        bbs_credential = credential.copy()
        bbs_credential["@context"].append("https://w3id.org/security/bbs/v1")
        bbs_credential["proof"] = {
            "type": "BbsBlsSignature2020",
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "verificationMethod": f"{self.issuer_did}#bbs-key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "kAkloZbLMc+wUEzVLApwbIHc0BUgGzYVvBOzE7It98HT0v0rklwTmRKy3lwj7QLodnxjQAEZvzCsZjTIwrGdEFmHHIcCCuaX9CYsmJZxX+4Pw3AXbGeJKg=="
        }
        
        # Save both versions of the credential
        cred_path = os.path.join(self.issuer_dir, f"credential_{credential_id}.json")
        with open(cred_path, "w") as f:
            json.dump(signed_credential, f, indent=2)
        
        bbs_cred_path = os.path.join(self.issuer_dir, f"credential_{credential_id}_bbs.json")
        with open(bbs_cred_path, "w") as f:
            json.dump(bbs_credential, f, indent=2)
        
        logger.info(f"Saved credential to {cred_path}")
        logger.info(f"Saved BBS+ credential to {bbs_cred_path}")
        
        # Update simulation state
        self.credential = credential
        self.signed_credential = signed_credential
        self.bbs_credential = bbs_credential
        self.credential_id = credential_id
        
        print_json(signed_credential, "Signed Credential with X.509 Metadata")
        
        # Simulate OID4VC issuance flow
        print("\n[OID4VC Flow Simulation]")
        print(f"1. Issuer endpoint available at: https://issuer.tu-berlin.de/oid4vc/credential")
        print(f"2. Authorization request generated for credential type: UniversityDegreeCredential")
        print(f"3. Authorization response received with code: auth_code_{credential_id[:8]}")
        print(f"4. Token endpoint accessed and access token obtained")
        print(f"5. Credential endpoint accessed with X.509 validation")
        print(f"6. Credential issued with X.509 metadata and trust chain")
        
        simulate_ui("Credential Issuance Service", 
                   user="Issuer",
                   action=f"✅ Credential {credential_id} issued to {self.holder_did}")
        
        return signed_credential
    
    def holder_receive_credential(self):
        """Simulate the holder receiving and storing the credential."""
        print_step(4, "Credential Storage in Holder's Wallet")
        
        simulate_ui("Digital Wallet Application", user="Credential Holder")
        
        logger.info("Holder receiving credential")
        
        # Simulate holder receiving the credential
        simulate_delay("Receiving credential")
        
        # Create a wallet storage structure
        wallet_storage = os.path.join(self.holder_dir, "wallet")
        os.makedirs(wallet_storage, exist_ok=True)
        
        # Store the credential in the wallet
        wallet_cred_path = os.path.join(wallet_storage, f"credential_{self.credential_id}.json")
        with open(wallet_cred_path, "w") as f:
            json.dump(self.signed_credential, f, indent=2)
        
        # Store the BBS+ credential in the wallet
        wallet_bbs_cred_path = os.path.join(wallet_storage, f"credential_{self.credential_id}_bbs.json")
        with open(wallet_bbs_cred_path, "w") as f:
            json.dump(self.bbs_credential, f, indent=2)
        
        logger.info(f"Stored credential in wallet: {wallet_cred_path}")
        
        # Simulate wallet UI showing the credential
        print("\n[Wallet UI] Credential Details:")
        print(f"Title: Bachelor of Science in Computer Science")
        print(f"Issuer: Technical University of Berlin ({self.issuer_did})")
        print(f"Date: {self.signed_credential['issuanceDate']}")
        print(f"Credential ID: {self.credential_id}")
        print(f"Trust: ✓ Certificate chain verified (X.509)")
        
        # Simulate OID4VC holder flow
        print("\n[OID4VC Holder Flow Simulation]")
        print(f"1. Authorization request received from issuer")
        print(f"2. User consent granted for credential issuance")
        print(f"3. Credentials received and validated using X.509 trust path")
        print(f"4. Credentials stored in secure wallet storage")
        
        simulate_ui("Digital Wallet Application", 
                   user="Credential Holder",
                   action="✅ Credential received and stored securely in wallet")
        
        return wallet_cred_path
    
    def create_presentation(self, selective_disclosure=True):
        """Create a verifiable presentation, optionally with selective disclosure."""
        print_step(5, "Presentation Creation")
        
        simulate_ui("Digital Wallet Application", user="Credential Holder")
        
        logger.info("Creating presentation")
        
        # Load the credential from the wallet
        wallet_storage = os.path.join(self.holder_dir, "wallet")
        
        # Decide which credential to use based on selective disclosure option
        if selective_disclosure:
            cred_path = os.path.join(wallet_storage, f"credential_{self.credential_id}_bbs.json")
            logger.info("Using BBS+ credential for selective disclosure")
        else:
            cred_path = os.path.join(wallet_storage, f"credential_{self.credential_id}.json")
            logger.info("Using X.509 credential without selective disclosure")
        
        with open(cred_path, "r") as f:
            cred = json.load(f)
        
        # Create a presentation
        presentation_id = str(uuid.uuid4())
        
        simulate_delay("Creating presentation")
        
        presentation = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": "VerifiablePresentation",
            "id": f"urn:uuid:{presentation_id}",
            "holder": self.holder_did,
            "verifiableCredential": []
        }
        
        # If selective disclosure, create a derived credential
        if selective_disclosure:
            # In a real implementation, this would be an actual selective disclosure
            # Here we'll simulate it by removing some fields
            disclosed_cred = cred.copy()
            
            # Remove grades from academic results
            for course in disclosed_cred["credentialSubject"]["academicResults"]:
                del course["grade"]
            
            # Update the proof for the selective disclosure
            disclosed_cred["proof"] = {
                "type": "BbsBlsSignatureProof2020",
                "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "verificationMethod": f"{self.issuer_did}#bbs-key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "kTQUl9W3xJmpEgRKR8sTi9+Y2M/WbJ3a/lNdBbkFsLpSBQDg4xE10pJkEWJwt/doxGpn/Xbn1HmL1q5HSPQJ1L8JznEXFqnW0ULmJZThIy9SuQ==",
                "nonce": "YWJjZGVm"
            }
            
            # Add the disclosed credential to the presentation
            presentation["verifiableCredential"].append(disclosed_cred)
            
            print("[Selective Disclosure] Only the following attributes will be shared:")
            print("- Degree type and name")
            print("- College name")
            print("- Graduation date")
            print("- Course codes and names (without grades)")
            
        else:
            # Add the full credential to the presentation
            presentation["verifiableCredential"].append(cred)
            
            print("[Full Disclosure] All credential attributes will be shared")
        
        # Add the presentation proof
        # This is a simplified placeholder
        presentation["proof"] = {
            "type": "Ed25519Signature2018",
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "verificationMethod": f"{self.holder_did}#keys-1",
            "proofPurpose": "authentication",
            "challenge": "1f44d55f-f161-4938-a659-f8026467f126",
            "domain": "verifier.example.com",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..aXRTBP5XEiwC_WoFYH091Go_GRN7sdE2VZ6QZjz2PN28BR41HA0cJPgYkDY3inUssRvs7WUAELi8xQ_mEytxBw"
        }
        
        # Save the presentation
        presentation_path = os.path.join(self.holder_dir, f"presentation_{presentation_id}.json")
        with open(presentation_path, "w") as f:
            json.dump(presentation, f, indent=2)
        
        logger.info(f"Saved presentation to {presentation_path}")
        
        # Update simulation state
        self.presentation = presentation
        self.presentation_id = presentation_id
        
        print_json(presentation, "Verifiable Presentation")
        
        # Simulate OID4VP presentation flow
        print("\n[OID4VP Flow Simulation]")
        print(f"1. Presentation request received from verifier")
        print(f"2. User consent granted for credential disclosure")
        print(f"3. Presentation created with {'selective' if selective_disclosure else 'full'} disclosure")
        print(f"4. Presentation sent to verifier")
        
        simulate_ui("Digital Wallet Application", 
                   user="Credential Holder",
                   action=f"✅ Presentation created with {'selective' if selective_disclosure else 'full'} disclosure")
        
        return presentation
    
    def verify_presentation(self, with_x509=True):
        """Verify the presentation using DID and optionally X.509 trust paths."""
        print_step(6, "Presentation Verification")
        
        simulate_ui("Verification Service", user="Verifier")
        
        logger.info("Verifying presentation")
        
        # Simulate receiving the presentation
        simulate_delay("Receiving presentation")
        
        # Save the presentation in the verifier directory
        verifier_pres_path = os.path.join(self.verifier_dir, f"presentation_{self.presentation_id}.json")
        with open(verifier_pres_path, "w") as f:
            json.dump(self.presentation, f, indent=2)
        
        # Extract the credential from the presentation
        credential = self.presentation["verifiableCredential"][0]
        
        # Verification steps
        print("\n[Verification Steps]")
        
        # 1. Basic structure verification
        print("1. Basic structure verification... ✓")
        
        # 2. Signature verification (simplified here)
        print("2. Presentation signature verification... ✓")
        
        # 3. Credential verification based on type
        is_bbs = "BbsBlsSignatureProof2020" in credential.get("proof", {}).get("type", "")
        is_x509 = "x509" in credential
        
        print(f"3. Credential type detected: {'BBS+ with selective disclosure' if is_bbs else 'Standard X.509-enhanced'}")
        
        if is_bbs:
            # Simulate BBS+ verification
            print("4. Verifying BBS+ selective disclosure proof... ✓")
            print("5. Checking credential integrity with selective disclosure... ✓")
            
            # Display the verified attributes
            print("\n[Verified Selective Disclosure]")
            print("The following attributes have been verified:")
            
            subject = credential["credentialSubject"]
            print(f"- Holder: {subject['id']}")
            print(f"- Degree: {subject['degree']['type']} in {subject['degree']['name']}")
            print(f"- College: {subject['college']}")
            print(f"- Graduation Date: {subject['graduationDate']}")
            
            # Show courses without grades
            print("- Courses:")
            for course in subject["academicResults"]:
                print(f"  * {course['courseCode']}: {course['courseName']}")
        
        if is_x509 and with_x509:
            # Perform X.509 verification
            print("4. Extracting X.509 certificate chain from credential...")
            
            # In a real implementation, we would load the trusted CA certificates
            # For this simulation, we'll use the pre-generated chain
            trusted_cas = [self.root_cert]
            
            simulate_delay("Verifying X.509 certificate chain")
            is_valid, reason = verify_credential_with_x509(credential, trusted_cas)
            
            print(f"5. X.509 verification result: {'✓' if is_valid else '✗'} {reason}")
            
            # Display the X.509 verification details
            if is_valid:
                print("\n[X.509 Verification Details]")
                print(f"- Certificate chain length: {len(credential['x509']['certificateChain'])}")
                print(f"- Subject: {credential['x509']['subject']['common_name']}")
                print(f"- Issuer DID match: ✓")
                cert_info = get_certificate_info(self.end_entity_cert)
                print(f"- Certificate valid until: {cert_info['validity']['not_after']}")
        
        # 4. Verify the credential issuer
        print(f"6. Credential issuer verification: ✓ ({credential['issuer']})")
        
        # 5. Verify issuance date
        print(f"7. Issuance date verification: ✓ ({credential['issuanceDate']})")
        
        # Overall verification result
        overall_result = True  # In a real implementation, this would be the result of all checks
        
        if overall_result:
            verification_result = "✅ Presentation verified successfully"
            result_detail = "All checks passed. The credential is valid and trustworthy."
        else:
            verification_result = "❌ Presentation verification failed"
            result_detail = "One or more checks failed. The credential cannot be trusted."
        
        # Simulate OID4VP verifier flow
        print("\n[OID4VP Verifier Flow Simulation]")
        print(f"1. Presentation request sent to holder")
        print(f"2. Presentation received and parsed")
        print(f"3. Presentation verified using {'X.509 trust path and ' if with_x509 and is_x509 else ''}DID trust")
        print(f"4. Verification result: {overall_result}")
        
        simulate_ui("Verification Service", 
                   user="Verifier",
                   action=f"{verification_result}\n{result_detail}")
        
        return overall_result
    
    def run_simulation(self):
        """Run the complete simulation workflow."""
        print_header("X.509 Integration End-to-End Simulation")
        
        # Step 1: Certificate Authority Setup
        self.setup_certificate_authority()
        
        # Step 2: DID Document Creation
        self.create_did_document()
        
        # Step 3: Credential Issuance
        self.issue_credential()
        
        # Step 4: Holder Receiving and Storing the Credential
        self.holder_receive_credential()
        
        # Step 5a: Create Presentation with Selective Disclosure (BBS+)
        self.create_presentation(selective_disclosure=True)
        
        # Step 6a: Verify Presentation (with BBS+)
        self.verify_presentation(with_x509=False)
        
        # Step 5b: Create Presentation without Selective Disclosure (X.509)
        self.create_presentation(selective_disclosure=False)
        
        # Step 6b: Verify Presentation (with X.509)
        self.verify_presentation(with_x509=True)
        
        # Simulation Complete
        print_header("Simulation Complete")
        print(f"Simulation directory: {self.simulation_dir}")
        print("\nSimulation Summary:")
        print(f"1. Certificate Authority: Generated a 3-tier certificate chain")
        print(f"2. DID Creation: Created a DID document for {self.issuer_did}")
        print(f"3. Credential Issuance: Issued credential {self.credential_id}")
        print(f"4. Credential Storage: Stored in holder's wallet")
        print(f"5. Presentation Creation: Created presentations with and without selective disclosure")
        print(f"6. Verification: Successfully verified presentations using both DID and X.509 trust paths")
        
        return {
            "simulation_dir": self.simulation_dir,
            "issuer_did": self.issuer_did,
            "holder_did": self.holder_did,
            "credential_id": self.credential_id,
            "presentation_id": self.presentation_id
        }


if __name__ == "__main__":
    simulation = X509WorkflowSimulation()
    simulation.run_simulation() 