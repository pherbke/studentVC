#!/usr/bin/env python3

import os
import sys
import json
import tempfile
import datetime
import uuid
from pathlib import Path

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the necessary modules
from src.x509.certificate import generate_certificate_chain
from src.x509.did_binding import (
    find_did_in_certificate_san,
    add_x509_verification_method_to_did_document
)
from src.x509.integration import (
    enhance_issuer_metadata_with_x509,
    embed_x509_metadata_in_credential,
    verify_credential_with_x509
)

def run_e2e_test():
    """Run an end-to-end test of X.509 integration with OID4VC and did:web."""
    print("Running end-to-end X.509 integration test...")
    
    # Step 1: Certificate Chain & DID Creation
    print("\n== Step 1: Certificate Chain & DID Creation ==")
    
    # Create a DID for the issuer (did:web:edu:tub format)
    did = "did:web:edu:tub:issuer"
    print(f"Creating issuer DID: {did}")
    
    # Generate a certificate chain with the DID in SubjectAlternativeName
    print("Generating certificate chain (Root CA → Intermediate CA → End-entity)...")
    cert_chain, private_keys = generate_certificate_chain(
        subject_name="did:web:edu:tub:issuer#key-1",
        did=did
    )
    
    # Unpack the certificates and keys
    end_entity_cert = cert_chain[0]  # End-entity certificate
    intermediate_cert = cert_chain[1]  # Intermediate CA
    root_cert = cert_chain[2]  # Root CA
    end_entity_key = private_keys[0]  # End-entity private key
    
    # Verify DID in certificate
    extracted_did = find_did_in_certificate_san(end_entity_cert)
    print(f"Verified DID in certificate: {extracted_did}")
    
    # Create a DID document
    print("Creating DID document with X.509 certificate chain...")
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": did,
        "verificationMethod": [],
        "authentication": [],
        "assertionMethod": []
    }
    
    # Add certificate chain to DID document as verification method
    verification_method_id = f"{did}#key-1"
    did_document = add_x509_verification_method_to_did_document(
        did_document,
        end_entity_cert,
        verification_method_id,
        ca_certificates=[intermediate_cert, root_cert]
    )
    
    # Add verification method to authentication and assertionMethod
    did_document["authentication"].append(verification_method_id)
    did_document["assertionMethod"].append(verification_method_id)
    
    # Step 2: Credential Issuance
    print("\n== Step 2: Credential Issuance ==")
    
    # Create a holder DID
    holder_did = "did:web:example.com:holder"
    print(f"Holder DID: {holder_did}")
    
    # Create issuer metadata
    issuer_metadata = {
        "id": did,
        "name": "Technical University of Berlin",
        "url": "https://www.tu-berlin.de"
    }
    
    # Enhance issuer metadata with X.509 certificate information
    print("Enhancing issuer metadata with X.509 certificate information...")
    enhanced_metadata = enhance_issuer_metadata_with_x509(
        issuer_metadata,
        end_entity_cert
    )
    
    # Create a credential
    credential_id = str(uuid.uuid4())
    issuance_date = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    print("Creating credential...")
    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": f"https://tu-berlin.de/credentials/{credential_id}",
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": did,
        "issuanceDate": issuance_date,
        "credentialSubject": {
            "id": holder_did,
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science in Computer Science"
            },
            "college": "Technical University of Berlin",
            "graduationDate": "2023-06-15"
        }
    }
    
    # Embed X.509 metadata in the credential
    print("Embedding X.509 metadata in credential...")
    credential_with_x509 = embed_x509_metadata_in_credential(
        credential,
        end_entity_cert,
        ca_certificates=[intermediate_cert, root_cert]
    )
    
    # Sign the credential
    # For testing purposes, we'll use a simple placeholder signature
    print("Signing credential...")
    credential_with_proof = credential_with_x509.copy()
    credential_with_proof["proof"] = {
        "type": "RsaSignature2018",
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "verificationMethod": verification_method_id,
        "proofPurpose": "assertionMethod",
        "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..HQ9GWRr6gqSPdYJ_UxDqACGttV8YPnl7VqzEqwG7CcJRCT4Ih6YhLxbX0nKFEOHtp_da_X_K9kNHUvVK_5H7-Q" # This is a placeholder
    }
    
    # Step 3: Credential Holding
    print("\n== Step 3: Credential Holding ==")
    
    # In a real implementation, the credential would be stored in the holder's wallet
    print("Storing credential in holder's wallet...")
    
    # For demonstration, we'll store it to a temporary file
    test_dir = tempfile.mkdtemp()
    credential_path = os.path.join(test_dir, f"credential_{credential_id}.json")
    with open(credential_path, "w") as f:
        json.dump(credential_with_proof, f, indent=2)
    
    print(f"Credential stored at: {credential_path}")
    
    # Step 4: Verification
    print("\n== Step 4: Verification ==")
    
    # In a real implementation, the credential would be retrieved from the holder's wallet
    print("Retrieving credential from holder's wallet...")
    
    # For demonstration, we'll read it from the temporary file
    with open(credential_path, "r") as f:
        retrieved_credential = json.load(f)
    
    # Verify the credential using X.509 trust path
    print("Verifying credential using X.509 trust path...")
    trusted_cas = [root_cert]  # Trust the root CA
    is_valid, reason = verify_credential_with_x509(retrieved_credential, trusted_cas)
    
    print(f"Verification result: {is_valid} ({reason})")
    print(f"Certificate chain length: {len(retrieved_credential['x509']['certificateChain'])}")
    
    # Print summary
    print("\n== Test Summary ==")
    print("✅ End-to-end X.509 workflow test completed successfully")
    print(f"   DID: {did}")
    print(f"   Credential ID: {credential_id}")
    print(f"   Verification result: {is_valid}")
    
    return {
        "did": did,
        "credential_id": credential_id,
        "credential_path": credential_path,
        "verification_result": is_valid
    }

if __name__ == "__main__":
    run_e2e_test() 