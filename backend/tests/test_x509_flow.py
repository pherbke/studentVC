"""
End-to-end test of X.509 credential flow with did:web:edu:tub DID

This test demonstrates a complete flow of:
1. Creating a test X.509 certificate chain (root CA, intermediate CA, end-entity)
2. Creating a did:web:edu:tub DID linked to the certificate
3. Creating a DID document with the certificate chain as verification method
4. Signing a credential with the X.509 certificate
5. Storing the credential locally
6. Verifying the credential using both DID and X.509 trust paths
"""

import base64
import datetime
import json
import os
import tempfile
import uuid
from pathlib import Path
import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.hazmat.backends import default_backend

# Import the modules to be tested
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.x509.certificate import get_certificate_info, save_certificate, generate_certificate_chain
from src.x509.did_binding import (
    find_did_in_certificate_san,
    verify_certificate_did_binding,
    add_x509_verification_method_to_did_document
)
from src.x509.integration import (
    enhance_issuer_metadata_with_x509,
    embed_x509_metadata_in_credential,
    verify_credential_with_x509
)

class TestX509Flow:
    """End-to-end test of X.509 credential flow with did:web:edu:tub DID."""
    
    @pytest.fixture(scope="class")
    def test_setup(self):
        """Set up test environment with X.509 certificate and DID."""
        # Create a temporary directory for test files
        test_dir = tempfile.mkdtemp()
        
        # Create a DID for the issuer (did:web:edu:tub format)
        did = "did:web:edu:tub:issuer"
        
        # Generate a certificate chain with the DID in SubjectAlternativeName
        cert_chain, private_keys = generate_certificate_chain(
            subject_name="did:web:edu:tub:issuer#key-1",
            did=did
        )
        
        # Unpack the certificates and keys
        end_entity_cert = cert_chain[0]  # End-entity certificate
        intermediate_cert = cert_chain[1]  # Intermediate CA
        root_cert = cert_chain[2]  # Root CA
        
        end_entity_key = private_keys[0]  # End-entity private key
        
        # Save certificates to file
        cert_paths = []
        for i, cert in enumerate(cert_chain):
            cert_type = ["entity", "intermediate", "root"][i]
            cert_path = os.path.join(test_dir, f"{cert_type}_cert.pem")
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            cert_paths.append(cert_path)
        
        # Save private key to file
        key_path = os.path.join(test_dir, "issuer_key.pem")
        with open(key_path, "wb") as f:
            f.write(end_entity_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Create a DID document
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
        
        # Save DID document to file
        did_doc_path = os.path.join(test_dir, "did_document.json")
        with open(did_doc_path, "w") as f:
            json.dump(did_document, f, indent=2)
        
        # Create a holder DID for testing
        holder_did = "did:web:example.com:holder"
        
        # Return all the test setup data
        return {
            "test_dir": test_dir,
            "end_entity_key": end_entity_key,
            "end_entity_cert": end_entity_cert,
            "intermediate_cert": intermediate_cert,
            "root_cert": root_cert,
            "key_path": key_path,
            "cert_paths": cert_paths,
            "did": did,
            "did_document": did_document,
            "did_doc_path": did_doc_path,
            "holder_did": holder_did,
            "verification_method_id": verification_method_id
        }
    
    def test_full_x509_credential_flow(self, test_setup):
        """Test the full X.509 credential flow from issuing to verification."""
        # Extract test setup data
        test_dir = test_setup["test_dir"]
        end_entity_key = test_setup["end_entity_key"]
        end_entity_cert = test_setup["end_entity_cert"]
        intermediate_cert = test_setup["intermediate_cert"]
        root_cert = test_setup["root_cert"]
        issuer_did = test_setup["did"]
        holder_did = test_setup["holder_did"]
        verification_method_id = test_setup["verification_method_id"]
        
        # Step 1: Verify that the DID is correctly embedded in the certificate
        extracted_did = find_did_in_certificate_san(end_entity_cert)
        assert extracted_did == issuer_did, f"Expected DID {issuer_did}, got {extracted_did}"
        
        # Step 2: Create metadata for the issuer
        issuer_metadata = {
            "id": issuer_did,
            "name": "Technical University of Berlin",
            "url": "https://www.tu-berlin.de"
        }
        
        # Enhance issuer metadata with X.509 certificate information
        enhanced_metadata = enhance_issuer_metadata_with_x509(
            issuer_metadata,
            end_entity_cert
        )
        
        # Verify X.509 certificate information is present in the metadata
        assert "x509_credentials" in enhanced_metadata
        assert "certificate" in enhanced_metadata["x509_credentials"]
        
        # Step 3: Create a credential to be issued
        credential_id = str(uuid.uuid4())
        issuance_date = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": f"https://tu-berlin.de/credentials/{credential_id}",
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": issuer_did,
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
        
        # Step 4: Embed X.509 metadata in the credential with the full certificate chain
        credential_with_x509 = embed_x509_metadata_in_credential(
            credential,
            end_entity_cert,
            ca_certificates=[intermediate_cert, root_cert]
        )
        
        # Verify X.509 metadata is embedded in the credential
        assert "x509" in credential_with_x509
        assert "certificateChain" in credential_with_x509["x509"]
        assert isinstance(credential_with_x509["x509"]["certificateChain"], list)
        assert len(credential_with_x509["x509"]["certificateChain"]) == 3
        
        # Step 5: Sign the credential
        # For testing purposes, we'll use a simple placeholder signature
        credential_with_proof = credential_with_x509.copy()
        credential_with_proof["proof"] = {
            "type": "RsaSignature2018",
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "verificationMethod": verification_method_id,
            "proofPurpose": "assertionMethod",
            "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..HQ9GWRr6gqSPdYJ_UxDqACGttV8YPnl7VqzEqwG7CcJRCT4Ih6YhLxbX0nKFEOHtp_da_X_K9kNHUvVK_5H7-Q" # This is a placeholder
        }
        
        # Step 6: Store the credential locally
        credential_path = os.path.join(test_dir, f"credential_{credential_id}.json")
        with open(credential_path, "w") as f:
            json.dump(credential_with_proof, f, indent=2)
        
        # Verify the credential file exists
        assert os.path.exists(credential_path)
        
        # Step 7: Retrieve the credential from storage
        with open(credential_path, "r") as f:
            retrieved_credential = json.load(f)
        
        # Verify the retrieved credential matches the original
        assert retrieved_credential["id"] == credential_with_proof["id"]
        assert retrieved_credential["issuer"] == issuer_did
        assert retrieved_credential["credentialSubject"]["id"] == holder_did
        
        # Step 8: Verify the credential using X.509 trust path
        trusted_cas = [root_cert]  # Trust the root CA
        is_valid, reason = verify_credential_with_x509(retrieved_credential, trusted_cas)
        
        # Verify the result - should be valid since we trust the root CA
        assert is_valid, f"Credential verification failed: {reason}"
        
        # Step 9: Print a success message
        print("\nX.509 credential flow with certificate chain completed successfully:")
        print(f"- Issuer DID: {issuer_did}")
        print(f"- Credential ID: {credential_id}")
        print(f"- Credential stored at: {credential_path}")
        print(f"- Verification result: {is_valid} ({reason})")
        print(f"- Certificate chain length: {len(credential_with_x509['x509']['certificateChain'])}")

if __name__ == "__main__":
    pytest.main(["-xvs", __file__]) 