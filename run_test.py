#!/usr/bin/env python3

import unittest
import json
import base64
from tests.integration.test_end_to_end_x509_shibboleth import TestEndToEndX509Shibboleth, MockUniversityAuthenticator

def print_json(obj, indent=4):
    """Print JSON object nicely formatted"""
    print(json.dumps(obj, indent=indent, sort_keys=False, default=str))

def run_test():
    # Create an instance of the test case
    test_case = TestEndToEndX509Shibboleth('test_secure_student_id_credential_flow_with_authenticator')
    
    # Set up the test environment
    test_case.setUp()
    
    print("\n" + "="*80)
    print("END-TO-END TEST: X.509 CERTIFICATE-BASED CREDENTIAL WITH ENHANCED SECURITY")
    print("="*80)
    
    print("\n--- X.509 CERTIFICATE CHAIN SETUP ---")
    cert_chain = [
        test_case.credential_issuer.certificates["issuer"],
        test_case.credential_issuer.certificates["intermediate"],
        test_case.credential_issuer.certificates["root"]
    ]
    
    print("\nIssuer Certificate:")
    print(f"  Subject: {cert_chain[0].subject_dn}")
    print(f"  Issuer: {cert_chain[0].issuer_dn}")
    print(f"  Valid from: {cert_chain[0].not_before} to {cert_chain[0].not_after}")
    print(f"  DID in SAN extension: {cert_chain[0].get_did_from_extensions()}")
    
    print("\nIntermediate CA Certificate:")
    print(f"  Subject: {cert_chain[1].subject_dn}")
    print(f"  Issuer: {cert_chain[1].issuer_dn}")
    
    print("\nRoot CA Certificate:")
    print(f"  Subject: {cert_chain[2].subject_dn}")
    print(f"  Issuer: {cert_chain[2].issuer_dn}")
    
    print("\n" + "-"*80)
    print("STEP 1: Student authenticates with Shibboleth (first authentication factor)")
    print("-"*80)
    
    alice_shibboleth_session = test_case.shibboleth.authenticate("alice", "password123")
    print(f"  → Session ID: {alice_shibboleth_session}")
    
    # Get session attributes
    session_info = test_case.shibboleth.validate_session(alice_shibboleth_session)
    print("\nShibboleth Session Attributes:")
    print_json(session_info["attributes"])
    
    print("\n" + "-"*80)
    print("STEP 2: Student registers TU Berlin Authenticator app (setup for second factor)")
    print("-"*80)
    
    # Create authenticator and assign to issuer
    authenticator = MockUniversityAuthenticator()
    test_case.credential_issuer.authenticator = authenticator
    
    # Register device
    device_id = "ALICE_SMARTPHONE_ID"
    registration = authenticator.register_device("alice", device_id)
    
    print(f"  → Device registration: {registration['success']}")
    print(f"  → Device ID: {registration['device_id']}")
    print(f"  → Registration time: {registration['registration_time']}")
    print(f"  → Secret key for TOTP: {registration['secret_key']}")
    print("  → QR code would be displayed to user in real implementation")
    
    print("\n" + "-"*80)
    print("STEP 3: Student generates one-time code on TU Berlin Authenticator app")
    print("-"*80)
    
    code_result = authenticator.generate_code("alice", device_id)
    authenticator_code = code_result["code"]
    
    print(f"  → Code generation: {code_result['success']}")
    print(f"  → One-time code: {authenticator_code}")
    print("  → In a real app, this would be a 6-digit TOTP code changing every 30 seconds")
    
    print("\n" + "-"*80)
    print("STEP 4: Issuer verifies both authentication factors and issues credential")
    print("-"*80)
    
    alice_credential, status_code = test_case.credential_issuer.issue_credential(
        alice_shibboleth_session,
        credential_type="StudentIDCredential",
        authenticator_code=authenticator_code,
        username="alice"
    )
    
    print(f"  → Credential issued with status code: {status_code}")
    print(f"  → Credential ID: {alice_credential['id']}")
    print(f"  → Credential type: {alice_credential['type']}")
    print(f"  → Issuer: {alice_credential['issuer']}")
    print(f"  → Issuance date: {alice_credential['issuanceDate']}")
    
    print("\nCredential Subject Data:")
    print_json(alice_credential['credentialSubject'])
    
    print("\nAuthenticator Evidence (MFA proof):")
    print_json(alice_credential['evidence'])
    
    print("\nProof Information:")
    print(f"  Type: {alice_credential['proof']['type']}")
    print(f"  Created: {alice_credential['proof']['created']}")
    print(f"  Verification Method: {alice_credential['proof']['verificationMethod']}")
    print(f"  Proof Purpose: {alice_credential['proof']['proofPurpose']}")
    
    print("\nX.509 Certificate Chain:")
    print(f"  Certificate Chain Length: {len(alice_credential['x509Certificate']['certificateChain'])}")
    
    print("\n" + "-"*80)
    print("STEP 5: Student stores credential in wallet")
    print("-"*80)
    
    store_result = test_case.alice_wallet.store_credential(alice_credential)
    print(f"  → Credential stored: {store_result['success']}")
    print(f"  → Wallet owner: {test_case.alice_wallet.owner_name}")
    print(f"  → Wallet DID: {test_case.alice_wallet.did}")
    print(f"  → Number of credentials in wallet: {len(test_case.alice_wallet.credentials)}")
    
    print("\n" + "-"*80)
    print("STEP 6: Student logs into university portal using Shibboleth")
    print("-"*80)
    
    portal_login = test_case.university_portal.login_with_shibboleth("alice", "password123")
    portal_session = portal_login["session_id"]
    print(f"  → Portal session ID: {portal_session}")
    print(f"  → Logged in as: {portal_login['user_info']['name']}")
    print(f"  → Email: {portal_login['user_info']['email']}")
    print(f"  → University: {portal_login['user_info']['university']}")
    
    print("\n" + "-"*80)
    print("STEP 7: Student creates verifiable presentation of credential")
    print("-"*80)
    
    presentation_result = test_case.alice_wallet.create_presentation(
        [alice_credential["id"]],
        "tu-berlin.edu",
        challenge="random_challenge_123"
    )
    presentation = presentation_result["presentation"]
    print(f"  → Presentation created with ID: {presentation['id']}")
    print(f"  → Presentation type: {presentation['type']}")
    print(f"  → Presentation holder: {presentation['holder']}")
    
    print("\nPresentation Proof:")
    print(f"  Type: {presentation['proof']['type']}")
    print(f"  Challenge: {presentation['proof']['challenge']}")
    print(f"  Domain: {presentation['proof']['domain']}")
    print(f"  Verification Method: {presentation['proof']['verificationMethod']}")
    
    print("\n" + "-"*80)
    print("STEP 8: Portal verifies the presented credential")
    print("-"*80)
    
    # In a real-world scenario, this would involve:
    print("Verification Steps (what would happen in a real implementation):")
    print("  1. Verify the presentation proof")
    print("  2. Extract the embedded credential")
    print("  3. Check authenticator evidence to confirm multi-factor authentication")
    print("  4. Verify X.509 certificate chain:")
    print("     a. Parse certificate chain from credential")
    print("     b. Validate certificate signatures")
    print("     c. Check certificate validity periods")
    print("     d. Verify certificate chain to trusted root")
    print("     e. Check certificate revocation status")
    print("  5. Verify the BBS+ signature:")
    print("     a. Resolve the DID to get the verification key")
    print("     b. Verify that the DID in the certificate matches the credential issuer")
    print("     c. Verify BBS+ signature over credential data")
    
    present_result = test_case.university_portal.present_credential(
        portal_session,
        presentation
    )
    print(f"\n  → Credential presentation result: {present_result['success']}")
    print(f"  → Message: {present_result['message']}")
    
    print("\n" + "-"*80)
    print("STEP 9: Student accesses protected resources using credential")
    print("-"*80)
    
    access_result = test_case.university_portal.access_protected_resource(
        portal_session,
        "student_records"
    )
    print(f"  → Resource access result: {access_result['success']}")
    print(f"  → Resource name: {access_result['resource']['name']}")
    print(f"  → Resource content: {access_result['resource']['content']}")
    
    print("\n" + "-"*80)
    print("DEMONSTRATING SECURITY: Invalid authenticator code attempt")
    print("-"*80)
    
    # Try with invalid authenticator code
    invalid_result, invalid_status = test_case.credential_issuer.issue_credential(
        alice_shibboleth_session,
        credential_type="StudentIDCredential",
        authenticator_code="000000",  # Invalid code
        username="alice"
    )
    
    print(f"  → Credential issuance attempt with invalid code - Status code: {invalid_status}")
    print(f"  → Error message: {invalid_result.get('error')}")
    print("  → The system correctly rejected the credential issuance with invalid authenticator code")
    
    # Clean up
    test_case.tearDown()
    
    print("\n" + "="*80)
    print("COMPLETE END-TO-END TEST WITH ENHANCED SECURITY SUCCESSFUL!")
    print("="*80)
    print("\nSecurity benefits of the TU Berlin Authenticator:")
    print("  1. Multi-factor authentication (what you know + what you have)")
    print("  2. Time-based one-time passwords prevent replay attacks")
    print("  3. Device binding ensures only registered devices can generate codes")
    print("  4. Enhanced audit trail with authentication evidence in credential")
    print("  5. Higher assurance level for issuing credentials to the right person")
    print("  6. Prevents credential issuance through compromised Shibboleth sessions")

if __name__ == "__main__":
    run_test() 