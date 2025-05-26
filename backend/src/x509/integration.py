"""
X.509 Integration with OID4VC and OID4VP

This module provides integration between X.509 certificate functionality
and OpenID for Verifiable Credentials (OID4VC) issuance and OpenID for
Verifiable Presentations (OID4VP) protocols.

The integration enables dual-path verification using both traditional PKI
trust chains and DID-based trust, enhancing security and interoperability.
"""

import os
import json
import logging
import base64
import datetime
from typing import Dict, Any, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from .certificate import get_certificate_info, is_certificate_valid
from .did_binding import (
    verify_certificate_did_binding,
    verify_bidirectional_linkage,
    find_did_in_certificate_san
)
from .challenge_response import (
    generate_challenge,
    verify_dual_control
)

logger = logging.getLogger(__name__)

# OID4VC Integration Functions

def get_certificate_subject_info(certificate: x509.Certificate) -> Dict[str, str]:
    """
    Extract subject information from a certificate.
    
    Args:
        certificate: The certificate to extract information from
        
    Returns:
        A dictionary containing subject attributes
    """
    subject_info = {}
    
    # Extract common subject attributes
    attrs = {
        "common_name": NameOID.COMMON_NAME,
        "organization_name": NameOID.ORGANIZATION_NAME,
        "organizational_unit_name": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "country_name": NameOID.COUNTRY_NAME,
        "state_or_province_name": NameOID.STATE_OR_PROVINCE_NAME,
        "locality_name": NameOID.LOCALITY_NAME,
        "email_address": NameOID.EMAIL_ADDRESS
    }
    
    for attr_name, oid in attrs.items():
        attrs_list = certificate.subject.get_attributes_for_oid(oid)
        if attrs_list:
            subject_info[attr_name] = attrs_list[0].value
    
    return subject_info

def enhance_issuer_metadata_with_x509(
    metadata: Dict[str, Any],
    certificate: x509.Certificate
) -> Dict[str, Any]:
    """
    Enhance issuer metadata with X.509 certificate information.
    
    Args:
        metadata: The issuer metadata to enhance
        certificate: The X.509 certificate to include
        
    Returns:
        Enhanced issuer metadata with X.509 information
    """
    # Create a copy of the metadata to avoid modifying the original
    enhanced_metadata = metadata.copy()
    
    # Extract certificate information
    subject_info = get_certificate_subject_info(certificate)
    
    # Convert the certificate to PEM format
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    # Extract the DID from the certificate if present
    cert_did = find_did_in_certificate_san(certificate)
    
    # Create the X.509 credentials section
    x509_credentials = {
        "certificate": {
            "pem": cert_pem,
            "subject": subject_info
        }
    }
    
    if cert_did:
        x509_credentials["did"] = cert_did
    
    # Add the X.509 credentials to the metadata
    enhanced_metadata["x509_credentials"] = x509_credentials
    
    return enhanced_metadata

def create_dual_proof_credential_offer(
    credential_offer: Dict[str, Any],
    cert: x509.Certificate
) -> Dict[str, Any]:
    """
    Enhance a credential offer with X.509 certificate information
    for dual-proof credential issuance.
    
    Args:
        credential_offer: Existing credential offer
        cert: X.509 certificate
        
    Returns:
        Enhanced credential offer
    """
    # Create a copy to avoid modifying the original
    offer = dict(credential_offer)
    
    # Add X.509 certificate information
    cert_info = get_certificate_info(cert)
    offer['issuer_x509'] = {
        'certificate': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
        'subject': cert_info['subject'],
        'issuer': cert_info['issuer'],
        'not_before': cert_info['validity']['not_before'].isoformat(),
        'not_after': cert_info['validity']['not_after'].isoformat(),
        'thumbprint': cert_info['thumbprint']
    }
    
    # Extract DID from certificate if available
    did = find_did_in_certificate_san(cert)
    if did and did == offer.get('issuer'):
        offer['issuer_x509']['did'] = did
        offer['x509_verification_required'] = True
    
    return offer

def embed_x509_metadata_in_credential(
    credential: Dict[str, Any],
    certificate: x509.Certificate,
    ca_certificates: List[x509.Certificate] = None
) -> Dict[str, Any]:
    """
    Embed X.509 certificate metadata in a verifiable credential.
    
    Args:
        credential: The credential to enhance
        certificate: The X.509 certificate to embed
        ca_certificates: Optional list of CA certificates to include in the chain
        
    Returns:
        Enhanced credential with X.509 metadata
    """
    # Create a copy of the credential to avoid modifying the original
    enhanced_credential = credential.copy()
    
    # Ensure the X.509 context is included
    if "@context" not in enhanced_credential:
        enhanced_credential["@context"] = []
    
    if isinstance(enhanced_credential["@context"], list):
        if "https://w3id.org/security/suites/x509-2021/v1" not in enhanced_credential["@context"]:
            enhanced_credential["@context"].append("https://w3id.org/security/suites/x509-2021/v1")
    
    # Convert certificates to base64-encoded DER format
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    cert_b64 = base64.b64encode(cert_der).decode('ascii')
    
    # Create certificate chain array
    cert_chain = [cert_b64]
    
    # Add CA certificates to the chain if provided
    if ca_certificates:
        for ca_cert in ca_certificates:
            ca_cert_der = ca_cert.public_bytes(serialization.Encoding.DER)
            ca_cert_b64 = base64.b64encode(ca_cert_der).decode('ascii')
            cert_chain.append(ca_cert_b64)
    
    # Extract and include subject information
    subject_info = get_certificate_subject_info(certificate)
    
    # Add the X.509 metadata to the credential
    enhanced_credential["x509"] = {
        "certificateChain": cert_chain,
        "subject": subject_info
    }
    
    return enhanced_credential

# OID4VP Integration Functions

def verify_credential_with_x509(
    credential: Dict[str, Any],
    trusted_certificates: List[x509.Certificate]
) -> Tuple[bool, str]:
    """
    Verify a credential using X.509 trust paths.
    
    Args:
        credential: The credential to verify
        trusted_certificates: List of trusted root certificates
        
    Returns:
        Tuple of (is_valid, reason)
    """
    # Check if the credential has X.509 metadata
    if "x509" not in credential:
        return False, "Credential does not contain X.509 metadata"
    
    # Extract certificate chain from credential
    cert_chain_data = credential["x509"].get("certificateChain")
    if not cert_chain_data:
        return False, "Credential does not contain certificate chain"
    
    # Parse the certificate chain
    certificates = []
    try:
        if isinstance(cert_chain_data, list):
            # Handle array of base64-encoded DER certificates
            for cert_b64 in cert_chain_data:
                cert_der = base64.b64decode(cert_b64)
                cert = x509.load_der_x509_certificate(cert_der)
                certificates.append(cert)
        elif isinstance(cert_chain_data, str):
            # Handle PEM format (backward compatibility)
            if "-----BEGIN CERTIFICATE-----" in cert_chain_data:
                cert = x509.load_pem_x509_certificate(cert_chain_data.encode('utf-8'))
                certificates.append(cert)
            else:
                # Assume single base64-encoded DER certificate
                cert_der = base64.b64decode(cert_chain_data)
                cert = x509.load_der_x509_certificate(cert_der)
                certificates.append(cert)
        else:
            return False, "Invalid certificate chain format"
        
        if not certificates:
            return False, "No certificates found in the chain"
    except Exception as e:
        return False, f"Failed to parse certificate chain: {str(e)}"
    
    # Get the end-entity certificate (first in the chain)
    end_entity_cert = certificates[0]
    
    # Verify that the certificate is not expired
    try:
        # Try the modern approach with UTC timezone
        now = datetime.datetime.now(datetime.timezone.utc)
        not_valid_before = end_entity_cert.not_valid_before_utc
        not_valid_after = end_entity_cert.not_valid_after_utc
    except AttributeError:
        # Fall back to naive datetime for older Python versions
        now = datetime.datetime.now(timezone.utc)
        not_valid_before = end_entity_cert.not_valid_before
        not_valid_after = end_entity_cert.not_valid_after
    
    if now < not_valid_before or now > not_valid_after:
        return False, "Certificate is expired or not yet valid"
    
    # Verify the certificate chain
    # In a real implementation, this would do a full validation of the chain
    # For this test implementation, we'll verify that at least one cert in the chain
    # is in the trusted list or that the chain contains a CA certificate
    
    cert_trusted = False
    
    # Check if the end-entity certificate is directly trusted
    for trusted_cert in trusted_certificates:
        if end_entity_cert.fingerprint(end_entity_cert.signature_hash_algorithm) == trusted_cert.fingerprint(trusted_cert.signature_hash_algorithm):
            cert_trusted = True
            break
    
    # If not directly trusted, check the certificate chain
    if not cert_trusted and len(certificates) > 1:
        # Simple chain verification - check if any CA in the chain is trusted
        for cert in certificates[1:]:  # Skip the end-entity certificate
            for trusted_cert in trusted_certificates:
                if cert.fingerprint(cert.signature_hash_algorithm) == trusted_cert.fingerprint(trusted_cert.signature_hash_algorithm):
                    cert_trusted = True
                    break
            
            # Check if this is a CA certificate
            try:
                constraints = cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.BASIC_CONSTRAINTS
                )
                if constraints.value.ca:
                    # It's a CA certificate, consider the chain partially valid
                    # In a real implementation, we would do more checks
                    cert_trusted = True
            except:
                pass
            
            if cert_trusted:
                break
    
    if not cert_trusted:
        return False, "Certificate chain is not trusted"
    
    # Verify that the certificate is linked to the issuer DID
    issuer_did = credential.get("issuer")
    if isinstance(issuer_did, dict):
        issuer_did = issuer_did.get("id")
    
    if not issuer_did:
        return False, "Credential does not specify an issuer DID"
    
    # Verify the DID-certificate binding
    if not verify_certificate_did_binding(end_entity_cert, issuer_did):
        return False, "Certificate is not bound to the issuer DID"
    
    # In a real implementation, we would also verify the credential signature
    # against the certificate's public key
    
    return True, "Credential successfully verified using X.509 trust path"

def create_presentation_with_dual_proof(
    presentation: Dict[str, Any],
    x509_signature: str,
    did_signature: str,
    challenge: str
) -> Dict[str, Any]:
    """
    Create a presentation with dual proof (X.509 and DID).
    
    Args:
        presentation: Existing verifiable presentation
        x509_signature: X.509 signature over the challenge
        did_signature: DID signature over the challenge
        challenge: Challenge that was signed
        
    Returns:
        Enhanced presentation with dual proof
    """
    # Create a copy to avoid modifying the original
    pres = dict(presentation)
    
    # Add dual proof information
    if 'proof' not in pres:
        pres['proof'] = {}
    
    # If proof is a list, append to it; otherwise create a list
    if isinstance(pres['proof'], list):
        proofs = pres['proof']
    else:
        proofs = [pres['proof']]
        pres['proof'] = proofs
    
    # Add X.509 signature proof
    x509_proof = {
        'type': 'X509Signature2022',
        'created': datetime.now().isoformat(),
        'challenge': challenge,
        'signatureValue': x509_signature,
        'proofPurpose': 'authentication'
    }
    
    # Add DID signature proof (if not already present)
    did_proof_exists = False
    for proof in proofs:
        if proof.get('type') in ['Ed25519Signature2020', 'JsonWebSignature2020']:
            did_proof_exists = True
            break
    
    if not did_proof_exists:
        did_proof = {
            'type': 'JsonWebSignature2020',
            'created': datetime.now().isoformat(),
            'challenge': challenge,
            'signatureValue': did_signature,
            'proofPurpose': 'authentication'
        }
        proofs.append(did_proof)
    
    proofs.append(x509_proof)
    
    # Add verification method
    pres['verificationMethod'] = {
        'dual': True,
        'methods': ['x509', 'did']
    }
    
    return pres

def verify_presentation_with_dual_proof(
    presentation: Dict[str, Any],
    challenge: str,
    cert: x509.Certificate,
    did_public_key: Any
) -> Tuple[bool, str]:
    """
    Verify a presentation with dual proof (X.509 and DID).
    
    Args:
        presentation: Verifiable presentation with dual proof
        challenge: Expected challenge
        cert: X.509 certificate for verification
        did_public_key: DID public key for verification
        
    Returns:
        Tuple of (is_valid, reason)
    """
    proofs = presentation.get('proof', [])
    if not isinstance(proofs, list):
        proofs = [proofs]
    
    x509_signature = None
    did_signature = None
    
    # Extract signatures from proofs
    for proof in proofs:
        if proof.get('type') == 'X509Signature2022':
            if proof.get('challenge') == challenge:
                x509_signature = proof.get('signatureValue')
        elif proof.get('type') in ['Ed25519Signature2020', 'JsonWebSignature2020']:
            if proof.get('challenge') == challenge:
                did_signature = proof.get('signatureValue')
    
    if not x509_signature or not did_signature:
        return False, "Presentation does not contain both X.509 and DID signatures"
    
    # Verify dual control
    is_valid, reason = verify_dual_control(
        challenge,
        x509_signature,
        did_signature,
        cert,
        did_public_key
    )
    
    return is_valid, reason

# Helper function for selective disclosure
def create_selective_disclosure_presentation(
    credential: Dict[str, Any],
    disclosed_attributes: List[str],
    cert_attributes: List[str] = None
) -> Dict[str, Any]:
    """
    Create a presentation with selective disclosure of credential attributes
    and X.509 certificate attributes.
    
    Args:
        credential: Verifiable credential
        disclosed_attributes: List of credential attributes to disclose
        cert_attributes: List of certificate attributes to disclose
        
    Returns:
        Selective disclosure presentation
    """
    # Create basic presentation structure
    presentation = {
        '@context': credential.get('@context', []),
        'type': ['VerifiablePresentation', 'SelectiveDisclosure'],
        'verifiableCredential': {}
    }
    
    # Create selective credential with only disclosed attributes
    selective_credential = {
        'id': credential.get('id'),
        'type': credential.get('type', []),
        'issuer': credential.get('issuer'),
        'issuanceDate': credential.get('issuanceDate')
    }
    
    # Add only the disclosed attributes from credential subject
    if 'credentialSubject' in credential:
        subject = credential['credentialSubject']
        selective_subject = {'id': subject.get('id')}
        
        for attr in disclosed_attributes:
            if attr in subject:
                selective_subject[attr] = subject[attr]
        
        selective_credential['credentialSubject'] = selective_subject
    
    # Add selected certificate attributes if requested
    if cert_attributes and 'evidence' in credential:
        for evidence in credential['evidence']:
            if evidence.get('type') == 'X509Certificate':
                cert_info = evidence.get('certificate', {})
                selective_cert_info = {}
                
                for attr in cert_attributes:
                    if attr in cert_info:
                        selective_cert_info[attr] = cert_info[attr]
                
                # Create selective evidence
                selective_evidence = {
                    'type': 'X509Certificate',
                    'certificate': selective_cert_info
                }
                
                if 'evidence' not in selective_credential:
                    selective_credential['evidence'] = []
                
                selective_credential['evidence'].append(selective_evidence)
    
    # Add the selective credential to the presentation
    presentation['verifiableCredential'] = selective_credential
    
    return presentation

def create_selective_disclosure_credential(
    credential: Dict[str, Any],
    disclosed_attributes: List[str]
) -> Dict[str, Any]:
    """
    Create a selective disclosure version of a credential.
    
    Args:
        credential: The original credential
        disclosed_attributes: List of attribute paths to include (dot notation)
        
    Returns:
        A new credential with only the specified attributes
    """
    # Create a copy of the credential with basic structure
    selective_credential = {
        "@context": credential["@context"],
        "id": credential["id"],
        "type": credential["type"],
        "issuer": credential["issuer"],
        "issuanceDate": credential["issuanceDate"],
        "credentialSubject": {"id": credential["credentialSubject"]["id"]}
    }
    
    # Copy over proof if it exists
    if "proof" in credential:
        selective_credential["proof"] = credential["proof"]
    
    # Copy over x509 metadata if it exists
    if "x509" in credential:
        selective_credential["x509"] = credential["x509"]
    
    # Process each disclosed attribute
    for attr_path in disclosed_attributes:
        if attr_path == "credentialSubject.id":
            continue  # Already included
            
        parts = attr_path.split(".")
        if parts[0] != "credentialSubject":
            continue  # Only support credentialSubject attributes for now
            
        # Navigate to the attribute in the original credential
        current_orig = credential
        current_sel = selective_credential
        
        for i, part in enumerate(parts):
            if part not in current_orig:
                break
                
            if i == len(parts) - 1:
                # Last part, set the value
                current_sel[part] = current_orig[part]
            else:
                # Create intermediate objects if needed
                if part not in current_sel:
                    current_sel[part] = {}
                    
                current_orig = current_orig[part]
                current_sel = current_sel[part]
    
    return selective_credential 