"""
Credential Status List Implementation

This module implements a status list for verifiable credentials based on the
StatusList2021 specification, with support for active, revoked, and suspended states.
"""

import os
import json
import base64
import time
import logging
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime, timedelta, timezone
from flask import current_app, jsonify
import jwt

from ..models import VC_validity, StatusList
from .. import db

logger = logging.getLogger(__name__)

# Constants for status purposes and states
STATUS_PURPOSE_REVOCATION = "revocation"
STATUS_PURPOSE_SUSPENSION = "suspension"

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"
STATUS_SUSPENDED = "suspended"

# We'll use a simple bitmap implementation for the status list
DEFAULT_STATUS_LIST_LENGTH = 100000  # Max number of entries in a status list


def create_status_list_credential(purpose: str) -> Dict[str, Any]:
    """
    Create a status list credential containing a bitmap for tracking credential statuses.
    
    Args:
        purpose: Purpose of the status list ("revocation" or "suspension")
        
    Returns:
        Status list credential as a dictionary
    """
    # Check if a status list already exists for this purpose
    status_list = StatusList.query.filter_by(purpose=purpose).first()
    
    if not status_list:
        # Create a new status list with all bits set to 0 (not revoked/suspended)
        # We'll use a simple bitmap stored as base64
        bitmap = bytearray([0] * (DEFAULT_STATUS_LIST_LENGTH // 8 + (1 if DEFAULT_STATUS_LIST_LENGTH % 8 > 0 else 0)))
        encoded_list = base64.b64encode(bitmap).decode('utf-8')
        
        # Create a status list credential
        list_id = f"urn:uuid:{os.urandom(16).hex()}"
        now = datetime.now(timezone.utc)
        
        status_list_credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc/status-list/2021/v1"
            ],
            "id": list_id,
            "type": ["VerifiableCredential", "StatusList2021Credential"],
            "issuer": current_app.config.get("ISSUER_DID", "did:example:issuer"),
            "issuanceDate": now.isoformat() + "Z",
            "validFrom": now.isoformat() + "Z",
            "validUntil": (now + timedelta(days=365)).isoformat() + "Z",
            "credentialSubject": {
                "id": f"{current_app.config['SERVER_URL']}/validate/statuslist/{purpose}",
                "type": "StatusList2021",
                "statusPurpose": purpose,
                "encodedList": encoded_list
            }
        }
        
        # Save to database
        new_status_list = StatusList(
            id=list_id,
            purpose=purpose,
            encoded_list=encoded_list,
            created_at=now,
            updated_at=now,
            credential=status_list_credential
        )
        db.session.add(new_status_list)
        db.session.commit()
        
        logger.info(f"Created new status list credential for purpose: {purpose}")
        return status_list_credential
    else:
        # Return existing status list credential
        logger.info(f"Using existing status list credential for purpose: {purpose}")
        return status_list.credential


def get_status_list_credential(purpose: str) -> Dict[str, Any]:
    """
    Get the current status list credential for a specific purpose.
    
    Args:
        purpose: Purpose of the status list ("revocation" or "suspension")
        
    Returns:
        Status list credential as a dictionary
    """
    status_list = StatusList.query.filter_by(purpose=purpose).first()
    
    if not status_list:
        # Create a new status list if none exists
        return create_status_list_credential(purpose)
    
    return status_list.credential


def set_credential_status(
    credential_id: str, 
    status: str,
    purpose: str = STATUS_PURPOSE_REVOCATION
) -> bool:
    """
    Set the status of a credential in the appropriate status list.
    
    Args:
        credential_id: Identifier of the credential
        status: New status (active, revoked, suspended)
        purpose: Purpose of the status change (revocation or suspension)
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Find the credential in our database
        credential_entry = VC_validity.query.filter_by(identifier=credential_id).first()
        if not credential_entry:
            logger.warning(f"Credential not found: {credential_id}")
            return False
        
        # Get the status index from the credential
        status_index = credential_entry.status_index
        
        # If no status index is assigned, assign one
        if status_index is None:
            # Count existing entries to determine the next index
            count = VC_validity.query.count()
            status_index = count
            credential_entry.status_index = status_index
        
        # Get the appropriate status list
        status_list = StatusList.query.filter_by(purpose=purpose).first()
        if not status_list:
            # Create the status list if it doesn't exist
            create_status_list_credential(purpose)
            status_list = StatusList.query.filter_by(purpose=purpose).first()
        
        # Decode the bitmap
        bitmap = bytearray(base64.b64decode(status_list.encoded_list))
        
        # Calculate byte and bit position
        byte_pos = status_index // 8
        bit_pos = status_index % 8
        
        # Ensure the bitmap is large enough
        if byte_pos >= len(bitmap):
            # Extend the bitmap if needed
            bitmap.extend([0] * (byte_pos - len(bitmap) + 1))
        
        # Set or clear the bit based on the requested status
        if status == STATUS_ACTIVE:
            # Clear the bit (set to 0) for active status
            bitmap[byte_pos] &= ~(1 << bit_pos)
            credential_entry.validity = True
        else:
            # Set the bit (set to 1) for revoked or suspended status
            bitmap[byte_pos] |= (1 << bit_pos)
            credential_entry.validity = False
        
        # Update the credential status in our database
        credential_entry.status = status
        
        # Re-encode the bitmap and update the status list
        status_list.encoded_list = base64.b64encode(bitmap).decode('utf-8')
        status_list.updated_at = datetime.now(timezone.utc)
        
        # Update the credentialSubject in the credential
        status_list.credential["credentialSubject"]["encodedList"] = status_list.encoded_list
        
        db.session.commit()
        logger.info(f"Updated status for credential {credential_id} to {status}")
        
        return True
    except Exception as e:
        logger.error(f"Error setting credential status: {str(e)}")
        db.session.rollback()
        return False


def check_credential_status(
    credential_id: str,
    status_index: int,
    purpose: str = STATUS_PURPOSE_REVOCATION
) -> Tuple[bool, str]:
    """
    Check the status of a credential in the status list.
    
    Args:
        credential_id: Identifier of the credential
        status_index: Index in the status list
        purpose: Purpose of the status (revocation or suspension)
        
    Returns:
        Tuple of (is_active, status_string)
    """
    try:
        # Get the status list
        status_list = StatusList.query.filter_by(purpose=purpose).first()
        if not status_list:
            logger.warning(f"No status list found for purpose: {purpose}")
            return True, STATUS_ACTIVE  # Default to active if no status list exists
        
        # Decode the bitmap
        bitmap = bytearray(base64.b64decode(status_list.encoded_list))
        
        # Check if the status index is within bounds
        if status_index >= len(bitmap) * 8:
            logger.warning(f"Status index {status_index} out of bounds")
            return True, STATUS_ACTIVE  # Default to active if index is out of bounds
        
        # Calculate byte and bit position
        byte_pos = status_index // 8
        bit_pos = status_index % 8
        
        # Check the bit
        is_bit_set = (bitmap[byte_pos] & (1 << bit_pos)) != 0
        
        if purpose == STATUS_PURPOSE_REVOCATION:
            if is_bit_set:
                return False, STATUS_REVOKED
            else:
                return True, STATUS_ACTIVE
        elif purpose == STATUS_PURPOSE_SUSPENSION:
            if is_bit_set:
                return False, STATUS_SUSPENDED
            else:
                return True, STATUS_ACTIVE
    
    except Exception as e:
        logger.error(f"Error checking credential status: {str(e)}")
    
    # Default to active in case of errors
    return True, STATUS_ACTIVE


def generate_credential_status(credential_id: str) -> Dict[str, Any]:
    """
    Generate the credentialStatus object for inclusion in a verifiable credential.
    
    Args:
        credential_id: Identifier for the credential
        
    Returns:
        Dictionary containing the credentialStatus object
    """
    # Assign a status index for this credential
    count = VC_validity.query.count()
    status_index = count
    
    # Ensure the status list exists
    status_list_credential = get_status_list_credential(STATUS_PURPOSE_REVOCATION)
    
    server_url = current_app.config.get("SERVER_URL", "http://localhost:5000")
    
    # Create the status object
    credential_status = {
        "id": f"{server_url}/validate/status/{credential_id}",
        "type": "StatusList2021Entry",
        "statusPurpose": STATUS_PURPOSE_REVOCATION,
        "statusListIndex": str(status_index),
        "statusListCredential": f"{server_url}/validate/statuslist"
    }
    
    return credential_status 