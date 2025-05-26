from flask import Blueprint, render_template, request, redirect, jsonify, current_app
from logging import getLogger
from ..models import VC_validity, StatusList
from .. import db
import json
from datetime import datetime
from .status_list import (
    get_status_list_credential,
    set_credential_status,
    check_credential_status,
    STATUS_ACTIVE,
    STATUS_REVOKED,
    STATUS_SUSPENDED,
    STATUS_PURPOSE_REVOCATION,
    STATUS_PURPOSE_SUSPENSION
)


validate = Blueprint('validate', __name__)
logger = getLogger("LOGGER")


@validate.route('/', methods=['GET', 'POST'])
def revokation():
    if request.method == "POST":
        identifier = request.form.get('identifier')
        action = request.form.get('action', 'toggle')
        
        if action == 'toggle':
            # Legacy toggle behavior
            entry = VC_validity.query.filter_by(identifier=identifier).first()
            if entry:
                entry.validity = not entry.validity
                entry.status = STATUS_ACTIVE if entry.validity else STATUS_REVOKED
                db.session.commit()
                logger.info(f"Toggled credential with identifier: {identifier}")
            else:
                logger.warning(
                    f"Attempted to revoke non-existent credential with identifier: {identifier}")
        else:
            # New status-based actions
            status = None
            if action == 'revoke':
                status = STATUS_REVOKED
            elif action == 'suspend':
                status = STATUS_SUSPENDED
            elif action == 'activate':
                status = STATUS_ACTIVE
                
            if status:
                purpose = STATUS_PURPOSE_REVOCATION
                if status == STATUS_SUSPENDED:
                    purpose = STATUS_PURPOSE_SUSPENSION
                    
                success = set_credential_status(identifier, status, purpose)
                if success:
                    logger.info(f"Set credential {identifier} status to {status}")
                else:
                    logger.warning(f"Failed to set credential {identifier} status to {status}")

    # get all credential statuses
    credentials = VC_validity.query.all()
    if not credentials:
        return render_template("validate.html", credentials=[])

    presentation_credentials = []
    for credential in credentials:
        view = {
            "firstName": credential.credential_data["vc"]["credentialSubject"]["firstName"],
            "lastName": credential.credential_data["vc"]["credentialSubject"]["lastName"],
            "studentId": credential.credential_data["vc"]["credentialSubject"]["studentId"],
        }
        view = json.dumps(view, indent=4)
        data = {
            "identifier": credential.identifier,
            "valid": credential.validity,
            "status": credential.status or STATUS_ACTIVE,
            "view": view,
            "status_index": credential.status_index
        }
        presentation_credentials.append(data)

    logger.debug(f"Credentials: {presentation_credentials}")
    return render_template("validate.html", credentials=presentation_credentials)


@validate.route('/isvalid/<string:identifier>', methods=['GET', 'POST'])
def is_valid(identifier):
    logger.info(
        f"Checking validity of credential with identifier: {identifier}")
    entry = VC_validity.query.filter_by(identifier=identifier).first()
    if entry:
        # If status_index exists, check against the status list
        if entry.status_index is not None:
            is_active, status = check_credential_status(
                identifier, 
                entry.status_index, 
                STATUS_PURPOSE_REVOCATION
            )
            # Check suspension status as well
            is_not_suspended, suspension_status = check_credential_status(
                identifier,
                entry.status_index,
                STATUS_PURPOSE_SUSPENSION
            )
            
            # Update the database entry if needed
            if entry.status != status and status != STATUS_ACTIVE:
                entry.status = status
                entry.validity = is_active
                db.session.commit()
            elif entry.status != suspension_status and suspension_status != STATUS_ACTIVE:
                entry.status = suspension_status
                entry.validity = is_not_suspended
                db.session.commit()
                
            logger.info(f"Credential status from status list: {status}")
            return jsonify({
                "valid": is_active and is_not_suspended,
                "status": entry.status,
                "statusDate": datetime.now(timezone.utc).isoformat() + "Z"
            })
        
        # Legacy validity check
        logger.info(f"Found credential with validity: {entry.validity}")
        return jsonify({"valid": entry.validity})
    else:
        return jsonify({"valid": False})


@validate.route('/status/<string:identifier>', methods=['GET'])
def credential_status(identifier):
    """
    API endpoint for checking credential status according to the Status List 2021 spec.
    """
    logger.info(f"Checking credential status for: {identifier}")
    
    # Find the credential
    entry = VC_validity.query.filter_by(identifier=identifier).first()
    if not entry:
        return jsonify({
            "error": "Credential not found",
            "status": "unknown"
        }), 404
    
    # Check both revocation and suspension status
    revocation_status = None
    suspension_status = None
    
    if entry.status_index is not None:
        is_active, revocation_status = check_credential_status(
            identifier, 
            entry.status_index, 
            STATUS_PURPOSE_REVOCATION
        )
        
        is_not_suspended, suspension_status = check_credential_status(
            identifier,
            entry.status_index,
            STATUS_PURPOSE_SUSPENSION
        )
    
    # Determine the effective status
    effective_status = entry.status or STATUS_ACTIVE
    if suspension_status == STATUS_SUSPENDED:
        effective_status = STATUS_SUSPENDED
    elif revocation_status == STATUS_REVOKED:
        effective_status = STATUS_REVOKED
    
    # Return the status information
    response = {
        "id": f"{current_app.config['SERVER_URL']}/validate/status/{identifier}",
        "status": effective_status,
        "statusDate": datetime.now(timezone.utc).isoformat() + "Z",
        "statusListIndex": str(entry.status_index) if entry.status_index is not None else "0",
        "statusListCredential": f"{current_app.config['SERVER_URL']}/validate/statuslist"
    }
    
    return jsonify(response)


@validate.route('/statuslist', methods=['GET'])
@validate.route('/statuslist/<string:purpose>', methods=['GET'])
def status_list(purpose=STATUS_PURPOSE_REVOCATION):
    """
    API endpoint for retrieving the status list credential.
    """
    logger.info(f"Retrieving status list for purpose: {purpose}")
    
    if purpose not in [STATUS_PURPOSE_REVOCATION, STATUS_PURPOSE_SUSPENSION]:
        return jsonify({"error": "Invalid status purpose"}), 400
    
    # Get or create the status list credential
    status_list_credential = get_status_list_credential(purpose)
    
    return jsonify(status_list_credential)
