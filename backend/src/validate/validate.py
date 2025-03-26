from flask import Blueprint, render_template, request, redirect, jsonify, current_app
from logging import getLogger
from ..models import VC_validity
from .. import db
import json


validate = Blueprint('validate', __name__)
logger = getLogger("LOGGER")


@validate.route('/', methods=['GET', 'POST'])
def revokation():
    if request.method == "POST":
        identifier = request.form.get('identifier')
        entry = VC_validity.query.filter_by(identifier=identifier).first()
        if entry:
            entry.validity = not entry.validity
            db.session.commit()
            logger.info(f"Toggled credential with identifier: {identifier}")
        else:
            logger.warning(
                f"Attempted to revoke non-existent credential with identifier: {identifier}")

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
        data = {}
        data["identifier"] = credential.identifier
        data["valid"] = credential.validity
        data["view"] = view
        presentation_credentials.append(data)

    logger.debug(f"Credentials: {presentation_credentials}")
    return render_template("validate.html", credentials=presentation_credentials)


@validate.route('/isvalid/<string:identifier>', methods=['GET', 'POST'])
def is_valid(identifier):
    logger.info(
        f"Checking validity of credential with identifier: {identifier}")
    entry = VC_validity.query.filter_by(identifier=identifier).first()
    if entry:
        logger.info(
            f"Found credential with validity: {entry.validity}")
        return jsonify({"valid": entry.validity})
    else:
        return jsonify({"valid": False})
