from ..models import VC_Offer
from uuid import uuid4
from .. import db
from flask import current_app as app
import random
from logging import getLogger

logger = getLogger(__name__)


def get_offer_url(credential_data):
    # Generate unique identifiers
    uuid = str(uuid4())
    issuer_state = uuid
    pre_authorized_code = generate_nonce(32)

    # Save the offer to the database
    new_offer = VC_Offer(
        uuid=uuid,
        issuer_state=issuer_state,
        pre_authorized_code=pre_authorized_code,
        credential_data=credential_data
    )
    logger.debug(f"Saving offer to the database: {new_offer.credential_data}")
    db.session.add(new_offer)
    db.session.commit()

    # Generate the credential offer URI
    credential_offer_uri = f"openid-credential-offer://?credential_offer_uri={app.config['SERVER_URL']}/credential-offer/{uuid}"
    return credential_offer_uri


def generate_nonce(length):
    return ''.join(random.choice(
        'abcdefghijklmnopqrstuvwxyz0123456789') for i in range(length))
