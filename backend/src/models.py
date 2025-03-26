from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy import ForeignKey, JSON
from sqlalchemy.orm import relationship
import datetime


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    password_hash = db.Column(db.String(150))
    creation_date = db.Column(db.DateTime(timezone=True), default=func.now())


class VC_Offer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    issuer_state = db.Column(db.String(36), nullable=False)
    pre_authorized_code = db.Column(db.String(64), nullable=False)
    credential_data = db.Column(JSON, nullable=False)
    creation_date = db.Column(db.DateTime(timezone=True), default=func.now())


class VC_Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    expires_at = db.Column(db.DateTime(timezone=True),
                           default=(datetime.datetime.now() + datetime.timedelta(hours=1)))


class VC_AuthorizationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(255), nullable=False)
    code_challenge = db.Column(db.String(255), nullable=True)
    auth_code = db.Column(db.String(255), nullable=True)
    issuer_state = db.Column(db.String(255), nullable=True)

    def __str__(self) -> str:
        return f"{self.client_id} - {self.code_challenge} - {self.auth_code} - {self.issuer_state}"


class VC_validity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(255), nullable=False)
    credential_data = db.Column(JSON, nullable=False)
    validity = db.Column(db.Boolean, nullable=False, default=True)
