from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy import ForeignKey, JSON
from sqlalchemy.orm import relationship
import datetime
from datetime import timezone


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    username = db.Column(db.String(150), unique=True)
    email = db.Column(db.String(255))
    full_name = db.Column(db.String(255))
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    password_hash = db.Column(db.String(150))
    
    # Shibboleth/SAML attributes
    saml_name_id = db.Column(db.String(255))
    shibboleth_session_id = db.Column(db.String(255))
    auth_method = db.Column(db.String(50), default='password')  # 'password', 'shibboleth'
    tenant = db.Column(db.String(50))
    
    # Timestamps
    creation_date = db.Column(db.DateTime(timezone=True), default=func.now())
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    last_login = db.Column(db.DateTime(timezone=True))


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
                           default=lambda: datetime.datetime.now(timezone.utc) + datetime.timedelta(hours=1))


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
    status_index = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), nullable=True, default="active")
    
    def __str__(self) -> str:
        return f"Credential ID: {self.identifier}, Valid: {self.validity}, Status: {self.status}"


class StatusList(db.Model):
    """
    Model for storing status list credentials (StatusList2021).
    A status list is used to track the status of verifiable credentials.
    """
    id = db.Column(db.String(255), primary_key=True)
    purpose = db.Column(db.String(50), nullable=False, index=True)  # revocation or suspension
    encoded_list = db.Column(db.Text, nullable=False)  # base64 encoded bitmap
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(timezone.utc), onupdate=lambda: datetime.datetime.now(timezone.utc))
    credential = db.Column(JSON, nullable=False)  # The full status list credential
    
    def __str__(self) -> str:
        return f"StatusList {self.id} ({self.purpose})"


class SystemMetric(db.Model):
    """Store real-time system metrics for statistics dashboard"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=func.now(), index=True)
    metric_type = db.Column(db.String(50), nullable=False, index=True)  # cpu, memory, disk, network
    metric_name = db.Column(db.String(100), nullable=False)  # cpu_percent, memory_used, etc.
    value = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(20), nullable=True)  # %, GB, MB, count
    extra_data = db.Column(JSON, nullable=True)  # Additional contextual data
    
    def __str__(self) -> str:
        return f"{self.metric_type}.{self.metric_name}: {self.value} {self.unit or ''}"


class WalletConnection(db.Model):
    """Track wallet connections and sessions"""
    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.String(255), nullable=False, index=True)  # Unique wallet identifier
    session_id = db.Column(db.String(255), nullable=False, unique=True)
    connection_type = db.Column(db.String(50), nullable=False)  # mobile, desktop, web
    connected_at = db.Column(db.DateTime(timezone=True), default=func.now())
    disconnected_at = db.Column(db.DateTime(timezone=True), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4/IPv6
    user_agent = db.Column(db.String(500), nullable=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    extra_data = db.Column(JSON, nullable=True)  # Additional connection info
    
    @property
    def session_duration(self):
        """Calculate session duration in minutes"""
        end_time = self.disconnected_at or datetime.datetime.now()
        return (end_time - self.connected_at).total_seconds() / 60
    
    def __str__(self) -> str:
        status = "Active" if self.is_active else "Disconnected"
        return f"Wallet {self.wallet_id} - {status} ({self.connection_type})"


class OperationMetric(db.Model):
    """Track performance metrics for issuance and verification operations"""
    id = db.Column(db.Integer, primary_key=True)
    operation_type = db.Column(db.String(50), nullable=False, index=True)  # issuance, verification
    operation_id = db.Column(db.String(255), nullable=False)  # Unique operation identifier
    started_at = db.Column(db.DateTime(timezone=True), default=func.now())
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    duration_ms = db.Column(db.Integer, nullable=True)  # Duration in milliseconds
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, success, failed
    error_message = db.Column(db.Text, nullable=True)
    wallet_id = db.Column(db.String(255), nullable=True)
    credential_type = db.Column(db.String(100), nullable=True)
    extra_data = db.Column(JSON, nullable=True)
    
    @property
    def duration_seconds(self):
        """Get duration in seconds"""
        return self.duration_ms / 1000 if self.duration_ms else None
    
    def __str__(self) -> str:
        return f"{self.operation_type} - {self.status} ({self.duration_ms}ms)"


class SystemLog(db.Model):
    """Store structured system logs in database"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=func.now(), index=True)
    level = db.Column(db.String(20), nullable=False, index=True)  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    category = db.Column(db.String(50), nullable=False, index=True)  # issuance, verification, security, etc.
    source = db.Column(db.String(100), nullable=False)  # Module/function that generated the log
    message = db.Column(db.Text, nullable=False)
    details = db.Column(JSON, nullable=True)  # Additional structured data
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    session_id = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    
    user = relationship('User', backref='logs')
    
    def __str__(self) -> str:
        return f"[{self.level}] {self.category}: {self.message[:100]}"


class SecurityEvent(db.Model):
    """Track security-related events and metrics"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=func.now(), index=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)  # auth_failure, rate_limit, suspicious_activity
    severity = db.Column(db.String(20), nullable=False, default='medium')  # low, medium, high, critical
    source_ip = db.Column(db.String(45), nullable=True, index=True)
    user_agent = db.Column(db.String(500), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    description = db.Column(db.Text, nullable=False)
    action_taken = db.Column(db.String(100), nullable=True)  # blocked, warned, logged
    extra_data = db.Column(JSON, nullable=True)
    resolved = db.Column(db.Boolean, default=False, index=True)
    
    user = relationship('User', backref='security_events')
    
    def __str__(self) -> str:
        return f"{self.event_type} - {self.severity} from {self.source_ip}"


class Certificate(db.Model):
    """Manage SSL/TLS certificates and X.509 certificates"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)  # Friendly name
    certificate_type = db.Column(db.String(50), nullable=False)  # ssl, x509, ca
    subject = db.Column(db.String(500), nullable=False)  # Certificate subject
    issuer = db.Column(db.String(500), nullable=False)  # Certificate issuer
    serial_number = db.Column(db.String(100), nullable=False)
    fingerprint = db.Column(db.String(200), nullable=False, unique=True)
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_until = db.Column(db.DateTime, nullable=False)
    key_size = db.Column(db.Integer, nullable=True)  # Key size in bits
    algorithm = db.Column(db.String(50), nullable=True)  # RSA, ECDSA, etc.
    certificate_data = db.Column(db.Text, nullable=False)  # PEM encoded certificate
    private_key_path = db.Column(db.String(500), nullable=True)  # Path to private key file
    is_active = db.Column(db.Boolean, default=True, index=True)
    auto_renew = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), default=func.now(), onupdate=func.now())
    extra_data = db.Column(JSON, nullable=True)
    
    @property
    def days_until_expiry(self):
        """Calculate days until certificate expires"""
        return (self.valid_until - datetime.datetime.now()).days
    
    @property
    def is_expired(self):
        """Check if certificate is expired"""
        return datetime.datetime.now() > self.valid_until
    
    @property
    def expires_soon(self):
        """Check if certificate expires within 30 days"""
        return self.days_until_expiry <= 30
    
    def __str__(self) -> str:
        return f"{self.name} ({self.certificate_type}) - Expires: {self.valid_until.strftime('%Y-%m-%d')}"


class Student(db.Model):
    """Store imported student data for credential issuance management"""
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(50), nullable=False, index=True)  # University student ID
    student_id_prefix = db.Column(db.String(20), nullable=True)  # Optional prefix
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), nullable=True)
    
    # Status tracking
    import_batch_id = db.Column(db.String(36), nullable=False, index=True)  # UUID for batch tracking
    is_active = db.Column(db.Boolean, default=True, index=True)
    is_selected_for_issuance = db.Column(db.Boolean, default=False, index=True)
    credential_issued = db.Column(db.Boolean, default=False, index=True)
    credential_issued_at = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    # Optional additional data
    program = db.Column(db.String(200), nullable=True)  # Study program
    semester = db.Column(db.String(20), nullable=True)  # Current semester
    enrollment_year = db.Column(db.Integer, nullable=True)
    extra_data = db.Column(JSON, nullable=True)  # Additional flexible data
    
    # Indexes for performance
    __table_args__ = (
        db.Index('idx_student_batch_active', 'import_batch_id', 'is_active'),
        db.Index('idx_student_issuance', 'is_selected_for_issuance', 'credential_issued'),
        db.Index('idx_student_search', 'first_name', 'last_name', 'student_id'),
    )
    
    @property
    def full_name(self):
        """Get full name of student"""
        return f"{self.first_name} {self.last_name}"
    
    @property
    def display_student_id(self):
        """Get display format of student ID with prefix if available"""
        if self.student_id_prefix:
            return f"{self.student_id_prefix}-{self.student_id}"
        return self.student_id
    
    def to_dict(self):
        """Convert student to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'studentId': self.student_id,
            'studentIdPrefix': self.student_id_prefix,
            'firstName': self.first_name,
            'lastName': self.last_name,
            'email': self.email,
            'fullName': self.full_name,
            'displayStudentId': self.display_student_id,
            'isActive': self.is_active,
            'isSelectedForIssuance': self.is_selected_for_issuance,
            'credentialIssued': self.credential_issued,
            'credentialIssuedAt': self.credential_issued_at.isoformat() if self.credential_issued_at else None,
            'importBatchId': self.import_batch_id,
            'program': self.program,
            'semester': self.semester,
            'enrollmentYear': self.enrollment_year,
            'createdAt': self.created_at.isoformat(),
            'updatedAt': self.updated_at.isoformat(),
            'extraData': self.extra_data
        }
    
    def __str__(self) -> str:
        status = "✓" if self.credential_issued else "○"
        return f"{status} {self.full_name} ({self.display_student_id})"


class ImportBatch(db.Model):
    """Track student import batches for audit and management"""
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.String(36), nullable=False, unique=True, index=True)  # UUID
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)  # SHA-256 hash
    file_size = db.Column(db.Integer, nullable=False)
    
    # Import details
    total_records = db.Column(db.Integer, nullable=False, default=0)
    successful_imports = db.Column(db.Integer, nullable=False, default=0)
    failed_imports = db.Column(db.Integer, nullable=False, default=0)
    import_errors = db.Column(JSON, nullable=True)  # Store error details
    
    # User and timestamp info
    imported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    imported_at = db.Column(db.DateTime(timezone=True), default=func.now())
    
    # Status
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, completed, failed
    
    # Relationships
    user = db.relationship('User', backref='import_batches')
    
    def __str__(self) -> str:
        return f"Import {self.batch_id[:8]} - {self.filename} ({self.successful_imports}/{self.total_records})"
