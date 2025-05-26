"""
Secure File Upload System with Modern Security Standards
Implements comprehensive security measures for file uploads
"""

import os
import hashlib
import tempfile
import uuid
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import csv
import json
from flask import current_app, request
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from logging import getLogger
import re

logger = getLogger("LOGGER")


class FileType(Enum):
    CSV = "text/csv"
    JSON = "application/json"
    TEXT = "text/plain"


class UploadError(Exception):
    """Custom exception for upload errors"""
    pass


@dataclass
class FileValidationConfig:
    """Configuration for file validation"""
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    allowed_extensions: List[str] = None
    allowed_mime_types: List[str] = None
    max_filename_length: int = 255
    scan_for_malware: bool = True
    require_content_validation: bool = True
    
    def __post_init__(self):
        if self.allowed_extensions is None:
            self.allowed_extensions = ['.csv', '.json', '.txt']
        if self.allowed_mime_types is None:
            self.allowed_mime_types = [
                'text/csv',
                'application/csv',
                'text/plain',
                'application/json'
            ]


@dataclass
class UploadResult:
    """Result of file upload operation"""
    success: bool
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    file_size: int = 0
    mime_type: Optional[str] = None
    original_filename: Optional[str] = None
    error_message: Optional[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class SecureFileUploader:
    """Secure file upload handler with comprehensive security measures"""
    
    def __init__(self, config: Optional[FileValidationConfig] = None):
        self.config = config or FileValidationConfig()
        self.upload_dir = None
        self.quarantine_dir = None
    
    def _setup_upload_directory(self) -> str:
        """Setup secure upload directory"""
        base_dir = current_app.config.get('INSTANCE_FOLDER_PATH', 'instance')
        upload_dir = os.path.join(base_dir, 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        
        # Set secure permissions (owner read/write only)
        os.chmod(upload_dir, 0o700)
        
        return upload_dir
    
    def _setup_quarantine_directory(self) -> str:
        """Setup quarantine directory for suspicious files"""
        base_dir = current_app.config.get('INSTANCE_FOLDER_PATH', 'instance')
        quarantine_dir = os.path.join(base_dir, 'quarantine')
        os.makedirs(quarantine_dir, exist_ok=True)
        
        # Set secure permissions
        os.chmod(quarantine_dir, 0o700)
        
        return quarantine_dir
    
    def _ensure_directories(self):
        """Ensure upload and quarantine directories exist"""
        if self.upload_dir is None:
            self.upload_dir = self._setup_upload_directory()
        if self.quarantine_dir is None:
            self.quarantine_dir = self._setup_quarantine_directory()
    
    def upload_file(self, file: FileStorage, user_id: Optional[int] = None) -> UploadResult:
        """
        Securely upload and validate file
        
        Args:
            file: FileStorage object from Flask request
            user_id: ID of user uploading file (for audit trail)
            
        Returns:
            UploadResult with success status and details
        """
        try:
            # Ensure directories are set up
            self._ensure_directories()
            
            # Initial file validation
            initial_validation = self._validate_file_initial(file)
            if not initial_validation.success:
                return initial_validation
            
            # Create temporary file for processing
            with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as temp_file:
                # Save file to temporary location
                file.save(temp_file.name)
                temp_file_path = temp_file.name
            
            try:
                # Comprehensive file validation
                validation_result = self._validate_file_comprehensive(temp_file_path, file.filename)
                if not validation_result.success:
                    return validation_result
                
                # Generate secure filename and final path
                secure_name = self._generate_secure_filename(file.filename)
                final_path = os.path.join(self.upload_dir, secure_name)
                
                # Move file to final location
                os.rename(temp_file_path, final_path)
                
                # Set secure file permissions
                os.chmod(final_path, 0o600)
                
                # Calculate file hash for integrity
                file_hash = self._calculate_file_hash(final_path)
                
                # Get file info
                file_size = os.path.getsize(final_path)
                mime_type = self._detect_mime_type(final_path)
                
                # Log successful upload
                logger.info(f"File uploaded successfully: {secure_name} by user {user_id}")
                
                return UploadResult(
                    success=True,
                    file_path=final_path,
                    file_hash=file_hash,
                    file_size=file_size,
                    mime_type=mime_type,
                    original_filename=file.filename,
                    warnings=validation_result.warnings
                )
                
            finally:
                # Clean up temporary file if it still exists
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
                    
        except Exception as e:
            logger.error(f"Error during file upload: {e}")
            return UploadResult(
                success=False,
                error_message=f"Upload failed: {str(e)}"
            )
    
    def _validate_file_initial(self, file: FileStorage) -> UploadResult:
        """Initial file validation before processing"""
        warnings = []
        
        # Check if file is provided
        if not file or not file.filename:
            return UploadResult(
                success=False,
                error_message="No file provided"
            )
        
        # Validate filename length
        if len(file.filename) > self.config.max_filename_length:
            return UploadResult(
                success=False,
                error_message=f"Filename too long (max {self.config.max_filename_length} characters)"
            )
        
        # Check for dangerous filename patterns
        if self._has_dangerous_filename(file.filename):
            return UploadResult(
                success=False,
                error_message="Filename contains dangerous patterns"
            )
        
        # Validate file extension
        file_ext = self._get_file_extension(file.filename)
        if file_ext not in self.config.allowed_extensions:
            return UploadResult(
                success=False,
                error_message=f"File type not allowed. Allowed: {', '.join(self.config.allowed_extensions)}"
            )
        
        # Check file size (initial check)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > self.config.max_file_size:
            return UploadResult(
                success=False,
                error_message=f"File too large. Max size: {self.config.max_file_size / (1024*1024):.1f}MB"
            )
        
        if file_size == 0:
            return UploadResult(
                success=False,
                error_message="Empty file not allowed"
            )
        
        return UploadResult(success=True, warnings=warnings)
    
    def _validate_file_comprehensive(self, file_path: str, original_filename: str) -> UploadResult:
        """Comprehensive file validation after upload"""
        warnings = []
        
        try:
            # MIME type detection and validation
            detected_mime = self._detect_mime_type(file_path)
            if detected_mime not in self.config.allowed_mime_types:
                # Move to quarantine
                self._quarantine_file(file_path, f"Invalid MIME type: {detected_mime}")
                return UploadResult(
                    success=False,
                    error_message=f"File content does not match extension. Detected: {detected_mime}"
                )
            
            # Content validation based on file type
            if self.config.require_content_validation:
                content_validation = self._validate_file_content(file_path, detected_mime)
                if not content_validation['valid']:
                    return UploadResult(
                        success=False,
                        error_message=f"Invalid file content: {content_validation['error']}"
                    )
                warnings.extend(content_validation.get('warnings', []))
            
            # Malware scanning (basic implementation)
            if self.config.scan_for_malware:
                malware_result = self._scan_for_malware(file_path)
                if not malware_result['clean']:
                    self._quarantine_file(file_path, f"Malware detected: {malware_result['threat']}")
                    return UploadResult(
                        success=False,
                        error_message="File failed security scan"
                    )
            
            return UploadResult(success=True, warnings=warnings)
            
        except Exception as e:
            logger.error(f"Error during comprehensive validation: {e}")
            return UploadResult(
                success=False,
                error_message="File validation failed"
            )
    
    def _has_dangerous_filename(self, filename: str) -> bool:
        """Check for dangerous filename patterns"""
        dangerous_patterns = [
            r'\.\./',  # Directory traversal
            r'\.\.\\',  # Windows directory traversal
            r'[<>:"|?*]',  # Invalid filename characters
            r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)',  # Windows reserved names
            r'[\x00-\x1f]',  # Control characters
            r'^\.',  # Hidden files (Unix)
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                return True
        
        return False
    
    def _get_file_extension(self, filename: str) -> str:
        """Get file extension safely"""
        return os.path.splitext(filename.lower())[1]
    
    def _generate_secure_filename(self, original_filename: str) -> str:
        """Generate secure filename with UUID prefix"""
        # Get file extension
        ext = self._get_file_extension(original_filename)
        
        # Generate UUID-based filename
        unique_id = str(uuid.uuid4())
        
        # Optional: include sanitized original name
        base_name = secure_filename(os.path.splitext(original_filename)[0])
        if base_name and len(base_name) <= 50:  # Limit length
            secure_name = f"{unique_id}_{base_name}{ext}"
        else:
            secure_name = f"{unique_id}{ext}"
        
        return secure_name
    
    def _detect_mime_type(self, file_path: str) -> str:
        """Detect MIME type using python-magic or fallback"""
        try:
            if HAS_MAGIC:
                # Try using python-magic if available
                mime_type = magic.from_file(file_path, mime=True)
                return mime_type
            else:
                # Fallback to extension-based detection with content validation
                return self._detect_mime_type_fallback(file_path)
        except:
            # Final fallback to extension-based detection
            ext = self._get_file_extension(file_path)
            mime_map = {
                '.csv': 'text/csv',
                '.json': 'application/json',
                '.txt': 'text/plain'
            }
            return mime_map.get(ext, 'application/octet-stream')
    
    def _detect_mime_type_fallback(self, file_path: str) -> str:
        """Fallback MIME type detection without python-magic"""
        ext = self._get_file_extension(file_path)
        
        # Read first few bytes to help with detection
        try:
            with open(file_path, 'rb') as f:
                header = f.read(512)
            
            # Basic content-based detection
            if header.startswith(b'\x7fELF') or header.startswith(b'MZ'):
                # Executable files - reject
                return 'application/octet-stream'
            
            # Try to decode as text
            try:
                text_content = header.decode('utf-8')
                
                # Check for JSON
                if text_content.strip().startswith(('{', '[')):
                    return 'application/json'
                
                # Check for CSV (basic heuristic)
                if ',' in text_content and '\n' in text_content:
                    return 'text/csv'
                
                # Plain text
                return 'text/plain'
                
            except UnicodeDecodeError:
                # Binary file
                pass
            
            # Extension-based fallback
            mime_map = {
                '.csv': 'text/csv',
                '.json': 'application/json',
                '.txt': 'text/plain'
            }
            return mime_map.get(ext, 'application/octet-stream')
            
        except Exception:
            # Final fallback
            ext = self._get_file_extension(file_path)
            mime_map = {
                '.csv': 'text/csv',
                '.json': 'application/json',
                '.txt': 'text/plain'
            }
            return mime_map.get(ext, 'application/octet-stream')
    
    def _validate_file_content(self, file_path: str, mime_type: str) -> Dict:
        """Validate file content based on type"""
        try:
            if mime_type in ['text/csv', 'application/csv']:
                return self._validate_csv_content(file_path)
            elif mime_type == 'application/json':
                return self._validate_json_content(file_path)
            elif mime_type == 'text/plain':
                return self._validate_text_content(file_path)
            else:
                return {'valid': True, 'warnings': []}
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def _validate_csv_content(self, file_path: str) -> Dict:
        """Validate CSV file content"""
        warnings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', newline='') as f:
                # Try to parse as CSV
                dialect = csv.Sniffer().sniff(f.read(1024))
                f.seek(0)
                
                reader = csv.reader(f, dialect)
                rows = list(reader)
                
                if not rows:
                    return {'valid': False, 'error': 'Empty CSV file'}
                
                # Check for reasonable number of columns
                if len(rows[0]) > 50:
                    warnings.append(f"CSV has many columns ({len(rows[0])})")
                
                # Check for reasonable number of rows
                if len(rows) > 10000:
                    warnings.append(f"CSV has many rows ({len(rows)})")
                
                # Validate required fields for student import
                header = [col.strip().lower() for col in rows[0]]
                required_fields = ['firstname', 'lastname', 'studentid']
                missing_fields = [field for field in required_fields if field not in header]
                
                if missing_fields:
                    return {
                        'valid': False, 
                        'error': f'Missing required fields: {", ".join(missing_fields)}'
                    }
                
                return {'valid': True, 'warnings': warnings}
                
        except Exception as e:
            return {'valid': False, 'error': f'Invalid CSV format: {str(e)}'}
    
    def _validate_json_content(self, file_path: str) -> Dict:
        """Validate JSON file content"""
        warnings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Check if it's a list of objects (expected for student data)
                if isinstance(data, list):
                    if len(data) > 10000:
                        warnings.append(f"JSON contains many records ({len(data)})")
                    
                    # Validate structure of first item if available
                    if data and isinstance(data[0], dict):
                        required_fields = ['firstName', 'lastName', 'studentId']
                        missing_fields = [field for field in required_fields if field not in data[0]]
                        if missing_fields:
                            return {
                                'valid': False,
                                'error': f'Missing required fields in JSON: {", ".join(missing_fields)}'
                            }
                
                return {'valid': True, 'warnings': warnings}
                
        except json.JSONDecodeError as e:
            return {'valid': False, 'error': f'Invalid JSON format: {str(e)}'}
        except Exception as e:
            return {'valid': False, 'error': f'JSON validation error: {str(e)}'}
    
    def _validate_text_content(self, file_path: str) -> Dict:
        """Validate text file content"""
        warnings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Check for reasonable file size
                if len(content) > 1024 * 1024:  # 1MB
                    warnings.append("Large text file")
                
                # Check for binary content
                if '\x00' in content:
                    return {'valid': False, 'error': 'File contains binary data'}
                
                return {'valid': True, 'warnings': warnings}
                
        except UnicodeDecodeError:
            return {'valid': False, 'error': 'File is not valid UTF-8 text'}
        except Exception as e:
            return {'valid': False, 'error': f'Text validation error: {str(e)}'}
    
    def _scan_for_malware(self, file_path: str) -> Dict:
        """Basic malware scanning (implement with proper antivirus if needed)"""
        try:
            # Basic checks for suspicious patterns
            with open(file_path, 'rb') as f:
                content = f.read()
                
                # Check for common malware signatures (very basic)
                suspicious_patterns = [
                    b'<script>',
                    b'javascript:',
                    b'vbscript:',
                    b'eval(',
                    b'exec(',
                    b'system(',
                    b'shell_exec(',
                ]
                
                for pattern in suspicious_patterns:
                    if pattern in content.lower():
                        return {'clean': False, 'threat': f'Suspicious pattern: {pattern.decode("utf-8", errors="ignore")}'}
                
                return {'clean': True}
                
        except Exception as e:
            logger.warning(f"Malware scan failed: {e}")
            return {'clean': True}  # Assume clean if scan fails
    
    def _quarantine_file(self, file_path: str, reason: str):
        """Move suspicious file to quarantine"""
        try:
            self._ensure_directories()
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, f"quarantine_{uuid.uuid4()}_{filename}")
            os.rename(file_path, quarantine_path)
            logger.warning(f"File quarantined: {filename} - Reason: {reason}")
        except Exception as e:
            logger.error(f"Failed to quarantine file: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def cleanup_old_files(self, max_age_days: int = 30):
        """Clean up old uploaded files"""
        try:
            self._ensure_directories()
            import time
            current_time = time.time()
            max_age_seconds = max_age_days * 24 * 60 * 60
            
            for directory in [self.upload_dir, self.quarantine_dir]:
                if directory and os.path.exists(directory):
                    for filename in os.listdir(directory):
                        file_path = os.path.join(directory, filename)
                        if os.path.isfile(file_path):
                            file_age = current_time - os.path.getctime(file_path)
                            if file_age > max_age_seconds:
                                os.unlink(file_path)
                                logger.info(f"Cleaned up old file: {filename}")
                            
        except Exception as e:
            logger.error(f"Error during file cleanup: {e}")


# Create singleton instance
secure_uploader = SecureFileUploader()