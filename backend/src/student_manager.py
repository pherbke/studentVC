"""
Enhanced Student Management System
Handles secure file upload, student storage, and credential issuance management
"""

import uuid
import csv
import json
import io
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from flask import current_app
from logging import getLogger
from .models import db, Student, ImportBatch
from .secure_upload import secure_uploader, UploadResult
from sqlalchemy import and_, or_, desc
from sqlalchemy.exc import SQLAlchemyError
import datetime

logger = getLogger("LOGGER")


@dataclass
class StudentImportResult:
    """Result of student import operation"""
    success: bool
    batch_id: Optional[str] = None
    total_records: int = 0
    successful_imports: int = 0
    failed_imports: int = 0
    errors: List[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


class StudentManager:
    """Enhanced student management with secure upload and database storage"""
    
    def __init__(self):
        self.required_fields = ['firstName', 'lastName', 'studentId']
        self.optional_fields = ['studentIdPrefix', 'email', 'program', 'semester', 'enrollmentYear']
        self.all_fields = self.required_fields + self.optional_fields
    
    def upload_and_import_students(self, file, user_id: Optional[int] = None) -> StudentImportResult:
        """
        Securely upload file and import students to database
        
        Args:
            file: FileStorage object from Flask request
            user_id: ID of user performing import
            
        Returns:
            StudentImportResult with detailed results
        """
        try:
            # Step 1: Secure file upload
            upload_result = secure_uploader.upload_file(file, user_id)
            
            if not upload_result.success:
                return StudentImportResult(
                    success=False,
                    errors=[upload_result.error_message]
                )
            
            # Step 2: Parse uploaded file
            parse_result = self._parse_uploaded_file(upload_result)
            
            if not parse_result['success']:
                return StudentImportResult(
                    success=False,
                    errors=parse_result['errors']
                )
            
            # Step 3: Import students to database
            import_result = self._import_students_to_database(
                parse_result['students'],
                upload_result,
                user_id
            )
            
            return import_result
            
        except Exception as e:
            logger.error(f"Error during student upload and import: {e}")
            return StudentImportResult(
                success=False,
                errors=[f"Import failed: {str(e)}"]
            )
    
    def _parse_uploaded_file(self, upload_result: UploadResult) -> Dict:
        """Parse uploaded file based on MIME type"""
        try:
            mime_type = upload_result.mime_type
            file_path = upload_result.file_path
            
            if mime_type in ['text/csv', 'application/csv']:
                return self._parse_csv_file(file_path)
            elif mime_type == 'application/json':
                return self._parse_json_file(file_path)
            else:
                return {
                    'success': False,
                    'errors': [f'Unsupported file type: {mime_type}']
                }
                
        except Exception as e:
            return {
                'success': False,
                'errors': [f'Error parsing file: {str(e)}']
            }
    
    def _parse_csv_file(self, file_path: str) -> Dict:
        """Parse CSV file with enhanced error handling"""
        try:
            students = []
            errors = []
            
            with open(file_path, 'r', encoding='utf-8', newline='') as f:
                # Detect CSV dialect
                sample = f.read(1024)
                f.seek(0)
                
                try:
                    dialect = csv.Sniffer().sniff(sample)
                except:
                    dialect = csv.excel  # Fallback to standard dialect
                
                reader = csv.DictReader(f, dialect=dialect)
                
                # Normalize header names (case-insensitive)
                fieldnames = reader.fieldnames
                if not fieldnames:
                    return {
                        'success': False,
                        'errors': ['CSV file has no header row']
                    }
                
                # Create field mapping (case-insensitive)
                field_mapping = self._create_field_mapping(fieldnames)
                
                # Validate required fields
                missing_fields = []
                for required_field in self.required_fields:
                    if required_field not in field_mapping:
                        missing_fields.append(required_field)
                
                if missing_fields:
                    return {
                        'success': False,
                        'errors': [f'Missing required fields: {", ".join(missing_fields)}'],
                        'available_fields': fieldnames
                    }
                
                # Process rows
                for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is row 1)
                    try:
                        student = self._process_csv_row(row, field_mapping, row_num)
                        if student:
                            students.append(student)
                    except Exception as e:
                        errors.append(f"Row {row_num}: {str(e)}")
                
                return {
                    'success': True,
                    'students': students,
                    'errors': errors
                }
                
        except Exception as e:
            return {
                'success': False,
                'errors': [f'Error reading CSV file: {str(e)}']
            }
    
    def _parse_json_file(self, file_path: str) -> Dict:
        """Parse JSON file with validation"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Ensure data is a list
            if isinstance(data, dict):
                data = [data]
            elif not isinstance(data, list):
                return {
                    'success': False,
                    'errors': ['JSON must contain a list of student objects']
                }
            
            students = []
            errors = []
            
            for index, student_data in enumerate(data):
                try:
                    student = self._process_json_student(student_data, index + 1)
                    if student:
                        students.append(student)
                except Exception as e:
                    errors.append(f"Student {index + 1}: {str(e)}")
            
            return {
                'success': True,
                'students': students,
                'errors': errors
            }
            
        except json.JSONDecodeError as e:
            return {
                'success': False,
                'errors': [f'Invalid JSON format: {str(e)}']
            }
        except Exception as e:
            return {
                'success': False,
                'errors': [f'Error reading JSON file: {str(e)}']
            }
    
    def _create_field_mapping(self, fieldnames: List[str]) -> Dict[str, str]:
        """Create case-insensitive field mapping"""
        mapping = {}
        
        # Common field name variations
        field_variations = {
            'firstName': ['firstname', 'first_name', 'fname', 'givenname', 'vorname'],
            'lastName': ['lastname', 'last_name', 'lname', 'surname', 'nachname'],
            'studentId': ['studentid', 'student_id', 'id', 'matrikelnummer', 'student_number'],
            'studentIdPrefix': ['studentidprefix', 'student_id_prefix', 'prefix', 'id_prefix'],
            'email': ['email', 'mail', 'e_mail', 'email_address'],
            'program': ['program', 'course', 'studiengang', 'major', 'degree'],
            'semester': ['semester', 'term', 'year', 'academic_year'],
            'enrollmentYear': ['enrollmentyear', 'enrollment_year', 'entry_year', 'start_year']
        }
        
        # Create mapping
        for field_name, variations in field_variations.items():
            for fieldname in fieldnames:
                if fieldname.lower().strip() in [v.lower() for v in variations + [field_name.lower()]]:
                    mapping[field_name] = fieldname
                    break
        
        return mapping
    
    def _process_csv_row(self, row: Dict, field_mapping: Dict[str, str], row_num: int) -> Optional[Dict]:
        """Process a single CSV row"""
        student = {}
        
        # Process required fields
        for field in self.required_fields:
            if field in field_mapping:
                value = row.get(field_mapping[field], '').strip()
                if not value:
                    raise ValueError(f"Missing required field: {field}")
                student[field] = value
            else:
                raise ValueError(f"Required field not found: {field}")
        
        # Process optional fields
        for field in self.optional_fields:
            if field in field_mapping:
                value = row.get(field_mapping[field], '').strip()
                if value:
                    student[field] = value
        
        # Validate student ID format
        self._validate_student_data(student)
        
        return student
    
    def _process_json_student(self, student_data: Dict, student_num: int) -> Optional[Dict]:
        """Process a single JSON student object"""
        if not isinstance(student_data, dict):
            raise ValueError("Student data must be an object")
        
        student = {}
        
        # Process required fields
        for field in self.required_fields:
            if field not in student_data or not str(student_data[field]).strip():
                raise ValueError(f"Missing required field: {field}")
            student[field] = str(student_data[field]).strip()
        
        # Process optional fields
        for field in self.optional_fields:
            if field in student_data and str(student_data[field]).strip():
                student[field] = str(student_data[field]).strip()
        
        # Validate student data
        self._validate_student_data(student)
        
        return student
    
    def _validate_student_data(self, student: Dict):
        """Validate student data"""
        # Validate student ID format (alphanumeric, reasonable length)
        student_id = student['studentId']
        if not student_id.replace('-', '').replace('_', '').isalnum():
            raise ValueError(f"Invalid student ID format: {student_id}")
        
        if len(student_id) > 50:
            raise ValueError(f"Student ID too long: {student_id}")
        
        # Validate names
        for field in ['firstName', 'lastName']:
            if field in student:
                name = student[field]
                if len(name) > 100:
                    raise ValueError(f"{field} too long: {name}")
                if not name.replace(' ', '').replace('-', '').replace("'", '').isalpha():
                    raise ValueError(f"Invalid {field}: {name}")
        
        # Validate email if provided
        if 'email' in student:
            email = student['email']
            if '@' not in email or len(email) > 255:
                raise ValueError(f"Invalid email: {email}")
    
    def _import_students_to_database(self, students: List[Dict], upload_result: UploadResult, user_id: Optional[int]) -> StudentImportResult:
        """Import validated students to database"""
        try:
            # Create import batch
            batch_id = str(uuid.uuid4())
            
            import_batch = ImportBatch(
                batch_id=batch_id,
                filename=upload_result.original_filename,
                file_hash=upload_result.file_hash,
                file_size=upload_result.file_size,
                total_records=len(students),
                imported_by=user_id,
                status='pending'
            )
            
            db.session.add(import_batch)
            db.session.flush()  # Get the ID
            
            # Import students
            successful_imports = 0
            failed_imports = 0
            errors = []
            
            for index, student_data in enumerate(students):
                try:
                    # Check for duplicates in this batch
                    existing = Student.query.filter(
                        and_(
                            Student.student_id == student_data['studentId'],
                            Student.import_batch_id == batch_id
                        )
                    ).first()
                    
                    if existing:
                        errors.append(f"Duplicate student ID in batch: {student_data['studentId']}")
                        failed_imports += 1
                        continue
                    
                    # Create student record
                    student = Student(
                        student_id=student_data['studentId'],
                        student_id_prefix=student_data.get('studentIdPrefix'),
                        first_name=student_data['firstName'],
                        last_name=student_data['lastName'],
                        email=student_data.get('email'),
                        program=student_data.get('program'),
                        semester=student_data.get('semester'),
                        enrollment_year=int(student_data['enrollmentYear']) if student_data.get('enrollmentYear', '').isdigit() else None,
                        import_batch_id=batch_id,
                        is_active=True
                    )
                    
                    db.session.add(student)
                    successful_imports += 1
                    
                except Exception as e:
                    errors.append(f"Student {index + 1} ({student_data.get('firstName', 'Unknown')} {student_data.get('lastName', '')}): {str(e)}")
                    failed_imports += 1
            
            # Update import batch
            import_batch.successful_imports = successful_imports
            import_batch.failed_imports = failed_imports
            import_batch.import_errors = errors
            import_batch.status = 'completed' if failed_imports == 0 else 'partial'
            
            db.session.commit()
            
            logger.info(f"Student import completed: batch {batch_id}, {successful_imports}/{len(students)} successful")
            
            return StudentImportResult(
                success=True,
                batch_id=batch_id,
                total_records=len(students),
                successful_imports=successful_imports,
                failed_imports=failed_imports,
                errors=errors
            )
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during student import: {e}")
            return StudentImportResult(
                success=False,
                errors=[f"Database error: {str(e)}"]
            )
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error importing students to database: {e}")
            return StudentImportResult(
                success=False,
                errors=[f"Import error: {str(e)}"]
            )
    
    def get_students(self, batch_id: Optional[str] = None, search: Optional[str] = None, 
                    page: int = 1, per_page: int = 50, only_active: bool = True) -> Dict:
        """Get students with filtering and pagination"""
        try:
            query = Student.query
            
            # Filter by batch if specified
            if batch_id:
                query = query.filter(Student.import_batch_id == batch_id)
            
            # Filter by active status
            if only_active:
                query = query.filter(Student.is_active == True)
            
            # Search functionality
            if search:
                search_term = f"%{search}%"
                query = query.filter(
                    or_(
                        Student.first_name.ilike(search_term),
                        Student.last_name.ilike(search_term),
                        Student.student_id.ilike(search_term),
                        Student.email.ilike(search_term)
                    )
                )
            
            # Order by name
            query = query.order_by(Student.last_name, Student.first_name)
            
            # Paginate
            pagination = query.paginate(
                page=page, 
                per_page=per_page, 
                error_out=False
            )
            
            students = [student.to_dict() for student in pagination.items]
            
            return {
                'success': True,
                'students': students,
                'pagination': {
                    'page': pagination.page,
                    'pages': pagination.pages,
                    'per_page': pagination.per_page,
                    'total': pagination.total,
                    'has_next': pagination.has_next,
                    'has_prev': pagination.has_prev
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting students: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def update_student_selection(self, student_ids: List[int], selected: bool) -> Dict:
        """Update selection status for multiple students"""
        try:
            updated_count = Student.query.filter(
                Student.id.in_(student_ids)
            ).update(
                {Student.is_selected_for_issuance: selected},
                synchronize_session=False
            )
            
            db.session.commit()
            
            return {
                'success': True,
                'updated_count': updated_count
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating student selection: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_selected_students(self) -> List[Dict]:
        """Get all students selected for credential issuance"""
        try:
            students = Student.query.filter(
                and_(
                    Student.is_selected_for_issuance == True,
                    Student.is_active == True,
                    Student.credential_issued == False
                )
            ).order_by(Student.last_name, Student.first_name).all()
            
            return [student.to_dict() for student in students]
            
        except Exception as e:
            logger.error(f"Error getting selected students: {e}")
            return []
    
    def mark_credentials_issued(self, student_ids: List[int]) -> Dict:
        """Mark credentials as issued for selected students"""
        try:
            updated_count = Student.query.filter(
                Student.id.in_(student_ids)
            ).update(
                {
                    Student.credential_issued: True,
                    Student.credential_issued_at: datetime.datetime.now(timezone.utc),
                    Student.is_selected_for_issuance: False
                },
                synchronize_session=False
            )
            
            db.session.commit()
            
            return {
                'success': True,
                'updated_count': updated_count
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error marking credentials as issued: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_import_batches(self, user_id: Optional[int] = None) -> List[Dict]:
        """Get import batch history"""
        try:
            query = ImportBatch.query
            
            if user_id:
                query = query.filter(ImportBatch.imported_by == user_id)
            
            batches = query.order_by(desc(ImportBatch.imported_at)).all()
            
            result = []
            for batch in batches:
                batch_data = {
                    'id': batch.id,
                    'batchId': batch.batch_id,
                    'filename': batch.filename,
                    'fileSize': batch.file_size,
                    'totalRecords': batch.total_records,
                    'successfulImports': batch.successful_imports,
                    'failedImports': batch.failed_imports,
                    'status': batch.status,
                    'importedAt': batch.imported_at.isoformat(),
                    'importedBy': batch.imported_by,
                    'errors': batch.import_errors or []
                }
                result.append(batch_data)
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting import batches: {e}")
            return []


# Create singleton instance
student_manager = StudentManager()