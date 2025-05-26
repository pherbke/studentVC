"""
Database Backup and Restore Functionality
Provides comprehensive backup, export, and import capabilities
"""

import datetime
import json
import csv
import os
import sqlite3
import zipfile
import io
from flask import current_app, jsonify, make_response
from logging import getLogger
from .models import db, User, VC_Offer, VC_validity, SystemMetric, WalletConnection, OperationMetric, SystemLog, SecurityEvent, Certificate
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
import tempfile

logger = getLogger("LOGGER")


class DatabaseBackupManager:
    """Manages database backup, export, and import operations"""
    
    def __init__(self):
        self.backup_dir = os.path.join(current_app.config.get('INSTANCE_FOLDER_PATH', 'instance'), 'backups')
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def create_full_backup(self, include_logs=True, include_metrics=True):
        """Create a complete database backup with all tables"""
        try:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f'database_backup_{timestamp}.zip'
            backup_path = os.path.join(self.backup_dir, backup_filename)
            
            # Create backup data
            backup_data = {}
            
            # Core application data
            backup_data['users'] = self._export_table_data(User)
            backup_data['vc_offers'] = self._export_table_data(VC_Offer)
            backup_data['vc_validity'] = self._export_table_data(VC_validity)
            backup_data['wallet_connections'] = self._export_table_data(WalletConnection)
            backup_data['operation_metrics'] = self._export_table_data(OperationMetric)
            backup_data['security_events'] = self._export_table_data(SecurityEvent)
            backup_data['certificates'] = self._export_table_data(Certificate)
            
            # Optional data
            if include_logs:
                backup_data['system_logs'] = self._export_table_data(SystemLog)
            
            if include_metrics:
                backup_data['system_metrics'] = self._export_table_data(SystemMetric)
            
            # Add metadata
            backup_data['metadata'] = {
                'created_at': datetime.datetime.now(timezone.utc).isoformat(),
                'version': '1.0',
                'include_logs': include_logs,
                'include_metrics': include_metrics,
                'total_records': sum(len(data) for data in backup_data.values() if isinstance(data, list))
            }
            
            # Create ZIP file with JSON backup
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add main backup data
                backup_json = json.dumps(backup_data, indent=2, default=str)
                zip_file.writestr('backup_data.json', backup_json)
                
                # Add individual CSV files for easy viewing
                for table_name, data in backup_data.items():
                    if isinstance(data, list) and data:
                        csv_content = self._convert_to_csv(data)
                        zip_file.writestr(f'{table_name}.csv', csv_content)
                
                # Add backup metadata
                metadata_content = json.dumps(backup_data['metadata'], indent=2)
                zip_file.writestr('backup_info.txt', metadata_content)
            
            logger.info(f"Database backup created successfully: {backup_filename}")
            return {
                'success': True,
                'filename': backup_filename,
                'path': backup_path,
                'size': os.path.getsize(backup_path),
                'records': backup_data['metadata']['total_records']
            }
            
        except Exception as e:
            logger.error(f"Error creating database backup: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _export_table_data(self, model_class):
        """Export data from a specific table"""
        try:
            records = []
            for item in model_class.query.all():
                record = {}
                for column in model_class.__table__.columns:
                    value = getattr(item, column.name)
                    # Convert datetime to string
                    if isinstance(value, datetime.datetime):
                        value = value.isoformat()
                    record[column.name] = value
                records.append(record)
            return records
        except Exception as e:
            logger.error(f"Error exporting table {model_class.__tablename__}: {e}")
            return []
    
    def _convert_to_csv(self, data):
        """Convert list of dictionaries to CSV string"""
        if not data:
            return ""
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()
    
    def restore_from_backup(self, backup_file):
        """Restore database from backup file"""
        try:
            # Extract and read backup data
            with zipfile.ZipFile(backup_file, 'r') as zip_file:
                backup_json = zip_file.read('backup_data.json').decode('utf-8')
                backup_data = json.loads(backup_json)
            
            # Validate backup
            if 'metadata' not in backup_data:
                raise ValueError("Invalid backup file format")
            
            restored_count = 0
            
            # Restore each table
            for table_name, records in backup_data.items():
                if table_name == 'metadata' or not isinstance(records, list):
                    continue
                
                count = self._restore_table_data(table_name, records)
                restored_count += count
                logger.info(f"Restored {count} records to {table_name}")
            
            db.session.commit()
            logger.info(f"Database restore completed: {restored_count} total records")
            
            return {
                'success': True,
                'restored_records': restored_count,
                'metadata': backup_data['metadata']
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error restoring database backup: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _restore_table_data(self, table_name, records):
        """Restore data to a specific table"""
        try:
            # Map table names to model classes
            model_map = {
                'users': User,
                'vc_offers': VC_Offer,
                'vc_validity': VC_validity,
                'wallet_connections': WalletConnection,
                'operation_metrics': OperationMetric,
                'system_logs': SystemLog,
                'security_events': SecurityEvent,
                'certificates': Certificate,
                'system_metrics': SystemMetric
            }
            
            if table_name not in model_map:
                logger.warning(f"Unknown table in backup: {table_name}")
                return 0
            
            model_class = model_map[table_name]
            count = 0
            
            for record in records:
                # Convert ISO date strings back to datetime
                for key, value in record.items():
                    if isinstance(value, str) and 'T' in value and value.endswith('Z') or value.count(':') >= 2:
                        try:
                            record[key] = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                        except:
                            pass  # Keep as string if conversion fails
                
                # Create new instance
                instance = model_class(**record)
                db.session.add(instance)
                count += 1
            
            return count
            
        except Exception as e:
            logger.error(f"Error restoring table {table_name}: {e}")
            return 0
    
    def get_backup_list(self):
        """Get list of available backups"""
        try:
            backups = []
            for filename in os.listdir(self.backup_dir):
                if filename.endswith('.zip') and filename.startswith('database_backup_'):
                    backup_path = os.path.join(self.backup_dir, filename)
                    stat = os.stat(backup_path)
                    
                    # Try to read metadata
                    metadata = {}
                    try:
                        with zipfile.ZipFile(backup_path, 'r') as zip_file:
                            if 'backup_info.txt' in zip_file.namelist():
                                metadata = json.loads(zip_file.read('backup_info.txt').decode('utf-8'))
                    except:
                        pass
                    
                    backups.append({
                        'filename': filename,
                        'size': stat.st_size,
                        'created_at': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'metadata': metadata
                    })
            
            # Sort by creation time (newest first)
            backups.sort(key=lambda x: x['created_at'], reverse=True)
            return backups
            
        except Exception as e:
            logger.error(f"Error getting backup list: {e}")
            return []


class StudentImportManager:
    """Manages student data import functionality"""
    
    def __init__(self):
        self.required_fields = ['firstName', 'lastName', 'studentId']
        self.optional_fields = ['studentIdPrefix', 'image', 'theme']
        self.all_fields = self.required_fields + self.optional_fields
    
    def import_students_from_csv(self, csv_file, has_header=True):
        """Import students from CSV file"""
        try:
            # Read CSV data using built-in csv module
            csv_file.seek(0)  # Reset file pointer
            content = csv_file.read().decode('utf-8')
            lines = content.strip().split('\n')
            
            if not lines:
                return {
                    'success': False,
                    'error': 'Empty CSV file'
                }
            
            # Parse CSV
            reader = csv.DictReader(io.StringIO(content)) if has_header else None
            
            if has_header:
                # Use header row
                fieldnames = reader.fieldnames
                rows = list(reader)
            else:
                # Create default fieldnames
                first_row = lines[0].split(',')
                fieldnames = ['firstName', 'lastName', 'studentId', 'studentIdPrefix'][:len(first_row)]
                
                # Create rows as dictionaries
                rows = []
                for line in lines:
                    values = [v.strip('"').strip() for v in line.split(',')]
                    row = {}
                    for i, value in enumerate(values):
                        if i < len(fieldnames):
                            row[fieldnames[i]] = value
                    rows.append(row)
            
            # Validate required columns
            missing_fields = [field for field in self.required_fields if field not in fieldnames]
            if missing_fields:
                return {
                    'success': False,
                    'error': f'Missing required fields: {", ".join(missing_fields)}',
                    'available_fields': fieldnames
                }
            
            students = []
            errors = []
            
            for index, row in enumerate(rows):
                try:
                    student = self._process_student_row_dict(row, index + 1)
                    students.append(student)
                except Exception as e:
                    errors.append(f"Row {index + 1}: {str(e)}")
            
            return {
                'success': True,
                'students': students,
                'total_count': len(students),
                'errors': errors,
                'preview': students[:5]  # First 5 for preview
            }
            
        except Exception as e:
            logger.error(f"Error importing students from CSV: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def import_students_from_json(self, json_file):
        """Import students from JSON file"""
        try:
            if isinstance(json_file, str):
                data = json.loads(json_file)
            else:
                data = json.load(json_file)
            
            # Handle both single student and list of students
            if isinstance(data, dict):
                data = [data]
            
            students = []
            errors = []
            
            for index, student_data in enumerate(data):
                try:
                    student = self._process_student_data(student_data, index + 1)
                    students.append(student)
                except Exception as e:
                    errors.append(f"Student {index + 1}: {str(e)}")
            
            return {
                'success': True,
                'students': students,
                'total_count': len(students),
                'errors': errors,
                'preview': students[:5]
            }
            
        except Exception as e:
            logger.error(f"Error importing students from JSON: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _process_student_row_dict(self, row, row_number):
        """Process a single student row from CSV (dictionary format)"""
        student = {}
        
        # Required fields
        for field in self.required_fields:
            if field in row and row[field] and row[field].strip():
                student[field] = str(row[field]).strip()
            else:
                raise ValueError(f"Missing required field: {field}")
        
        # Optional fields
        for field in self.optional_fields:
            if field in row and row[field] and row[field].strip():
                student[field] = str(row[field]).strip()
        
        # Add default values
        student['issuanceCount'] = '1'
        student = self._add_default_theme(student)
        
        return student
    
    def _process_student_row(self, row, row_number):
        """Process a single student row from CSV"""
        student = {}
        
        # Required fields
        for field in self.required_fields:
            if field in row and pd.notna(row[field]):
                student[field] = str(row[field]).strip()
            elif field in self.required_fields:
                raise ValueError(f"Missing required field: {field}")
        
        # Optional fields
        for field in self.optional_fields:
            if field in row and pd.notna(row[field]):
                student[field] = str(row[field]).strip()
        
        # Add default values
        student['issuanceCount'] = '1'
        student = self._add_default_theme(student)
        
        return student
    
    def _process_student_data(self, data, student_number):
        """Process a single student from JSON data"""
        # Validate required fields
        for field in self.required_fields:
            if field not in data or not data[field]:
                raise ValueError(f"Missing required field: {field}")
        
        student = {}
        
        # Copy all valid fields
        for field in self.all_fields:
            if field in data:
                student[field] = data[field]
        
        # Add defaults
        student['issuanceCount'] = '1'
        student = self._add_default_theme(student)
        
        return student
    
    def _add_default_theme(self, student):
        """Add default theme configuration to student"""
        if 'theme' not in student:
            student['theme'] = {
                'name': current_app.config.get('TENANT_NAME', 'Technical University'),
                'bgColorCard': 'c40e20',
                'bgColorSectionTop': 'c40e20', 
                'bgColorSectionBot': 'FFFFFF',
                'fgColorTitle': 'FFFFFF'
            }
        
        return student
    
    def get_sample_csv_template(self):
        """Generate a sample CSV template for student import"""
        template_data = [
            {
                'firstName': 'Max',
                'lastName': 'Mustermann',
                'studentId': '123456',
                'studentIdPrefix': '654321'
            },
            {
                'firstName': 'Anna',
                'lastName': 'Mueller',
                'studentId': '789012',
                'studentIdPrefix': '210987'
            },
            {
                'firstName': 'Tom',
                'lastName': 'Schmidt',
                'studentId': '345678',
                'studentIdPrefix': '876543'
            }
        ]
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['firstName', 'lastName', 'studentId', 'studentIdPrefix'])
        writer.writeheader()
        writer.writerows(template_data)
        
        return output.getvalue()
    
    def get_sample_json_template(self):
        """Generate a sample JSON template for student import"""
        template_data = [
            {
                'firstName': 'Max',
                'lastName': 'Mustermann',
                'studentId': '123456',
                'studentIdPrefix': '654321',
                'theme': {
                    'name': 'Technical University',
                    'bgColorCard': 'c40e20',
                    'bgColorSectionTop': 'c40e20',
                    'bgColorSectionBot': 'FFFFFF',
                    'fgColorTitle': 'FFFFFF'
                }
            },
            {
                'firstName': 'Anna',
                'lastName': 'Mueller', 
                'studentId': '789012',
                'studentIdPrefix': '210987'
            }
        ]
        
        return json.dumps(template_data, indent=2)


# Managers will be initialized when needed
backup_manager = None
student_import_manager = None

def get_backup_manager():
    """Get or create backup manager instance"""
    global backup_manager
    if backup_manager is None:
        backup_manager = DatabaseBackupManager()
    return backup_manager

def get_student_import_manager():
    """Get or create student import manager instance"""
    global student_import_manager
    if student_import_manager is None:
        student_import_manager = StudentImportManager()
    return student_import_manager