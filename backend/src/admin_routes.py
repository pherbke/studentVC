"""
Administrative Routes for Database Management and Student Import
Provides API endpoints for backup, restore, and student import functionality
"""

from flask import Blueprint, request, jsonify, send_file, render_template, flash, redirect, url_for, make_response
from flask_login import login_required, current_user
from logging import getLogger
from werkzeug.utils import secure_filename
import os
import tempfile
import json
from .database_backup import get_backup_manager, get_student_import_manager
from .data_collector import track_operation, track_security_event
import time

admin = Blueprint('admin', __name__, url_prefix='/admin')
logger = getLogger("LOGGER")

ALLOWED_EXTENSIONS = {'csv', 'json', 'zip'}


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@admin.route('/database', methods=['GET'])
@login_required
def database_management():
    """Database management page"""
    return render_template('admin/database.html')


@admin.route('/backup/create', methods=['POST'])
@login_required
def create_backup():
    """Create a new database backup"""
    start_time = time.time()
    
    try:
        data = request.get_json() or {}
        include_logs = data.get('include_logs', True)
        include_metrics = data.get('include_metrics', True)
        
        logger.info(f"Creating database backup - logs: {include_logs}, metrics: {include_metrics}")
        
        result = get_backup_manager().create_full_backup(
            include_logs=include_logs,
            include_metrics=include_metrics
        )
        
        if result['success']:
            # Track successful backup operation
            duration_ms = int((time.time() - start_time) * 1000)
            track_operation('database_backup', 'success', duration_ms, {
                'filename': result['filename'],
                'records': result['records'],
                'include_logs': include_logs,
                'include_metrics': include_metrics
            }, current_user.id)
            
            # Log security event
            track_security_event('database_backup', 'low', 
                               f'Database backup created by user {current_user.name}',
                               request.remote_addr, current_user.id, {
                                   'filename': result['filename'],
                                   'size': result['size']
                               })
            
            return jsonify({
                'success': True,
                'message': 'Database backup created successfully',
                'filename': result['filename'],
                'size': result['size'],
                'records': result['records']
            })
        else:
            # Track failed backup
            duration_ms = int((time.time() - start_time) * 1000)
            track_operation('database_backup', 'failed', duration_ms, {
                'error': result['error']
            }, current_user.id)
            
            return jsonify({
                'success': False,
                'error': result['error']
            }), 500
            
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin.route('/backup/list', methods=['GET'])
@login_required
def list_backups():
    """Get list of available backups"""
    try:
        backups = get_backup_manager().get_backup_list()
        return jsonify({
            'success': True,
            'backups': backups
        })
    except Exception as e:
        logger.error(f"Error listing backups: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin.route('/backup/download/<filename>', methods=['GET'])
@login_required
def download_backup(filename):
    """Download a backup file"""
    try:
        # Security: validate filename
        filename = secure_filename(filename)
        backup_path = os.path.join(get_backup_manager().backup_dir, filename)
        
        if not os.path.exists(backup_path):
            return jsonify({'error': 'Backup file not found'}), 404
        
        # Log security event
        track_security_event('backup_download', 'low',
                           f'Backup file downloaded by user {current_user.name}: {filename}',
                           request.remote_addr, current_user.id)
        
        return send_file(backup_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        logger.error(f"Error downloading backup: {e}")
        return jsonify({'error': str(e)}), 500


@admin.route('/backup/restore', methods=['POST'])
@login_required
def restore_backup():
    """Restore database from backup file"""
    start_time = time.time()
    
    try:
        if 'backup_file' not in request.files:
            return jsonify({'error': 'No backup file provided'}), 400
        
        file = request.files['backup_file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only ZIP files are allowed.'}), 400
        
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
            file.save(temp_file.name)
            
            logger.info(f"Restoring database from backup: {file.filename}")
            
            result = get_backup_manager().restore_from_backup(temp_file.name)
            
            # Clean up temp file
            os.unlink(temp_file.name)
        
        if result['success']:
            # Track successful restore
            duration_ms = int((time.time() - start_time) * 1000)
            track_operation('database_restore', 'success', duration_ms, {
                'filename': file.filename,
                'restored_records': result['restored_records']
            }, current_user.id)
            
            # Log security event - this is a high-impact operation
            track_security_event('database_restore', 'high',
                               f'Database restored from backup by user {current_user.name}: {file.filename}',
                               request.remote_addr, current_user.id, {
                                   'restored_records': result['restored_records']
                               })
            
            return jsonify({
                'success': True,
                'message': 'Database restored successfully',
                'restored_records': result['restored_records'],
                'metadata': result['metadata']
            })
        else:
            # Track failed restore
            duration_ms = int((time.time() - start_time) * 1000)
            track_operation('database_restore', 'failed', duration_ms, {
                'error': result['error'],
                'filename': file.filename
            }, current_user.id)
            
            return jsonify({
                'success': False,
                'error': result['error']
            }), 500
            
    except Exception as e:
        logger.error(f"Error restoring backup: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin.route('/students', methods=['GET'])
@login_required
def student_management():
    """Student import management page"""
    return render_template('admin/students.html')


@admin.route('/students/import', methods=['POST'])
@login_required
def import_students():
    """Import students from CSV or JSON file"""
    start_time = time.time()
    
    try:
        if 'student_file' not in request.files:
            return jsonify({'error': 'No student file provided'}), 400
        
        file = request.files['student_file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only CSV and JSON files are allowed.'}), 400
        
        # Get import options
        has_header = request.form.get('has_header', 'true').lower() == 'true'
        
        # Process based on file type
        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower()
        
        logger.info(f"Importing students from {file_ext.upper()} file: {filename}")
        
        if file_ext == 'csv':
            result = get_student_import_manager().import_students_from_csv(file, has_header=has_header)
        elif file_ext == 'json':
            result = get_student_import_manager().import_students_from_json(file)
        else:
            return jsonify({'error': 'Unsupported file format'}), 400
        
        if result['success']:
            # Track successful import
            duration_ms = int((time.time() - start_time) * 1000)
            track_operation('student_import', 'success', duration_ms, {
                'filename': filename,
                'total_students': result['total_count'],
                'errors': len(result['errors']),
                'file_type': file_ext
            }, current_user.id)
            
            # Log security event
            track_security_event('student_import', 'medium',
                               f'Student data imported by user {current_user.name}: {result["total_count"]} students',
                               request.remote_addr, current_user.id, {
                                   'filename': filename,
                                   'total_count': result['total_count']
                               })
            
            return jsonify({
                'success': True,
                'message': f'Successfully imported {result["total_count"]} students',
                'students': result['students'],
                'total_count': result['total_count'],
                'errors': result['errors'],
                'preview': result['preview']
            })
        else:
            # Track failed import
            duration_ms = int((time.time() - start_time) * 1000)
            track_operation('student_import', 'failed', duration_ms, {
                'error': result['error'],
                'filename': filename
            }, current_user.id)
            
            return jsonify({
                'success': False,
                'error': result['error'],
                'available_fields': result.get('available_fields', [])
            }), 400
            
    except Exception as e:
        logger.error(f"Error importing students: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin.route('/students/template/csv', methods=['GET'])
@login_required
def download_csv_template():
    """Download CSV template for student import"""
    try:
        csv_content = get_student_import_manager().get_sample_csv_template()
        
        # Create response with CSV content
        response = make_response(csv_content)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=student_import_template.csv'
        
        return response
        
    except Exception as e:
        logger.error(f"Error generating CSV template: {e}")
        return jsonify({'error': str(e)}), 500


@admin.route('/students/template/json', methods=['GET'])
@login_required
def download_json_template():
    """Download JSON template for student import"""
    try:
        json_content = get_student_import_manager().get_sample_json_template()
        
        # Create response with JSON content
        response = make_response(json_content)
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = 'attachment; filename=student_import_template.json'
        
        return response
        
    except Exception as e:
        logger.error(f"Error generating JSON template: {e}")
        return jsonify({'error': str(e)}), 500


@admin.route('/students/bulk-issue', methods=['POST'])
@login_required
def bulk_issue_credentials():
    """Issue credentials for multiple students from imported data"""
    start_time = time.time()
    
    try:
        data = request.get_json()
        students = data.get('students', [])
        
        if not students:
            return jsonify({'error': 'No student data provided'}), 400
        
        # Process each student for credential issuance
        from .issuer.offer import get_offer_url
        from .issuer.qr_codes import generate_qr_code
        
        results = []
        errors = []
        
        for index, student in enumerate(students):
            try:
                # Add default image if not provided
                if 'image' not in student:
                    from .issuer.utils import get_placeholders
                    _, placeholder_profile = get_placeholders()
                    student['image'] = placeholder_profile
                
                # Generate credential offer
                offer_url = get_offer_url(student)
                qr_code = generate_qr_code(offer_url)
                
                results.append({
                    'student': student,
                    'offer_url': offer_url,
                    'qr_code': qr_code,
                    'index': index
                })
                
            except Exception as e:
                errors.append(f"Student {index + 1} ({student.get('firstName', 'Unknown')} {student.get('lastName', '')}): {str(e)}")
        
        # Track bulk issuance operation
        duration_ms = int((time.time() - start_time) * 1000)
        track_operation('bulk_credential_issuance', 'success', duration_ms, {
            'total_students': len(students),
            'successful': len(results),
            'errors': len(errors)
        }, current_user.id)
        
        logger.info(f"Bulk credential issuance completed: {len(results)} successful, {len(errors)} errors")
        
        return jsonify({
            'success': True,
            'message': f'Generated credentials for {len(results)} students',
            'results': results,
            'errors': errors,
            'total_processed': len(students),
            'successful_count': len(results)
        })
        
    except Exception as e:
        logger.error(f"Error in bulk credential issuance: {e}")
        
        # Track failed bulk issuance
        duration_ms = int((time.time() - start_time) * 1000)
        track_operation('bulk_credential_issuance', 'failed', duration_ms, {
            'error': str(e)
        }, current_user.id)
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500