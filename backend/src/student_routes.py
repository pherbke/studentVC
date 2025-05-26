"""
Enhanced Student Management Routes
Secure upload, storage, and credential issuance management
"""

from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from logging import getLogger
import time
from .student_manager import student_manager
from .data_collector import track_operation, track_security_event

student_admin = Blueprint('student_admin', __name__, url_prefix='/admin/students')
logger = getLogger("LOGGER")


@student_admin.route('/', methods=['GET'])
@login_required
def student_management():
    """Enhanced student management interface"""
    return render_template('admin/student_management.html')


@student_admin.route('/upload', methods=['POST'])
@login_required
def upload_student_file():
    """Secure upload and import of student data"""
    start_time = time.time()
    
    try:
        if 'student_file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file provided'
            }), 400
        
        file = request.files['student_file']
        if not file or file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
        
        logger.info(f"Student file upload initiated by user {current_user.id}: {file.filename}")
        
        # Use enhanced student manager for secure upload and import
        result = student_manager.upload_and_import_students(file, current_user.id)
        
        duration_ms = int((time.time() - start_time) * 1000)
        
        if result.success:
            # Track successful operation
            track_operation('student_file_upload', 'success', duration_ms, {
                'batch_id': result.batch_id,
                'total_records': result.total_records,
                'successful_imports': result.successful_imports,
                'failed_imports': result.failed_imports,
                'filename': file.filename
            }, current_user.id)
            
            # Log security event
            track_security_event('student_data_import', 'medium',
                               f'Student data uploaded by user {current_user.name}: {result.successful_imports} students',
                               request.remote_addr, current_user.id, {
                                   'batch_id': result.batch_id,
                                   'filename': file.filename
                               })
            
            return jsonify({
                'success': True,
                'message': f'Successfully imported {result.successful_imports} students',
                'batchId': result.batch_id,
                'totalRecords': result.total_records,
                'successfulImports': result.successful_imports,
                'failedImports': result.failed_imports,
                'errors': result.errors,
                'warnings': result.warnings
            })
        else:
            # Track failed operation
            track_operation('student_file_upload', 'failed', duration_ms, {
                'errors': result.errors,
                'filename': file.filename
            }, current_user.id)
            
            return jsonify({
                'success': False,
                'error': result.errors[0] if result.errors else 'Upload failed',
                'errors': result.errors
            }), 400
            
    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        track_operation('student_file_upload', 'error', duration_ms, {
            'error': str(e)
        }, current_user.id)
        
        logger.error(f"Error in student file upload: {e}")
        return jsonify({
            'success': False,
            'error': f'Upload failed: {str(e)}'
        }), 500


@student_admin.route('/list', methods=['GET'])
@login_required
def list_students():
    """Get paginated list of students with filtering"""
    try:
        # Get query parameters
        batch_id = request.args.get('batch_id')
        search = request.args.get('search', '').strip()
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)  # Max 100 per page
        only_active = request.args.get('only_active', 'true').lower() == 'true'
        
        # Get students
        result = student_manager.get_students(
            batch_id=batch_id,
            search=search if search else None,
            page=page,
            per_page=per_page,
            only_active=only_active
        )
        
        if result['success']:
            return jsonify({
                'success': True,
                'students': result['students'],
                'pagination': result['pagination']
            })
        else:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 500
            
    except Exception as e:
        logger.error(f"Error listing students: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@student_admin.route('/batches', methods=['GET'])
@login_required
def list_import_batches():
    """Get list of import batches"""
    try:
        batches = student_manager.get_import_batches()
        return jsonify({
            'success': True,
            'batches': batches
        })
        
    except Exception as e:
        logger.error(f"Error listing import batches: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@student_admin.route('/select', methods=['POST'])
@login_required
def update_student_selection():
    """Update student selection for credential issuance"""
    try:
        data = request.get_json()
        student_ids = data.get('student_ids', [])
        selected = data.get('selected', True)
        
        if not isinstance(student_ids, list) or not student_ids:
            return jsonify({
                'success': False,
                'error': 'Invalid student IDs provided'
            }), 400
        
        result = student_manager.update_student_selection(student_ids, selected)
        
        if result['success']:
            action = 'selected' if selected else 'deselected'
            logger.info(f"User {current_user.id} {action} {result['updated_count']} students for issuance")
            
            return jsonify({
                'success': True,
                'message': f'{result["updated_count"]} students {action} for credential issuance',
                'updatedCount': result['updated_count']
            })
        else:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 500
            
    except Exception as e:
        logger.error(f"Error updating student selection: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@student_admin.route('/selected', methods=['GET'])
@login_required
def get_selected_students():
    """Get students selected for credential issuance"""
    try:
        students = student_manager.get_selected_students()
        return jsonify({
            'success': True,
            'students': students,
            'count': len(students)
        })
        
    except Exception as e:
        logger.error(f"Error getting selected students: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@student_admin.route('/issue-credentials', methods=['POST'])
@login_required
def issue_credentials_for_selected():
    """Issue credentials for selected students"""
    start_time = time.time()
    
    try:
        # Get selected students
        selected_students = student_manager.get_selected_students()
        
        if not selected_students:
            return jsonify({
                'success': False,
                'error': 'No students selected for credential issuance'
            }), 400
        
        # Import credential generation functions
        from .issuer.offer import get_offer_url
        from .issuer.qr_codes import generate_qr_code
        from .issuer.utils import get_placeholders
        
        # Get placeholder image
        _, placeholder_profile = get_placeholders()
        
        results = []
        errors = []
        successful_count = 0
        
        logger.info(f"Starting bulk credential issuance for {len(selected_students)} students")
        
        for student in selected_students:
            try:
                # Convert student data to credential format
                credential_data = {
                    'firstName': student['firstName'],
                    'lastName': student['lastName'],
                    'studentId': student['studentId'],
                    'studentIdPrefix': student.get('studentIdPrefix', ''),
                    'issuanceCount': '1',
                    'image': placeholder_profile,  # Use default image
                    'theme': {
                        'name': current_app.config.get('TENANT_NAME', 'University'),
                        'bgColorCard': 'c40e20',
                        'bgColorSectionTop': 'c40e20',
                        'bgColorSectionBot': 'FFFFFF',
                        'fgColorTitle': 'FFFFFF'
                    }
                }
                
                # Generate credential offer
                offer_url = get_offer_url(credential_data)
                qr_code = generate_qr_code(offer_url)
                
                results.append({
                    'student': student,
                    'offer_url': offer_url,
                    'qr_code': qr_code,
                    'credential_data': credential_data
                })
                
                successful_count += 1
                
            except Exception as e:
                error_msg = f"{student['fullName']} (ID: {student['displayStudentId']}): {str(e)}"
                errors.append(error_msg)
                logger.error(f"Error generating credential for student {student['id']}: {e}")
        
        # Mark credentials as issued for successful generations
        if successful_count > 0:
            student_ids = [result['student']['id'] for result in results]
            mark_result = student_manager.mark_credentials_issued(student_ids)
            
            if not mark_result['success']:
                logger.error(f"Error marking credentials as issued: {mark_result['error']}")
        
        # Track operation
        duration_ms = int((time.time() - start_time) * 1000)
        track_operation('bulk_credential_issuance', 'success', duration_ms, {
            'total_students': len(selected_students),
            'successful': successful_count,
            'errors': len(errors)
        }, current_user.id)
        
        logger.info(f"Bulk credential issuance completed: {successful_count}/{len(selected_students)} successful")
        
        return jsonify({
            'success': True,
            'message': f'Generated credentials for {successful_count} students',
            'results': results,
            'errors': errors,
            'totalProcessed': len(selected_students),
            'successfulCount': successful_count,
            'errorCount': len(errors)
        })
        
    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        track_operation('bulk_credential_issuance', 'failed', duration_ms, {
            'error': str(e)
        }, current_user.id)
        
        logger.error(f"Error in bulk credential issuance: {e}")
        return jsonify({
            'success': False,
            'error': f'Credential issuance failed: {str(e)}'
        }), 500


@student_admin.route('/template/csv', methods=['GET'])
@login_required
def download_enhanced_csv_template():
    """Download enhanced CSV template with all supported fields"""
    try:
        from flask import make_response
        
        # Enhanced template with all fields
        template_content = """firstName,lastName,studentId,studentIdPrefix,email,program,semester,enrollmentYear
Max,Mustermann,123456,STU,max.mustermann@university.edu,Computer Science,3,2022
Anna,Schmidt,789012,STU,anna.schmidt@university.edu,Mathematics,1,2024
Tom,Mueller,345678,STU,tom.mueller@university.edu,Physics,5,2021
Maria,Weber,456789,STU,maria.weber@university.edu,Biology,2,2023"""
        
        response = make_response(template_content)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=student_template_enhanced.csv'
        
        return response
        
    except Exception as e:
        logger.error(f"Error generating enhanced CSV template: {e}")
        return jsonify({'error': str(e)}), 500


@student_admin.route('/template/json', methods=['GET'])
@login_required  
def download_enhanced_json_template():
    """Download enhanced JSON template with all supported fields"""
    try:
        from flask import make_response
        import json
        
        template_data = [
            {
                "firstName": "Max",
                "lastName": "Mustermann",
                "studentId": "123456",
                "studentIdPrefix": "STU",
                "email": "max.mustermann@university.edu",
                "program": "Computer Science",
                "semester": "3",
                "enrollmentYear": "2022"
            },
            {
                "firstName": "Anna",
                "lastName": "Schmidt",
                "studentId": "789012",
                "studentIdPrefix": "STU",
                "email": "anna.schmidt@university.edu",
                "program": "Mathematics",
                "semester": "1", 
                "enrollmentYear": "2024"
            }
        ]
        
        json_content = json.dumps(template_data, indent=2)
        
        response = make_response(json_content)
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = 'attachment; filename=student_template_enhanced.json'
        
        return response
        
    except Exception as e:
        logger.error(f"Error generating enhanced JSON template: {e}")
        return jsonify({'error': str(e)}), 500