#!/usr/bin/env python3
"""
University Student Data API

Provides endpoints for securely retrieving student data from university systems
after Shibboleth authentication, for use in credential issuance processes.

Author: StudentVC Team
Date: April 8, 2025
"""

from flask import Flask, request, jsonify
import requests
import os
import json
import logging
import datetime
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("student_data_api.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load configuration from environment variables
SHIBBOLETH_METADATA_URL = os.environ.get("SHIBBOLETH_METADATA_URL", "https://shibboleth.example.edu/metadata")
STUDENT_DB_API_URL = os.environ.get("STUDENT_DB_API_URL", "https://university-db.example.edu/api")
STUDENT_DB_API_KEY = os.environ.get("STUDENT_DB_API_KEY", "test_api_key")
API_KEY = os.environ.get("API_KEY", "test_api_key_for_studentvc_system")
DEBUG_MODE = os.environ.get("DEBUG_MODE", "False").lower() == "true"

app = Flask(__name__)

# Cache for Shibboleth sessions and student data to reduce API calls
session_cache = {}
student_data_cache = {}
employee_data_cache = {}

def require_api_key(f):
    """Decorator to require API key for endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != API_KEY:
            logger.warning(f"Invalid API key attempt: {api_key}")
            return jsonify({"error": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/v1/student/data', methods=['GET'])
@require_api_key
def get_student_data():
    """Retrieve student or employee data based on Shibboleth authenticated session"""
    try:
        # Get the Shibboleth session ID
        session_id = request.headers.get('X-Shibboleth-Session')
        if not session_id:
            logger.warning("Missing Shibboleth session ID in request")
            return jsonify({"error": "Missing Shibboleth session ID"}), 400
        
        # Validate Shibboleth session
        session_info = validate_shibboleth_session(session_id)
        if not session_info or not session_info.get("valid"):
            logger.warning(f"Invalid Shibboleth session: {session_id}")
            return jsonify({"error": "Invalid Shibboleth session"}), 401
        
        # Get attributes from session
        attributes = session_info.get("attributes", {})
        student_id = attributes.get("StudentID")
        employee_id = attributes.get("EmployeeID")
        university_id = attributes.get("UniversityID")
        
        if not university_id:
            logger.warning("Missing UniversityID in Shibboleth attributes")
            return jsonify({"error": "Missing required Shibboleth attribute: UniversityID"}), 400
            
        # Determine if this is a student or employee request
        if student_id:
            # Retrieve student data
            try:
                student_data = fetch_student_data(student_id, university_id)
                if not student_data:
                    logger.warning(f"Student with ID {student_id} not found")
                    return jsonify({"error": f"Student with ID {student_id} not found"}), 404
                
                # Format for credential issuance
                formatted_data = format_student_data(student_data, university_id)
                return jsonify(formatted_data), 200
            except Exception as e:
                logger.error(f"Error retrieving student data: {str(e)}")
                return jsonify({"error": "Failed to retrieve student data"}), 500
                
        elif employee_id:
            # Retrieve employee data
            try:
                employee_data = fetch_employee_data(employee_id, university_id)
                if not employee_data:
                    logger.warning(f"Employee with ID {employee_id} not found")
                    return jsonify({"error": f"Employee with ID {employee_id} not found"}), 404
                
                # Format for credential issuance
                formatted_data = format_employee_data(employee_data, university_id)
                return jsonify(formatted_data), 200
            except Exception as e:
                logger.error(f"Error retrieving employee data: {str(e)}")
                return jsonify({"error": "Failed to retrieve employee data"}), 500
        
        else:
            logger.warning("Missing StudentID or EmployeeID in Shibboleth attributes")
            return jsonify({"error": "Missing required Shibboleth attribute: StudentID or EmployeeID"}), 400
            
    except Exception as e:
        logger.error(f"Unexpected error in get_student_data: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "up", "timestamp": datetime.datetime.now().isoformat()}), 200

@app.route('/api/v1/clear-cache', methods=['POST'])
@require_api_key
def clear_cache():
    """Clear all caches"""
    global session_cache, student_data_cache, employee_data_cache
    session_cache = {}
    student_data_cache = {}
    employee_data_cache = {}
    return jsonify({"status": "success", "message": "All caches cleared"}), 200

def validate_shibboleth_session(session_id):
    """
    Validate a Shibboleth session ID against the Shibboleth service
    
    Returns:
        dict: Session information including validity and attributes
    """
    # Check if session is in cache
    if session_id in session_cache:
        # Check if cached session is still valid (not expired)
        cached_session = session_cache[session_id]
        session_expiry = cached_session.get("expiry")
        if session_expiry and datetime.datetime.now() < session_expiry:
            return cached_session
        # Session expired, remove from cache
        del session_cache[session_id]
    
    if not session_id:
        return None
        
    try:
        # Query Shibboleth session validation endpoint
        response = requests.get(
            f"{SHIBBOLETH_METADATA_URL}/validate",
            params={"session": session_id},
            timeout=5
        )
        
        if response.status_code != 200:
            logger.warning(f"Shibboleth validation failed with status {response.status_code}")
            return {"valid": False}
        
        session_info = response.json()
        
        # Add expiry time to session info (30 minutes)
        session_info["expiry"] = datetime.datetime.now() + datetime.timedelta(minutes=30)
        
        # Cache the session info
        session_cache[session_id] = session_info
        
        return session_info
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to Shibboleth service: {str(e)}")
        
        # If in debug mode, allow testing with mock sessions
        if DEBUG_MODE and session_id.startswith("SHIB_SESSION_"):
            logger.warning("DEBUG MODE: Using mock Shibboleth session")
            
            # Mock sessions for testing
            if session_id == "SHIB_SESSION_EXPIRED":
                return {"valid": False}
                
            student_id = None
            employee_id = None
            
            if "E" in session_id:
                employee_id = "E" + session_id.split("_")[-1]
            else:
                student_id = str(int(session_id.split("_")[-1]) + 12345678)
                
            mock_session = {
                "valid": True,
                "attributes": {
                    "UniversityID": "tu-berlin"
                }
            }
            
            if student_id:
                mock_session["attributes"]["StudentID"] = student_id
            if employee_id:
                mock_session["attributes"]["EmployeeID"] = employee_id
                
            # Cache the session info
            mock_session["expiry"] = datetime.datetime.now() + datetime.timedelta(minutes=30)
            session_cache[session_id] = mock_session
            
            return mock_session
            
        return {"valid": False}

def fetch_student_data(student_id, university_id):
    """
    Fetch student data from university database
    
    Args:
        student_id (str): Student ID
        university_id (str): University ID
        
    Returns:
        dict: Student data
    """
    # Check if student data is in cache
    cache_key = f"{university_id}:{student_id}"
    if cache_key in student_data_cache:
        return student_data_cache[cache_key]
    
    try:
        # Call internal university API to get student data
        response = requests.get(
            f"{STUDENT_DB_API_URL}/students/{student_id}",
            headers={
                "Authorization": f"Bearer {STUDENT_DB_API_KEY}",
                "X-University-ID": university_id
            },
            timeout=10
        )
        
        if response.status_code != 200:
            logger.warning(f"Student data API returned {response.status_code} for student {student_id}")
            
            # If in debug mode and student ID starts with a specific pattern, return mock data
            if DEBUG_MODE:
                logger.warning(f"DEBUG MODE: Using mock student data for {student_id}")
                
                # Mock student data for testing
                mock_data = {
                    "studentIdentifier": student_id,
                    "fullName": f"Mock Student {student_id[-4:]}",
                    "dateOfBirth": "2000-01-01",
                    "email": f"student{student_id[-4:]}@student.{university_id}.edu",
                    "universityName": f"University of {university_id.upper()}",
                    "faculty": "Faculty of Computer Science",
                    "program": "Computer Science (B.Sc.)",
                    "enrollmentDate": "2020-10-01",
                    "expectedGraduationDate": "2023-09-30",
                    "enrolledCourses": [
                        {
                            "courseId": "CS-1001",
                            "name": "Introduction to Programming",
                            "credits": 6,
                            "semester": "Winter 2020/21",
                            "status": "Completed",
                            "grade": 2.0
                        }
                    ],
                    "completedDegrees": []
                }
                
                # Cache the data
                student_data_cache[cache_key] = mock_data
                
                return mock_data
                
            return None
            
        # Parse JSON response
        student_data = response.json()
        
        # Cache the data
        student_data_cache[cache_key] = student_data
        
        return student_data
    except Exception as e:
        logger.error(f"Error fetching student data: {str(e)}")
        
        # If in debug mode, return mock data
        if DEBUG_MODE:
            logger.warning(f"DEBUG MODE: Using mock student data for {student_id}")
            
            # Mock student data for testing
            mock_data = {
                "studentIdentifier": student_id,
                "fullName": f"Mock Student {student_id[-4:]}",
                "dateOfBirth": "2000-01-01",
                "email": f"student{student_id[-4:]}@student.{university_id}.edu",
                "universityName": f"University of {university_id.upper()}",
                "faculty": "Faculty of Computer Science",
                "program": "Computer Science (B.Sc.)",
                "enrollmentDate": "2020-10-01",
                "expectedGraduationDate": "2023-09-30",
                "enrolledCourses": [
                    {
                        "courseId": "CS-1001",
                        "name": "Introduction to Programming",
                        "credits": 6,
                        "semester": "Winter 2020/21",
                        "status": "Completed",
                        "grade": 2.0
                    }
                ],
                "completedDegrees": []
            }
            
            # Cache the data
            student_data_cache[cache_key] = mock_data
            
            return mock_data
            
        raise

def fetch_employee_data(employee_id, university_id):
    """
    Fetch employee data from university database
    
    Args:
        employee_id (str): Employee ID
        university_id (str): University ID
        
    Returns:
        dict: Employee data
    """
    # Check if employee data is in cache
    cache_key = f"{university_id}:{employee_id}"
    if cache_key in employee_data_cache:
        return employee_data_cache[cache_key]
    
    try:
        # Call internal university API to get employee data
        response = requests.get(
            f"{STUDENT_DB_API_URL}/employees/{employee_id}",
            headers={
                "Authorization": f"Bearer {STUDENT_DB_API_KEY}",
                "X-University-ID": university_id
            },
            timeout=10
        )
        
        if response.status_code != 200:
            logger.warning(f"Employee data API returned {response.status_code} for employee {employee_id}")
            
            # If in debug mode and employee ID starts with a specific pattern, return mock data
            if DEBUG_MODE:
                logger.warning(f"DEBUG MODE: Using mock employee data for {employee_id}")
                
                # Mock employee data for testing
                mock_data = {
                    "employeeIdentifier": employee_id,
                    "fullName": f"Prof. Mock {employee_id[-4:]}",
                    "dateOfBirth": "1980-01-01",
                    "email": f"professor{employee_id[-4:]}@{university_id}.edu",
                    "universityName": f"University of {university_id.upper()}",
                    "department": "Department of Computer Science",
                    "position": "Professor",
                    "employmentStart": "2010-01-01",
                    "employmentEnd": None,
                    "specializations": ["Software Engineering", "Distributed Systems"],
                    "teachingCourses": [
                        {
                            "courseId": "CS-4001",
                            "name": "Advanced Algorithms",
                            "semester": "Winter 2022/23"
                        }
                    ],
                    "academicDegrees": [
                        {
                            "type": "Ph.D.",
                            "field": "Computer Science",
                            "institution": "ETH Zurich",
                            "year": 2005
                        }
                    ]
                }
                
                # Cache the data
                employee_data_cache[cache_key] = mock_data
                
                return mock_data
                
            return None
            
        # Parse JSON response
        employee_data = response.json()
        
        # Cache the data
        employee_data_cache[cache_key] = employee_data
        
        return employee_data
    except Exception as e:
        logger.error(f"Error fetching employee data: {str(e)}")
        
        # If in debug mode, return mock data
        if DEBUG_MODE:
            logger.warning(f"DEBUG MODE: Using mock employee data for {employee_id}")
            
            # Mock employee data for testing
            mock_data = {
                "employeeIdentifier": employee_id,
                "fullName": f"Prof. Mock {employee_id[-4:]}",
                "dateOfBirth": "1980-01-01",
                "email": f"professor{employee_id[-4:]}@{university_id}.edu",
                "universityName": f"University of {university_id.upper()}",
                "department": "Department of Computer Science",
                "position": "Professor",
                "employmentStart": "2010-01-01",
                "employmentEnd": None,
                "specializations": ["Software Engineering", "Distributed Systems"],
                "teachingCourses": [
                    {
                        "courseId": "CS-4001",
                        "name": "Advanced Algorithms",
                        "semester": "Winter 2022/23"
                    }
                ],
                "academicDegrees": [
                    {
                        "type": "Ph.D.",
                        "field": "Computer Science",
                        "institution": "ETH Zurich",
                        "year": 2005
                    }
                ]
            }
            
            # Cache the data
            employee_data_cache[cache_key] = mock_data
            
            return mock_data
            
        raise

def format_student_data(student_data, university_id):
    """
    Format student data for credential issuance
    
    Args:
        student_data (dict): Raw student data
        university_id (str): University ID
        
    Returns:
        dict: Formatted student data for credential issuance
    """
    return {
        "personalInfo": {
            "name": student_data.get("fullName"),
            "birthDate": student_data.get("dateOfBirth"),
            "studentID": student_data.get("studentIdentifier"),
            "email": student_data.get("email")
        },
        "academicInfo": {
            "university": student_data.get("universityName"),
            "faculty": student_data.get("faculty"),
            "program": student_data.get("program"),
            "enrollmentDate": student_data.get("enrollmentDate"),
            "expectedGraduationDate": student_data.get("expectedGraduationDate")
        },
        "courses": student_data.get("enrolledCourses", []),
        "degrees": student_data.get("completedDegrees", []),
        "metadata": {
            "dataSource": "UniversityAPI",
            "retrievalTimestamp": datetime.datetime.now().isoformat(),
            "universityDID": f"did:web:edu:{university_id.lower()}"
        }
    }

def format_employee_data(employee_data, university_id):
    """
    Format employee data for credential issuance
    
    Args:
        employee_data (dict): Raw employee data
        university_id (str): University ID
        
    Returns:
        dict: Formatted employee data for credential issuance
    """
    return {
        "personalInfo": {
            "name": employee_data.get("fullName"),
            "birthDate": employee_data.get("dateOfBirth"),
            "employeeID": employee_data.get("employeeIdentifier"),
            "email": employee_data.get("email")
        },
        "employmentInfo": {
            "university": employee_data.get("universityName"),
            "department": employee_data.get("department"),
            "position": employee_data.get("position"),
            "startDate": employee_data.get("employmentStart"),
            "endDate": employee_data.get("employmentEnd")
        },
        "specializations": employee_data.get("specializations", []),
        "teachingCourses": employee_data.get("teachingCourses", []),
        "academicDegrees": employee_data.get("academicDegrees", []),
        "metadata": {
            "dataSource": "UniversityAPI",
            "retrievalTimestamp": datetime.datetime.now().isoformat(),
            "universityDID": f"did:web:edu:{university_id.lower()}"
        }
    }

if __name__ == "__main__":
    # Get port from environment variable or use default
    port = int(os.environ.get("PORT", 5000))
    
    # Print startup message
    logger.info(f"Starting Student Data API on port {port}")
    logger.info(f"Debug mode: {DEBUG_MODE}")
    logger.info(f"Shibboleth URL: {SHIBBOLETH_METADATA_URL}")
    logger.info(f"Student DB API URL: {STUDENT_DB_API_URL}")
    
    # Run the app
    app.run(debug=DEBUG_MODE, host="0.0.0.0", port=port) 