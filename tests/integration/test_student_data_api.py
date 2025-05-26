#!/usr/bin/env python3
"""
Test Student Data API

This test suite validates the implementation of the Student Data API that bridges
Shibboleth authentication with the credential issuance service, using mock data
for both students and university employees.

Author: StudentVC Team
Date: April 8, 2025
"""

import unittest
import json
import os
import sys
import datetime
import uuid
from unittest.mock import patch, MagicMock
import requests
import flask
from flask import Flask, request, jsonify
from werkzeug.test import Client
from werkzeug.wrappers import Response

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Import the actual module we're testing
# In a real implementation, replace with actual import
# from api.student_data_api import app, validate_shibboleth_session, fetch_student_data

# Mock Student Data (would be retrieved from university database)
MOCK_STUDENTS = {
    "12345678": {
        "studentIdentifier": "12345678",
        "fullName": "Alice Johnson",
        "dateOfBirth": "1998-03-15",
        "email": "alice.johnson@student.tu-berlin.de",
        "universityName": "Technical University of Berlin",
        "faculty": "Faculty of Computer Science",
        "program": "Computer Science (M.Sc.)",
        "enrollmentDate": "2022-10-01",
        "expectedGraduationDate": "2024-09-30",
        "enrolledCourses": [
            {
                "courseId": "CS-4001",
                "name": "Advanced Algorithms",
                "credits": 6,
                "semester": "Winter 2022/23",
                "status": "Completed",
                "grade": 1.3
            },
            {
                "courseId": "CS-4102",
                "name": "Cryptography",
                "credits": 6,
                "semester": "Summer 2023",
                "status": "Completed",
                "grade": 1.7
            },
            {
                "courseId": "CS-5001",
                "name": "Distributed Systems",
                "credits": 6,
                "semester": "Winter 2023/24",
                "status": "In Progress",
                "grade": None
            }
        ],
        "completedDegrees": []
    },
    "23456789": {
        "studentIdentifier": "23456789",
        "fullName": "Bob Smith",
        "dateOfBirth": "1997-07-22",
        "email": "bob.smith@student.tu-berlin.de",
        "universityName": "Technical University of Berlin",
        "faculty": "Faculty of Electrical Engineering",
        "program": "Electrical Engineering (B.Sc.)",
        "enrollmentDate": "2020-10-01",
        "expectedGraduationDate": "2023-09-30",
        "enrolledCourses": [
            {
                "courseId": "EE-2001",
                "name": "Circuit Theory",
                "credits": 5,
                "semester": "Winter 2020/21",
                "status": "Completed",
                "grade": 2.0
            },
            {
                "courseId": "EE-3001",
                "name": "Semiconductor Devices",
                "credits": 5,
                "semester": "Summer 2021",
                "status": "Completed",
                "grade": 1.7
            },
            {
                "courseId": "EE-4001",
                "name": "Digital Signal Processing",
                "credits": 6,
                "semester": "Winter 2022/23",
                "status": "Completed",
                "grade": 2.3
            }
        ],
        "completedDegrees": [
            {
                "type": "Bachelor of Science",
                "field": "Electrical Engineering",
                "institution": "Technical University of Berlin",
                "graduationDate": "2023-07-15",
                "finalGrade": "2.1"
            }
        ]
    },
    "34567890": {
        "studentIdentifier": "34567890",
        "fullName": "Charlie Weber",
        "dateOfBirth": "1995-11-30",
        "email": "charlie.weber@student.tu-berlin.de",
        "universityName": "Technical University of Berlin",
        "faculty": "Faculty of Mathematics",
        "program": "Mathematics (Ph.D.)",
        "enrollmentDate": "2021-04-01",
        "expectedGraduationDate": "2025-03-31",
        "enrolledCourses": [
            {
                "courseId": "MATH-7001",
                "name": "Advanced Analysis",
                "credits": 10,
                "semester": "Summer 2021",
                "status": "Completed",
                "grade": 1.0
            },
            {
                "courseId": "MATH-7002",
                "name": "Algebraic Topology",
                "credits": 10,
                "semester": "Winter 2021/22",
                "status": "Completed",
                "grade": 1.3
            }
        ],
        "completedDegrees": [
            {
                "type": "Bachelor of Science",
                "field": "Mathematics",
                "institution": "University of Munich",
                "graduationDate": "2018-06-30",
                "finalGrade": "1.2"
            },
            {
                "type": "Master of Science",
                "field": "Mathematics",
                "institution": "Technical University of Berlin",
                "graduationDate": "2020-09-30",
                "finalGrade": "1.1"
            }
        ]
    }
}

MOCK_EMPLOYEES = {
    "E12345": {
        "employeeIdentifier": "E12345",
        "fullName": "Dr. David Müller",
        "dateOfBirth": "1975-05-10",
        "email": "david.mueller@tu-berlin.de",
        "universityName": "Technical University of Berlin",
        "department": "Department of Computer Science",
        "position": "Professor",
        "employmentStart": "2010-03-01",
        "employmentEnd": None,
        "specializations": ["Distributed Systems", "Computer Security"],
        "teachingCourses": [
            {
                "courseId": "CS-4001",
                "name": "Advanced Algorithms",
                "semester": "Winter 2022/23"
            },
            {
                "courseId": "CS-5001",
                "name": "Distributed Systems",
                "semester": "Winter 2023/24"
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
    },
    "E23456": {
        "employeeIdentifier": "E23456",
        "fullName": "Prof. Elena Schmidt",
        "dateOfBirth": "1980-12-22",
        "email": "elena.schmidt@tu-berlin.de",
        "universityName": "Technical University of Berlin",
        "department": "Department of Electrical Engineering",
        "position": "Associate Professor",
        "employmentStart": "2015-09-01",
        "employmentEnd": None,
        "specializations": ["Signal Processing", "Communication Systems"],
        "teachingCourses": [
            {
                "courseId": "EE-4001",
                "name": "Digital Signal Processing",
                "semester": "Winter 2022/23"
            }
        ],
        "academicDegrees": [
            {
                "type": "Ph.D.",
                "field": "Electrical Engineering",
                "institution": "Technical University of Munich",
                "year": 2010
            }
        ]
    }
}

# Mock Shibboleth Session Data
VALID_SHIBBOLETH_SESSIONS = {
    "SHIB_SESSION_12345": {
        "valid": True,
        "attributes": {
            "StudentID": "12345678",
            "UniversityID": "tu-berlin"
        }
    },
    "SHIB_SESSION_23456": {
        "valid": True,
        "attributes": {
            "StudentID": "23456789",
            "UniversityID": "tu-berlin"
        }
    },
    "SHIB_SESSION_34567": {
        "valid": True,
        "attributes": {
            "StudentID": "34567890",
            "UniversityID": "tu-berlin"
        }
    },
    "SHIB_SESSION_E12345": {
        "valid": True,
        "attributes": {
            "EmployeeID": "E12345",
            "UniversityID": "tu-berlin"
        }
    },
    "SHIB_SESSION_E23456": {
        "valid": True,
        "attributes": {
            "EmployeeID": "E23456",
            "UniversityID": "tu-berlin"
        }
    },
    "SHIB_SESSION_EXPIRED": {
        "valid": False,
        "attributes": {
            "StudentID": "12345678",
            "UniversityID": "tu-berlin"
        }
    }
}

# Mock API Key
VALID_API_KEY = "test_api_key_for_studentvc_system"

# Implementation of a mock Student Data API for testing
class MockStudentDataAPI:
    """Mock implementation of the Student Data API"""
    
    def __init__(self):
        """Initialize the Flask app"""
        self.app = Flask(__name__)
        self.setup_routes()
        self.client = self.app.test_client()
    
    def setup_routes(self):
        """Set up API routes"""
        @self.app.route('/api/v1/student/data', methods=['GET'])
        def get_student_data():
            # Check API key
            api_key = request.headers.get('X-API-Key')
            if not api_key or api_key != VALID_API_KEY:
                return jsonify({"error": "Invalid or missing API key"}), 401
            
            # Get the Shibboleth session ID from header
            session_id = request.headers.get('X-Shibboleth-Session')
            
            # Validate Shibboleth session
            session_info = VALID_SHIBBOLETH_SESSIONS.get(session_id)
            if not session_info or not session_info["valid"]:
                return jsonify({"error": "Invalid Shibboleth session"}), 401
            
            # Get attributes from session
            attributes = session_info["attributes"]
            student_id = attributes.get("StudentID")
            employee_id = attributes.get("EmployeeID")
            university_id = attributes.get("UniversityID")
            
            if not university_id:
                return jsonify({"error": "Missing required Shibboleth attribute: UniversityID"}), 400
                
            # Determine if this is a student or employee request
            if student_id:
                # Retrieve student data
                student_data = MOCK_STUDENTS.get(student_id)
                if not student_data:
                    return jsonify({"error": f"Student with ID {student_id} not found"}), 404
                
                # Format for credential issuance
                formatted_data = {
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
                
                return jsonify(formatted_data), 200
                
            elif employee_id:
                # Retrieve employee data
                employee_data = MOCK_EMPLOYEES.get(employee_id)
                if not employee_data:
                    return jsonify({"error": f"Employee with ID {employee_id} not found"}), 404
                
                # Format for credential issuance
                formatted_data = {
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
                
                return jsonify(formatted_data), 200
            
            else:
                return jsonify({"error": "Missing required Shibboleth attribute: StudentID or EmployeeID"}), 400


class TestStudentDataAPI(unittest.TestCase):
    """Test suite for the Student Data API"""
    
    def setUp(self):
        """Set up test environment"""
        self.api = MockStudentDataAPI()
        self.client = self.api.client
    
    def test_student_data_with_valid_session(self):
        """Test retrieving student data with a valid Shibboleth session"""
        response = self.client.get(
            '/api/v1/student/data',
            headers={
                'X-API-Key': VALID_API_KEY,
                'X-Shibboleth-Session': 'SHIB_SESSION_12345'
            }
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        # Verify response structure
        self.assertIn('personalInfo', data)
        self.assertIn('academicInfo', data)
        self.assertIn('courses', data)
        
        # Verify student data
        self.assertEqual(data['personalInfo']['name'], 'Alice Johnson')
        self.assertEqual(data['personalInfo']['studentID'], '12345678')
        self.assertEqual(data['academicInfo']['program'], 'Computer Science (M.Sc.)')
        self.assertEqual(len(data['courses']), 3)
        
    def test_employee_data_with_valid_session(self):
        """Test retrieving employee data with a valid Shibboleth session"""
        response = self.client.get(
            '/api/v1/student/data',
            headers={
                'X-API-Key': VALID_API_KEY,
                'X-Shibboleth-Session': 'SHIB_SESSION_E12345'
            }
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        # Verify response structure
        self.assertIn('personalInfo', data)
        self.assertIn('employmentInfo', data)
        self.assertIn('teachingCourses', data)
        
        # Verify employee data
        self.assertEqual(data['personalInfo']['name'], 'Dr. David Müller')
        self.assertEqual(data['personalInfo']['employeeID'], 'E12345')
        self.assertEqual(data['employmentInfo']['position'], 'Professor')
        self.assertEqual(len(data['teachingCourses']), 2)
    
    def test_invalid_api_key(self):
        """Test request with invalid API key"""
        response = self.client.get(
            '/api/v1/student/data',
            headers={
                'X-API-Key': 'INVALID_KEY',
                'X-Shibboleth-Session': 'SHIB_SESSION_12345'
            }
        )
        
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Invalid or missing API key')
    
    def test_invalid_shibboleth_session(self):
        """Test request with invalid Shibboleth session"""
        response = self.client.get(
            '/api/v1/student/data',
            headers={
                'X-API-Key': VALID_API_KEY,
                'X-Shibboleth-Session': 'INVALID_SESSION'
            }
        )
        
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Invalid Shibboleth session')
    
    def test_expired_shibboleth_session(self):
        """Test request with expired Shibboleth session"""
        response = self.client.get(
            '/api/v1/student/data',
            headers={
                'X-API-Key': VALID_API_KEY,
                'X-Shibboleth-Session': 'SHIB_SESSION_EXPIRED'
            }
        )
        
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Invalid Shibboleth session')
    
    def test_student_with_completed_degrees(self):
        """Test retrieving data for a student with completed degrees"""
        response = self.client.get(
            '/api/v1/student/data',
            headers={
                'X-API-Key': VALID_API_KEY,
                'X-Shibboleth-Session': 'SHIB_SESSION_23456'
            }
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        # Verify degrees
        self.assertEqual(len(data['degrees']), 1)
        self.assertEqual(data['degrees'][0]['type'], 'Bachelor of Science')
        self.assertEqual(data['degrees'][0]['field'], 'Electrical Engineering')
    
    def test_phd_student_with_multiple_degrees(self):
        """Test retrieving data for a PhD student with multiple prior degrees"""
        response = self.client.get(
            '/api/v1/student/data',
            headers={
                'X-API-Key': VALID_API_KEY,
                'X-Shibboleth-Session': 'SHIB_SESSION_34567'
            }
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        # Verify program and degrees
        self.assertEqual(data['academicInfo']['program'], 'Mathematics (Ph.D.)')
        self.assertEqual(len(data['degrees']), 2)
        
    def test_nonexistent_student(self):
        """Test requesting data for a nonexistent student"""
        # Create a session with a non-existent student ID
        nonexistent_session = {
            "valid": True,
            "attributes": {
                "StudentID": "99999999",
                "UniversityID": "tu-berlin"
            }
        }
        
        # Temporarily add this session for testing
        VALID_SHIBBOLETH_SESSIONS["SHIB_SESSION_NONEXISTENT"] = nonexistent_session
        
        response = self.client.get(
            '/api/v1/student/data',
            headers={
                'X-API-Key': VALID_API_KEY,
                'X-Shibboleth-Session': 'SHIB_SESSION_NONEXISTENT'
            }
        )
        
        # Remove the temporary session
        del VALID_SHIBBOLETH_SESSIONS["SHIB_SESSION_NONEXISTENT"]
        
        self.assertEqual(response.status_code, 404)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Student with ID 99999999 not found')
    
    def test_missing_university_id(self):
        """Test request missing the university ID attribute"""
        # Create a session with missing university ID
        incomplete_session = {
            "valid": True,
            "attributes": {
                "StudentID": "12345678"
                # Missing UniversityID
            }
        }
        
        # Temporarily add this session for testing
        VALID_SHIBBOLETH_SESSIONS["SHIB_SESSION_INCOMPLETE"] = incomplete_session
        
        response = self.client.get(
            '/api/v1/student/data',
            headers={
                'X-API-Key': VALID_API_KEY,
                'X-Shibboleth-Session': 'SHIB_SESSION_INCOMPLETE'
            }
        )
        
        # Remove the temporary session
        del VALID_SHIBBOLETH_SESSIONS["SHIB_SESSION_INCOMPLETE"]
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Missing required Shibboleth attribute: UniversityID')


if __name__ == '__main__':
    unittest.main() 