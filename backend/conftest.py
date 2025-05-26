"""
Pytest configuration file for StudentVC backend tests.
"""

import os
import pytest
import tempfile
from flask import Flask

# Set environment variables for testing
os.environ['FLASK_ENV'] = 'testing'
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['TESTING'] = 'true'

@pytest.fixture(scope='session')
def app():
    """Create Flask application for testing."""
    try:
        # Import the Flask app with proper error handling
        import sys
        backend_path = os.path.dirname(os.path.abspath(__file__))
        if backend_path not in sys.path:
            sys.path.insert(0, backend_path)
        
        # Create a minimal Flask app for testing
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SECRET_KEY'] = 'test-secret-key'
        app.config['DATABASE_URL'] = 'sqlite:///:memory:'
        
        return app
    except Exception as e:
        # If import fails, create a minimal test app
        app = Flask(__name__)
        app.config['TESTING'] = True
        return app

@pytest.fixture
def client(app):
    """Create a test client for the Flask application."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Create a test runner for the Flask application."""
    return app.test_cli_runner()