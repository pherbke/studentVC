"""
StudentVC Backend Source.

This package contains the backend source code for the StudentVC application.
"""

__version__ = "1.0.0"

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import logging
import random
import os
from flask_socketio import SocketIO
import secrets  # Import secrets module for secure random generation
from .tenant_config import tenant_config

# Create and configure the logger
log_file_path = os.path.join("..", "instance", "service.log")
os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

# Set up the root logger
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file_path),
        logging.StreamHandler(),  # Optional: To also log to the console
    ],
)

logger = logging.getLogger("LOGGER")

# Log something in the main app
logger.info("Logger initialized!")

# Create the db
db = SQLAlchemy()
DB_NAME = "database.db"
SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_NAME}"

# Create socketio
socketio = SocketIO()

# Secure random cookie key using secrets module
SECRET_KEY = ''.join(secrets.choice(
    'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)') for i in range(50))

INSTANCE_PATH = os.path.join(os.path.dirname(__file__), '..', 'instance')


def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000
    app.config['INSTANCE_FOLDER_PATH'] = INSTANCE_PATH
    app.config['INSTANCE_FOLDER'] = INSTANCE_PATH  # Fix for issuer.py compatibility
    
    # Add tenant configuration to app config
    app.config['TENANT_CONFIG'] = tenant_config
    app.config['TENANT_ID'] = tenant_config.tenant_id
    app.config['TENANT_NAME'] = tenant_config.get('name')
    app.config['TENANT_DID'] = tenant_config.get('did')
    
    # Add template context processor for tenant variables
    @app.context_processor
    def inject_tenant_config():
        return tenant_config.get_template_context()
    
    db.init_app(app)

    from .home import home
    from .auth import auth
    from .issuer.issuer import issuer
    from .verifier.verifier import verifier
    from .validate.validate import validate
    from .x509.routes import x509_bp

    app.register_blueprint(home, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(issuer, url_prefix='/')
    app.register_blueprint(verifier, url_prefix='/verifier')
    app.register_blueprint(validate, url_prefix='/validate')
    app.register_blueprint(x509_bp)
    
    from .models import User

    with app.app_context():
        db.create_all()
        # addAllTrackableItems()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = "warning"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    socketio.init_app(app)
    return app
