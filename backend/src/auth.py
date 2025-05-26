from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from .models import User
from logging import getLogger
from datetime import timedelta
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from . import db
from .logging_system import log_auth, log_error, log_security, LogLevel, log_function_call, LogCategory
import time


auth = Blueprint('auth', __name__)
logger = getLogger("LOGGER")


@auth.route('/login', methods=['GET', 'POST'])
@log_function_call(LogCategory.AUTHENTICATION)
def login():
    from .data_collector import track_operation, track_security_event
    start_time = time.time()

    # If already logged in, redirect to home
    if current_user.is_authenticated:
        logger.debug(
            f"Already logged in {current_user.name}, redirecting home")
        log_auth("User already authenticated, redirecting", user_id=current_user.name, level=LogLevel.DEBUG)
        return redirect(url_for('home.index'))

    # handle first page request
    if request.method == 'GET':
        logger.info(f"GET request for login page")
        return render_template("login.html")

    # handle form submission
    # get form data
    try:
        name = request.form.get('name')
        password = request.form.get('password')
        logger.info(f"Attempted Login: {name}")
    except Exception as e:
        return login_error_handler(f"Invalid form {e}")

    # get user from db
    user = User.query.filter_by(name=name).first()

    # if user does not exist
    if user is None:
        duration_ms = int((time.time() - start_time) * 1000)
        track_operation('user_authentication', 'failed', duration_ms, {'username': name, 'reason': 'user_not_found'})
        track_security_event('failed_login', 'medium', f'Login attempt with non-existent user: {name}', request.remote_addr)
        log_security("Login attempt with non-existent user", user_id=name, level=LogLevel.WARNING)
        return login_error_handler(f"User with name: {name} does not exist.")

    # if password is incorrect
    if not check_password_hash(user.password_hash, password):
        duration_ms = int((time.time() - start_time) * 1000)
        track_operation('user_authentication', 'failed', duration_ms, {'username': name, 'reason': 'incorrect_password'})
        track_security_event('failed_login', 'medium', f'Login attempt with incorrect password for user: {name}', request.remote_addr, user.id)
        log_security("Login attempt with incorrect password", user_id=name, level=LogLevel.WARNING)
        return login_error_handler(f"Password incorrect for {name}")

    # Successful login
    duration_ms = int((time.time() - start_time) * 1000)
    track_operation('user_authentication', 'success', duration_ms, {'username': name, 'user_id': user.id})
    track_security_event('successful_login', 'low', f'User {name} logged in successfully', request.remote_addr, user.id)
    
    login_user(user, remember=True, duration=timedelta(hours=1))
    flash('Logged in successfully!', category='success')
    logger.info(f"Login Success: {name}")
    log_auth("User login successful", user_id=name, level=LogLevel.INFO)
    return redirect(url_for('home.index'))


def login_error_handler(log_error):
    errorString = "Invalid Credentials!"
    logger.error("LOGIN failed: " + log_error)
    flash(errorString, category='error')
    return render_template("login.html")


@auth.route('/logout')
@login_required
def logout():
    logger.info(f"Logout: {current_user.name}")
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    # if not in debug mode, redirect to home
    if not current_app.config['DEBUG']:
        logger.warning("Attempted to access register page in production")
        return redirect(url_for('home.index'))

    # if get then render the register page
    if request.method == 'GET':
        logger.info("GET request for register page")
        return render_template("register.html")

    try:
        name = request.form.get('name')
        password = request.form.get('password')
        logger.info(f"Attempted Register: {name}")
    except Exception as e:
        flash("Invalid form", category='error')
        return render_template("register.html")

    # check if user already exists
    existing_user = User.query.filter_by(name=name).first()
    if existing_user:
        flash("User already exists", category='error')
        return render_template("register.html")

    # create new user
    hashed_password = generate_password_hash(password)
    new_user = User(name=name, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    logger.info(f"Register Success: {name}")
    flash('Account created!', category='success')

    # login the user
    login_user(new_user, remember=True, duration=timedelta(hours=1))
    logger.info(f"Login Success: {name}")

    return redirect(url_for('home.index'))
