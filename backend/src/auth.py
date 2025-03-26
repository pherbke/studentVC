from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from .models import User
from logging import getLogger
from datetime import timedelta
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from . import db


auth = Blueprint('auth', __name__)
logger = getLogger("LOGGER")


@auth.route('/login', methods=['GET', 'POST'])
def login():

    # If already logged in, redirect to home
    if current_user.is_authenticated:
        logger.debug(
            f"Already logged in {current_user.name}, redirecting home")
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
        return login_error_handler(f"User with name: {name} does not exist.")

    # if password is incorrect
    if not check_password_hash(user.password_hash, password):
        return login_error_handler(f"Password incorrect for {name}")

    login_user(user, remember=True, duration=timedelta(hours=1))
    flash('Logged in successfully!', category='success')
    logger.info(f"Login Success: {name}")
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
