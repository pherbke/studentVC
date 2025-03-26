from flask import Blueprint, render_template, redirect
from logging import getLogger
from flask_login import login_required, current_user


home = Blueprint('home', __name__)
logger = getLogger("LOGGER")


@home.route('/index', methods=['GET'])
@home.route('/home', methods=['GET'])
@home.route('/', methods=['GET'])
# @login_required
def index():
    return redirect("/issuer")
