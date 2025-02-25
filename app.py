# app.py
from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv
import os
from datetime import datetime, timezone
from itsdangerous import URLSafeTimedSerializer, BadSignature

from auth import signup, login, forgot_password, reset_password, verify_reset_token
from testdb import test_db_connection
from connections import create_db_connection, get_user_connections, set_primary_connection, unset_primary_connection
from utils import send_reset_email
from models import db #import the db instance.

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Initialize database
with app.app_context():
    db.create_all()

# Authentication routes
@app.route('/signup', methods=['POST'])
def signup_route():
    return signup(db, request, URLSafeTimedSerializer, os)

@app.route('/login', methods=['POST'])
def login_route():
    return login(db, request, URLSafeTimedSerializer, os)

@app.route('/forgot-password', methods=['POST'])
def forgot_password_route():
    return forgot_password(db, request, URLSafeTimedSerializer, os, send_reset_email)

@app.route('/reset-password', methods=['POST'])
def reset_password_route():
    return reset_password(db, request, verify_reset_token)

# Connection routes
@app.route('/testdbcon', methods=['POST'])
def test_db_connection_route():
    return test_db_connection()

@app.route('/createdbcon', methods=['POST'])
def create_db_connection_route():
    return create_db_connection(db, request, URLSafeTimedSerializer, os, datetime, timezone, BadSignature)

@app.route('/getuserconnections', methods=['POST'])
def get_user_connections_route():
    return get_user_connections(db, request, URLSafeTimedSerializer, os, BadSignature, datetime)

@app.route('/setprimary', methods=['POST'])
def set_primary_connection_route():
    return set_primary_connection(db, request, URLSafeTimedSerializer, os, BadSignature)

@app.route('/unsetprimary', methods=['POST'])
def unset_primary_connection_route():
    return unset_primary_connection(db, request, URLSafeTimedSerializer, os, BadSignature)


if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)