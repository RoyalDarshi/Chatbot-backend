from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv
import os
from datetime import datetime, timezone
from itsdangerous import URLSafeTimedSerializer, BadSignature

# Import modules
from auth import signup, reset_password, verify_reset_token, validate_token, google_login, linkedin_login

from ldap_auth import store_ldap_details, login

from connections import create_db_connection,create_default_db_connection, get_user_connections, delete_user_connection
from utils import send_reset_email
from models import db  # Import the db instance

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy with the app
db.init_app(app)

# Create database tables (if they don't exist)
with app.app_context():
    db.create_all()

# Initialize serializer for token generation/verification
serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))

# Helper function to handle errors
def handle_error(message, error=None, status_code=500):
    """Return a JSON response for errors."""
    return jsonify({'message': message, 'error': str(error) if error else None}), status_code

# Authentication routes
@app.route('/store-ldap', methods=['POST'])
def store_ldap_details_route():
    try:
        return store_ldap_details(db, request, serializer, os)
    except Exception as e:
        return handle_error("Signup failed", error=e, status_code=500)

@app.route('/signup', methods=['POST'])
def signup_route():
    try:
        return signup(db, request, serializer, os)
    except Exception as e:
        return handle_error("Signup failed", error=e, status_code=500)

@app.route('/login', methods=['POST'])
def login_route():
    return login(db, request, URLSafeTimedSerializer, os)

# @app.route('/forgot-password', methods=['POST'])
# def forgot_password_route():
#     try:
#         return forgot_password(db, request, serializer, os, send_reset_email)
#     except Exception as e:
#         return handle_error("Forgot password failed", error=e, status_code=500)

@app.route('/reset-password', methods=['POST'])
def reset_password_route():
    try:
        return reset_password(db, request, verify_reset_token)
    except Exception as e:
        return handle_error("Reset password failed", error=e, status_code=500)

@app.route('/google-login', methods=['POST'])
def google_login_route():
    try:
        return google_login(db, request, serializer, os)
    except Exception as e:
        return handle_error("Google login failed", error=e, status_code=500)

@app.route('/linkedin-login', methods=['POST'])
def linkedin_login_route():
    try:
        return linkedin_login(db, request, serializer, os)
    except Exception as e:
        return handle_error("LinkedIn login failed", error=e, status_code=500)

# Connection routes

@app.route('/createdbcon', methods=['POST'])
def create_db_connection_route():
    try:
        return create_db_connection(db, request, serializer, os, datetime, timezone, BadSignature)
    except Exception as e:
        return handle_error("Create DB connection failed", error=e, status_code=500)
    
@app.route('/create-default-dbcon',methods=['POST'])
def create_default_db_connection_route():
    try:
        return create_default_db_connection(db, request, serializer, os, datetime, timezone, BadSignature)
    except Exception as e:
        print(e)
        return handle_error("Create default DB connection failed", error=e, status_code=500)

@app.route('/getuserconnections', methods=['POST'])
def get_user_connections_route():
    try:
        return get_user_connections(db, request, serializer, os, BadSignature, datetime)
    except Exception as e:
        return handle_error("Get user connections failed", error=e, status_code=500)

@app.route('/deleteuserconnection', methods=['POST'])
def delete_user_connection_route():
    try:
        return delete_user_connection(db, request, serializer, os, BadSignature)
    except Exception as e:
        return handle_error("Delete user connection failed", error=e, status_code=500)

# Token validation route
@app.route('/validate-token', methods=['POST'])
def validate_token_route():
    try:
        return validate_token(db, request, serializer, os)
    except Exception as e:
        return handle_error("Token validation failed", error=e, status_code=500)

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)