from flask import request, jsonify
from auth import signup, reset_password, verify_reset_token, validate_token, google_login, linkedin_login
from ldap_auth import store_ldap_details, login as ldap_login  # Renamed for clarity
from utils import send_reset_email
from models import db, Admin
from itsdangerous import URLSafeTimedSerializer, BadSignature
from werkzeug.security import check_password_hash
import jwt
from datetime import datetime, timedelta
import os
import logging

# Logging setup
logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Helper function for errors
def handle_error(message, error=None, status_code=500):
    logger.error(f"{message}: {str(error)}" if error else message)
    return jsonify({'message': message, 'error': str(error) if error else None}), status_code

# Authentication Routes
def store_ldap_details_route():
    try:
        return store_ldap_details(db, request, URLSafeTimedSerializer, os)
    except Exception as e:
        return handle_error("LDAP store failed", error=e, status_code=500)

def signup_route():
    # Assuming signup is not needed since users are in LDAP
    return handle_error("Signup not supported; users managed via LDAP", status_code=400)

def login_route():
    try:
        # Use LDAP login from ldap_auth.py
        result = ldap_login(db, request, URLSafeTimedSerializer, os)
        # Assuming ldap_login returns (response, status_code)
        response, status = result
        if status == 200:
            # Generate JWT token for LDAP-authenticated user
            user_email = response.get('email')  # Adjust based on ldap_login return value
            token = jwt.encode({
                'user_email': user_email,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, os.getenv('SECRET_KEY', 'your-secret-key'))
            return jsonify({'token': token}), 200
        return result  # Return LDAP login error if failed
    except Exception as e:
        return handle_error("Login failed", error=e, status_code=500)

def admin_login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return handle_error("Email and password required", status_code=400)
        admin = Admin.query.filter_by(email=email).first()
        if not admin or not check_password_hash(admin.password, password):
            return handle_error("Invalid admin credentials", status_code=401)
        token = jwt.encode({
            'admin_id': admin.id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, os.getenv('SECRET_KEY', 'your-secret-key'))
        return jsonify({'token': token}), 200
    except Exception as e:
        return handle_error("Admin login failed", error=e, status_code=500)

def reset_password_route():
    try:
        return reset_password(db, request, verify_reset_token)
    except Exception as e:
        return handle_error("Reset password failed", error=e, status_code=500)

def google_login_route():
    try:
        return google_login(db, request, URLSafeTimedSerializer, os)
    except Exception as e:
        return handle_error("Google login failed", error=e, status_code=500)

def linkedin_login_route():
    try:
        return linkedin_login(db, request, URLSafeTimedSerializer, os)
    except Exception as e:
        return handle_error("LinkedIn login failed", error=e, status_code=500)

def validate_token_route():
    try:
        token = request.json.get('token', request.headers.get('Authorization', ''))
        if not token:
            return handle_error("Token required", status_code=400)
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
        serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY', 'your-secret-key'))
        try:
            jwt.decode(token, os.getenv('SECRET_KEY', 'your-secret-key'), algorithms=["HS256"])
        except jwt.InvalidTokenError:
            serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT', 'your-salt'), max_age=3600)
        return jsonify({'message': 'Token is valid'}), 200
    except Exception as e:
        return handle_error("Token validation failed", error=e, status_code=401)