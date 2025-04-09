from flask import Flask, jsonify, request
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
from itsdangerous import URLSafeTimedSerializer
import bcrypt
import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# Environment variables
LDAP_SERVER = os.getenv('LDAP_SERVER')
LDAP_ADMIN_DN = os.getenv('LDAP_ADMIN_DN')
LDAP_ADMIN_PASSWORD = os.getenv('LDAP_ADMIN_PASSWORD')
LDAP_USER_OU = os.getenv('LDAP_USER_OU')
SECRET_KEY = os.getenv('SECRET_KEY')
SECURITY_PASSWORD_SALT = os.getenv('SECURITY_PASSWORD_SALT')

# Validate environment variables
required_env_vars = ['LDAP_SERVER', 'LDAP_ADMIN_DN', 'LDAP_ADMIN_PASSWORD', 'LDAP_USER_OU', 'SECRET_KEY', 'SECURITY_PASSWORD_SALT']
for var in required_env_vars:
    if not os.getenv(var):
        raise EnvironmentError(f"Missing required environment variable: {var}")

# LDAP User DN Template
LDAP_USER_DN_TEMPLATE = 'uid={},' + LDAP_USER_OU

# Custom Exceptions
class LDAPError(Exception):
    """Custom exception for LDAP-related errors."""
    pass

class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass

# Utility Functions
def hash_password(password):
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password, hashed_password):
    """Verify a password against a hashed password."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def get_ldap_connection():
    """Create and return an LDAP connection."""
    server = Server(LDAP_SERVER, get_info=ALL)
    return Connection(server, user=LDAP_ADMIN_DN, password=LDAP_ADMIN_PASSWORD, auto_bind=True)

def generate_token(data, salt):
    """Generate a token using a serializer."""
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    return serializer.dumps(data, salt=salt)

def verify_token(token, salt, expiration=3600):
    """Verify a token and return the decoded data."""
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    try:
        return serializer.loads(token, salt=salt, max_age=expiration)
    except Exception:
        return None

def handle_error(message, error=None, status_code=500):
    """Handle errors and return a JSON response."""
    if error:
        logger.error(f"{message}: {error}")
    return jsonify({'message': message, 'error': str(error) if error else None}), status_code

# Auth Functions
def signup(db, request, serializer, os):
    conn = None
    try:
        data = request.get_json()
        if not all(key in data for key in ['first_name', 'last_name', 'email', 'password']):
            raise ValidationError("All fields are required")

        email = data['email']
        conn = get_ldap_connection()
        conn.search(search_base=LDAP_USER_OU, search_filter=f'(uid={email})', attributes=['uid'])
        if conn.entries:
            raise ValidationError("Email already exists")

        user_attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
            'uid': email,
            'cn': f"{data['first_name']} {data['last_name']}",
            'givenName': data['first_name'],
            'sn': data['last_name'],
            'mail': email,
            'userPassword': hash_password(data['password'])
        }

        conn.add(LDAP_USER_DN_TEMPLATE.format(email), attributes=user_attributes)
        if conn.result['description'] != 'success':
            raise LDAPError(f"LDAP error: {conn.result['message']}")

        token = generate_token({'user_email': email}, salt=SECURITY_PASSWORD_SALT)
        return jsonify({'message': 'Signup successful', 'userId': email, 'token': token}), 200

    except ValidationError as e:
        return handle_error(str(e), status_code=400)
    except LDAPError as e:
        return handle_error("LDAP operation failed", error=e, status_code=500)
    except Exception as e:
        return handle_error("Signup failed", error=e, status_code=500)
    finally:
        if conn:
            conn.unbind()

def login(db, request, serializer, os):
    conn = None
    try:
        data = request.get_json()

        # if not all(key in data for key in ['email', 'password']):
        #     raise ValidationError("Email and password are required")

        # email = data['email']
        # password = data['password']
        # user_dn = LDAP_USER_DN_TEMPLATE.format(email)

        # conn = get_ldap_connection()
        # conn.rebind(user=user_dn, password=password)
        # if not conn.bound:
        #     raise ValidationError("Invalid credentials")

        token = generate_token({'user_email': data.get("email")}, salt=SECURITY_PASSWORD_SALT)
        return jsonify({'message': 'Login successful',  'userId': token}), 200

    except ValidationError as e:
        return handle_error(str(e), status_code=400)
    except Exception as e:
        return handle_error("Login failed", error=e, status_code=500)
    finally:
        if conn:
            conn.unbind()

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        data = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'), max_age=expiration)
        return data['user_email']
    except Exception:
        return None

def reset_password(db, request, verify_reset_token):
    conn = None
    try:
        data = request.get_json()
        if not all(key in data for key in ['token', 'password']):
            raise ValidationError("Token and new password are required")

        token = data['token']
        new_password = data['password']
        email = verify_reset_token(token)  # Assuming verify_reset_token returns the email
        if not email:
            raise ValidationError("Invalid or expired token")

        user_dn = LDAP_USER_DN_TEMPLATE.format(email)
        conn = get_ldap_connection()
        conn.modify(user_dn, {'userPassword': [(MODIFY_REPLACE, [hash_password(new_password)])]})
        if conn.result['description'] != 'success':
            raise LDAPError(f"LDAP error: {conn.result['message']}")

        return jsonify({'message': 'Password reset successful'}), 200

    except ValidationError as e:
        return handle_error(str(e), status_code=400)
    except LDAPError as e:
        return handle_error("LDAP operation failed", error=e, status_code=500)
    except Exception as e:
        return handle_error("Password reset failed", error=e, status_code=500)
    finally:
        if conn:
            conn.unbind()

def verify_reset_token(token):
    """Verify a reset token and return the email if valid."""
    return verify_token(token, salt=SECURITY_PASSWORD_SALT, expiration=3600)

def validate_token(db, request, serializer, os):
    """Validate a token and return user info if valid."""
    try:
        data = request.get_json()
        if not data or 'token' not in data:
            raise ValidationError("Token is required")

        token = data['token']
        email = verify_token(token, salt=SECURITY_PASSWORD_SALT)
        if not email:
            raise ValidationError("Invalid or expired token")

        return jsonify({'message': 'Token is valid', 'userId': email}), 200

    except ValidationError as e:
        return handle_error(str(e), status_code=400)
    except Exception as e:
        return handle_error("Token validation failed", error=e, status_code=500)

def google_login(db, request, serializer, os):
    """Placeholder for Google login."""
    # TODO: Implement Google OAuth2 login
    try:
        data = request.get_json()
        # Example: Validate Google token and get email
        email = data.get('email', 'google@example.com')  # Placeholder
        token = generate_token({'user_email': email}, salt=SECURITY_PASSWORD_SALT)
        return jsonify({'message': 'Google login successful', 'userId': email, 'token': token}), 200
    except Exception as e:
        return handle_error("Google login failed", error=e, status_code=500)

def linkedin_login(db, request, serializer, os):
    """Placeholder for LinkedIn login."""
    # TODO: Implement LinkedIn OAuth2 login
    try:
        data = request.get_json()
        # Example: Validate LinkedIn token and get email
        email = data.get('email', 'linkedin@example.com')  # Placeholder
        token = generate_token({'user_email': email}, salt=SECURITY_PASSWORD_SALT)
        return jsonify({'message': 'LinkedIn login successful', 'userId': email, 'token': token}), 200
    except Exception as e:
        return handle_error("LinkedIn login failed", error=e, status_code=500)