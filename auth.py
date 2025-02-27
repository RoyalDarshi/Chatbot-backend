# auth.py
from flask import jsonify
from sib_api_v3_sdk import Configuration, ApiClient, TransactionalEmailsApi
from sib_api_v3_sdk.models.send_smtp_email import SendSmtpEmail
from itsdangerous import URLSafeTimedSerializer
import bcrypt
import os

def hash_password(password):
    """Hashes a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def verify_password(password, hashed_password):
    """Verifies a password against a hashed password."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def signup(db, request, URLSafeTimedSerializer, os):
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    if not name or not email or not password:
        return jsonify({'message': 'All fields are required'}), 400
    if db.session.query(db.Model.metadata.tables['user']).filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400
    from models import User
    hashed_password = hash_password(password)
    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    token = serializer.dumps({'user_id': new_user.id}, salt=os.getenv('SECURITY_PASSWORD_SALT'))
    return jsonify({'message': 'Signup successful', 'userId': new_user.id, 'token': token}), 200

def login(db, request, URLSafeTimedSerializer, os):
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    from models import User
    user = db.session.query(User).filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not registered'}), 404
    if not verify_password(password, user.password):
        return jsonify({'message': 'Invalid credentials'}), 401
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    token = serializer.dumps({'user_id': user.id}, salt=os.getenv('SECURITY_PASSWORD_SALT'))
    return jsonify({'message': 'Login successful', 'token': token}), 200

def generate_reset_token(user_email, URLSafeTimedSerializer, os):
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    return serializer.dumps({'user_email': user_email}, salt=os.getenv('SECURITY_PASSWORD_SALT'))

def forgot_password(db, request, URLSafeTimedSerializer, os, send_reset_email):
    data = request.get_json()
    email = data.get('email')
    from models import User, PasswordResetToken
    user = db.session.query(User).filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    token = generate_reset_token(user.email, URLSafeTimedSerializer, os)
    reset_entry = PasswordResetToken(user_id=user.id, token=token)
    db.session.add(reset_entry)
    db.session.commit()
    try:
        send_reset_email(
            user.email, user.name, token)
        return jsonify({'message': 'Password reset email sent'}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to send email', 'error': str(e)}), 500

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        data = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'), max_age=expiration)
        return data['user_email']
    except Exception:
        return None

def reset_password(db, request, verify_reset_token):
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('password')

    if not token or not new_password:
        return jsonify({'message': 'Token and new password are required'}), 400

    from models import PasswordResetToken, User
    reset_entry = db.session.query(PasswordResetToken).filter_by(token=token).first()
    if not reset_entry or reset_entry.used:
        return jsonify({'message': 'Invalid or expired token'}), 400

    try:
        decoded = verify_reset_token(token)
        user = db.session.query(User).filter_by(email=decoded).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        hashed_password = hash_password(new_password)
        user.password = hashed_password
        reset_entry.used = True
        db.session.commit()

        return jsonify({'message': 'Password reset successful'}), 200
    except Exception:
        return jsonify({'message': 'Invalid or expired token'}), 400