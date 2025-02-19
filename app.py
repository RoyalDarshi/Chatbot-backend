from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy #type: ignore
from flask_cors import CORS
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os
from itsdangerous import URLSafeTimedSerializer, BadSignature
from datetime import datetime, timezone
from sib_api_v3_sdk import Configuration, ApiClient, TransactionalEmailsApi
from sib_api_v3_sdk.models.send_smtp_email import SendSmtpEmail


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Define ConnectionDetails model
class ConnectionDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    connectionName = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(255))
    hostname = db.Column(db.String(120), nullable=False)
    port = db.Column(db.String(10), nullable=False)
    database = db.Column(db.String(120), nullable=False)
    commandTimeout = db.Column(db.String(10))
    maxTransportObjects = db.Column(db.String(10))
    username = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    applicationName = db.Column(db.String(120))
    clientAccountingInformation = db.Column(db.String(120))
    clientHostname = db.Column(db.String(120))
    clientUser = db.Column(db.String(120))
    selectedDB = db.Column(db.String(120), nullable=False)
    isPrimary = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)

# Create the database
with app.app_context():
    db.create_all()

# Signup endpoint
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'message': 'All fields are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400
    new_user = User(name=name, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()
    # Generate token
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    token = serializer.dumps({'user_id': new_user.id}, salt=os.getenv('SECURITY_PASSWORD_SALT'))
    return jsonify({'message': 'Signup successful', 'userId': new_user.id,'token': token}), 200

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not registerd'}), 404

    user = User.query.filter_by(email=email, password=password).first()
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

    # Generate token
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    token = serializer.dumps({'user_id': user.id}, salt=os.getenv('SECURITY_PASSWORD_SALT'))
    return jsonify({'message': 'Login successful', 'token': token}), 200

def generate_reset_token(user_email):
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    return serializer.dumps({'user_email': user_email}, salt=os.getenv('SECURITY_PASSWORD_SALT'))

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404

    token = generate_reset_token(user.email)
    reset_entry = PasswordResetToken(user_id=user.id, token=token)
    db.session.add(reset_entry)
    db.session.commit()

    sender_email = os.getenv('SENDER_EMAIL')
    sendinblue_api_key = os.getenv('SENDINBLUE_API_KEY')
    configuration = Configuration()
    configuration.api_key['api-key'] = sendinblue_api_key
    api_instance = TransactionalEmailsApi(ApiClient(configuration))
    to = [{'email': email}]
    subject = "Password Reset Request"
    html_content = f"""
    <p>Hi {user.name},</p>
    <p>To reset your password, click the link below:</p>
    <p><a href='http://localhost:5173/reset-password/{token}'>Reset Password</a></p>
    <p>If you didn't request this, ignore this email.</p>
    """
    send_smtp_email = SendSmtpEmail(sender={'email': sender_email}, to=to, subject=subject, html_content=html_content)
    try:
        api_instance.send_transac_email(send_smtp_email)
        return jsonify({'message': 'Password reset email sent'}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to send email', 'error': str(e)}), 500
    
    # Function to Verify Token
def verify_reset_token(token, expiration=3600):  # 1 hour expiration
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        data = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'), max_age=expiration)
        return data['user_email']
    except Exception:
        return None



# Reset Password API
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('password')

    if not token or not new_password:
        return jsonify({'message': 'Token and new password are required'}), 400

    reset_entry = PasswordResetToken.query.filter_by(token=token).first()
    if not reset_entry or reset_entry.used:
        return jsonify({'message': 'Invalid or expired token'}), 400

    try:
        decoded = verify_reset_token(token)
        user = User.query.filter_by(email=decoded).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        user.password =new_password
        reset_entry.used = True
        db.session.commit()

        return jsonify({'message': 'Password reset successful'}), 200
    except Exception:
        return jsonify({'message': 'Invalid or expired token'}),400

# Test DB Connection endpoint
@app.route('/testdbcon', methods=['POST'])
def test_db_connection():
    # Here you can add logic to test the database connection if needed
    # For now, we just return a dummy success message
    return jsonify({'message': 'Connection made successfully'}), 200

# Create DB Connection endpoint
@app.route('/createdbcon', methods=['POST'])
def create_db_connection():
    data = request.get_json()
    token = data.get('userId')
    connection_details = data.get('connectionDetails')

    if not token or not connection_details:
        return jsonify({'message': 'Token and connection details are required'}), 400

    # Decode token to get user_id
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        decoded_token = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'))
        user_id = decoded_token.get('user_id')
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 401

    # Create new connection details entry
    new_connection = ConnectionDetails(
    user_id=user_id,
    connectionName=connection_details.get('connectionName'),
    description=connection_details.get('description'),
    hostname=connection_details.get('hostname'),
    port=connection_details.get('port'),
    database=connection_details.get('database'),
    commandTimeout=connection_details.get('commandTimeout'),
    maxTransportObjects=connection_details.get('maxTransportObjects'),
    username=connection_details.get('username'),
    password=connection_details.get('password'),
    applicationName=connection_details.get('applicationName'),
    clientAccountingInformation=connection_details.get('clientAccountingInformation'),
    clientHostname=connection_details.get('clientHostname'),
    clientUser=connection_details.get('clientUser'),
    selectedDB=connection_details.get('selectedDB'),
    isPrimary=connection_details.get('isPrimary', False),  # ✅ Default to False if not provided
    created_at=datetime.now(timezone.utc)
)
    db.session.add(new_connection)
    db.session.commit()

    return jsonify({'message': 'Connection details saved successfully'}), 200

# Get User Connections endpoint
@app.route('/getuserconnections', methods=['POST'])
def get_user_connections():
    data = request.get_json()
    token = data.get('userId')

    if not token:
        return jsonify({'message': 'Token is required'}), 400

    # Decode token to get user_id
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        decoded_token = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'))
        user_id = decoded_token.get('user_id')
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 401

    # Query for all connections associated with the user_id
    connections = ConnectionDetails.query.filter_by(user_id=user_id).all()
    connections_list = [
        {
            'id': conn.id,
            'connectionName': conn.connectionName,
            'description': conn.description,
            'hostname': conn.hostname,
            'port': conn.port,
            'database': conn.database,
            'commandTimeout': conn.commandTimeout,
            'maxTransportObjects': conn.maxTransportObjects,
            'username': conn.username,
            'applicationName': conn.applicationName,
            'clientAccountingInformation': conn.clientAccountingInformation,
            'clientHostname': conn.clientHostname,
            'clientUser': conn.clientUser,
            'selectedDB': conn.selectedDB,
            'isPrimary': conn.isPrimary,
            'created_at': conn.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        for conn in connections
    ]

    return jsonify({'connections': connections_list}), 200

@app.route('/getfile', methods=['GET'])
def get_pdf():
    # Replace with the path to your PDF file
    pdf_path = "C:/Users/priya/Downloads/dummy.pdf" 
    return send_file(pdf_path, as_attachment=False)

# Set a connection as primary
@app.route('/setprimary', methods=['POST'])
def set_primary_connection():
    data = request.get_json()
    token = data.get('userId')
    connection_id = data.get('connectionId')

    if not token or not connection_id:
        return jsonify({'message': 'Token and connection ID are required'}), 400

    # Decode token to get user_id
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        decoded_token = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'))
        user_id = decoded_token.get('user_id')
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 401

    # Get the connection that is being set to primary
    connection_to_update = ConnectionDetails.query.filter_by(id=connection_id, user_id=user_id).first()

    if not connection_to_update:
        return jsonify({'message': 'Connection not found'}), 404

    # Check if there's already a primary connection for the user
    existing_primary = ConnectionDetails.query.filter_by(user_id=user_id, isPrimary=True).first()

    # If there is an existing primary, set it to False
    if existing_primary:
        existing_primary.isPrimary = False
        db.session.commit()

    # Set the selected connection as primary
    connection_to_update.isPrimary = True
    db.session.commit()

    return jsonify({'message': 'Primary connection updated successfully'}), 200


# Unset the primary connection
@app.route('/unsetprimary', methods=['POST'])
def unset_primary_connection():
    data = request.get_json()
    token = data.get('userId')
    connection_id = data.get('connectionId')

    if not token or not connection_id:
        return jsonify({'message': 'Token and connection ID are required'}), 400

    # Decode token to get user_id
    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        decoded_token = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'))
        user_id = decoded_token.get('user_id')
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 401

    # Get the connection to update
    connection_to_update = ConnectionDetails.query.filter_by(id=connection_id, user_id=user_id).first()

    if not connection_to_update:
        return jsonify({'message': 'Connection not found'}), 404

    # If the connection is already not primary, return an appropriate message
    if not connection_to_update.isPrimary:
        return jsonify({'message': 'This connection is already not primary'}), 400

    # Set the isPrimary flag to False
    connection_to_update.isPrimary = False
    db.session.commit()

    return jsonify({'message': 'Connection is no longer marked as primary'}), 200


if __name__ == '__main__':
    app.run(debug=True)