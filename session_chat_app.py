from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv, dotenv_values, set_key
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature
from datetime import datetime, timezone
from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash
from ldap3 import Server, Connection, ALL, SUBTREE, AUTO_BIND_TLS_BEFORE_BIND, Tls
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn
import ssl
import json
import os
import uuid

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Load environment variables from .env file
load_dotenv()

# Basic app configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT', 'your-salt')

# LDAP Configuration
LDAP_SERVER = "ldap://150.239.171.184"
LDAP_BASE_DN = "dc=150,dc=239,dc=171,dc=184"
LDAP_USER_DN_TEMPLATE = "uid={},ou=people," + LDAP_BASE_DN
LDAP_PORT = 389
LDAP_SEARCH_FILTER = "(uid=%s)"

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define the Admin model
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Define the Session model
class Session(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    uid = db.Column(db.String(255), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Define the Message model
class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = db.Column(db.String(36), db.ForeignKey('session.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_bot = db.Column(db.Boolean, default=False, nullable=False)
    is_favorited = db.Column(db.Boolean, default=False, nullable=False)
    parent_id = db.Column(db.String(36), db.ForeignKey('message.id'), nullable=True)  # New field
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    session = db.relationship('Session', backref=db.backref('messages', lazy=True))
    parent = db.relationship('Message', remote_side=[id], backref='responses')

# Define the Favorite model
class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.String(255), nullable=False)
    question_content = db.Column(db.String(500), nullable=False)
    response_id = db.Column(db.String(255), nullable=True)
    response_query = db.Column(db.String(500), nullable=True)
    uid = db.Column(db.String(255), nullable=False)
    count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Define the ConnectionDetails model
class ConnectionDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)
    uid = db.Column(db.String(120), nullable=False)
    connectionName = db.Column(db.String(120), nullable=False, unique=True)
    description = db.Column(db.String(255))
    hostname = db.Column(db.String(120), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    database = db.Column(db.String(120), nullable=False)
    commandTimeout = db.Column(db.Integer)
    maxTransportObjects = db.Column(db.Integer)
    username = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    selectedDB = db.Column(db.String(120), nullable=False)
    isAdmin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))

# Drop and recreate tables (for development only, comment out in production)
with app.app_context():
    # db.drop_all()
    db.create_all()

# Create a serializer for token handling
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def authenticate_user(username, password):
    error_message = "Unknown error occurred"
    try:
        print(f"Attempting LDAP authentication for user: {username}")

        safe_username = escape_rdn(username)
        safe_filter = escape_filter_chars(username)
        user_dn = LDAP_USER_DN_TEMPLATE.format(safe_username)

        server = Server(LDAP_SERVER, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=user_dn, password=password, 
                         auto_bind=AUTO_BIND_TLS_BEFORE_BIND, receive_timeout=10)

        if not conn.bound:
            return False, "LDAP bind failed. Invalid credentials or server issue."

        conn.search(LDAP_BASE_DN, 
                   f"(uid={safe_filter})", 
                   search_scope=SUBTREE, 
                   attributes=['cn', 'uid'])

        if conn.entries:
            user_entry = conn.entries[0]
            print(f"Authentication successful for: {user_entry}")
            return True, {
                "uid": user_entry.uid.value,
                "cn": user_entry.cn.value
            }
        return False, "User not found in LDAP directory."

    except Exception as e:
        error_message = f"LDAP Error: {str(e)}"
        print(f"Authentication Failed: {error_message}")
        return False, error_message

def user_exists_ldap(username):
    LDAP_SERVER = "150.239.171.184"
    LDAP_BASE_DN = "dc=example,dc=com"
    SERVICE_ACCOUNT_DN = "cn=admin,dc=example,dc=com"
    SERVICE_PASSWORD = "your_admin_password"
    
    conn = None
    try:
        server = Server(
            host=f"ldap://{LDAP_SERVER}",
            port=389,
            tls=Tls(
                validate=ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLSv1_2
            ),
            get_info=ALL
        )

        conn = Connection(
            server,
            user=SERVICE_ACCOUNT_DN,
            password=SERVICE_PASSWORD,
            auto_bind=True,
            authentication="SIMPLE"
        )

        search_params = {
            'search_base': LDAP_BASE_DN,
            'search_filter': f"(uid={escape_filter_chars(username)})",
            'search_scope': SUBTREE,
            'attributes': ['*', '+'],
            'size_limit': 2,
            'get_operational_attributes': True
        }

        if not conn.search(**search_params):
            print(f"Search failed: {conn.result}")
            return False

        return len(conn.entries) > 0

    except Exception as e:
        print(f"\n[Critical Error] {str(e)}")
        return False
    finally:
        if conn and not conn.closed:
            conn.unbind()

# Token verification decorator
def token_required(f):
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        elif request.json and 'token' in request.json:
            token = request.json.get('token')

        if not token:
            return jsonify({'message': 'Token is required'}), 401
        try:
            data = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'])
            request.user_email = data.get('user_email')
            request.uid = data.get('uid')
        except BadSignature:
            return jsonify({'message': 'Invalid token'}), 401
        # Skip Content-Type check for GET and DELETE, or POST without body
        if request.method in ['POST', 'PUT', 'PATCH'] and request.get_data() and request.content_type != 'application/json':
            return jsonify({"error": "Unsupported Media Type, Content-Type must be application/json"}), 415
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# Admin verification decorator
def admin_required(f):
    @token_required
    def decorated(*args, **kwargs):
        admin_email = request.user_email
        if not Admin.query.filter_by(email=admin_email).first():
            return jsonify({'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# User login route
@app.route('/login/user', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get("email")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # success, result = authenticate_user(username, password)
    success = True
    if success:
        token = serializer.dumps({'uid': "user1"}, salt=app.config['SECURITY_PASSWORD_SALT'])
        return jsonify({"message": "Login successful", "token": token}), 200
    else:
        return jsonify({"error": "result"}), 401

# Admin login route
@app.route('/login/admin', methods=['POST'])
def login_admin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400
    admin = Admin.query.filter_by(email=email).first()
    if admin and check_password_hash(admin.password, password):
        token = serializer.dumps({'user_email': email}, salt=app.config['SECURITY_PASSWORD_SALT'])
        return jsonify({'token': token, 'isAdmin': True}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# Token validation route
@app.route('/validate-token', methods=['POST'])
def validate_token():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({'message': 'Token is required', 'valid': False}), 400
    try:
        decoded_data = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'])
        if decoded_data.get('user_email'):
            email = decoded_data.get('user_email')
            admin = Admin.query.filter_by(email=email).first()
            is_admin = bool(admin)
            return jsonify({
                'message': 'Token is valid',
                'valid': True,
                'email': email,
                'isAdmin': is_admin
            }), 200
        elif decoded_data.get('uid'):
            uid = decoded_data.get('uid')
            return jsonify({
                'message': 'Token is valid',
                'valid': True,
                'uid': uid,
                'isAdmin': False 
            }), 200
        else:
            return jsonify({'message': 'Invalid token format', 'valid': False}), 401
    except BadSignature:
        return jsonify({'message': 'Invalid or expired token', 'valid': False}), 401

# Route to create a connection for regular users
@app.route('/connections/user/create', methods=['POST'])
@token_required
def create_user_connection():
    data = request.get_json()
    connection_details = data.get('connectionDetails', {})
    uid = request.uid

    password = connection_details.get('password', '')
    hashed_password = serializer.dumps({'password': password}, salt=app.config['SECURITY_PASSWORD_SALT'])

    new_connection = ConnectionDetails(
        uid=uid,
        connectionName=connection_details.get('connectionName', ''),
        description=connection_details.get('description', ''),
        hostname=connection_details.get('hostname', ''),
        port=connection_details.get('port', 0),
        database=connection_details.get('database', ''),
        username=connection_details.get('username', ''),
        password=hashed_password,
        selectedDB=connection_details.get('selectedDB', ''),
        isAdmin=False,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(new_connection)
    db.session.commit()
    return jsonify({'message': 'Connection created'}), 200

# Route to create a connection for admins
@app.route('/connections/admin/create', methods=['POST'])
@admin_required
def create_admin_connection():
    data = request.get_json()
    connection_details = data.get('connectionDetails', {})
    admin = Admin.query.filter_by(email=request.user_email).first()

    password = connection_details.get('password', '')
    hashed_password = serializer.dumps({'password': password}, salt=app.config['SECURITY_PASSWORD_SALT'])

    new_connection = ConnectionDetails(
        admin_id=admin.id,
        uid='',
        connectionName=connection_details.get('connectionName', ''),
        description=connection_details.get('description', ''),
        hostname=connection_details.get('hostname', ''),
        port=connection_details.get('port', 0),
        database=connection_details.get('database', ''),
        username=connection_details.get('username', ''),
        password=hashed_password,
        selectedDB=connection_details.get('selectedDB', ''),
        isAdmin=True,
        created_at=datetime.now(timezone.utc)
    )

    db.session.add(new_connection)
    db.session.commit()
    return jsonify({'message': 'Admin connection created'}), 200

# Route to get connections for regular users
@app.route('/connections/user/list', methods=['POST'])
@token_required
def get_user_connections():
    uid = request.uid

    user_connections = ConnectionDetails.query.filter(ConnectionDetails.uid == uid).all()
    admin_connections = ConnectionDetails.query.filter(ConnectionDetails.isAdmin == True).all()

    all_connections = user_connections + admin_connections

    connections_list = [
        {
            'id': conn.id,
            'connectionName': conn.connectionName,
            'description': conn.description,
            'uid': conn.uid,
            'hostname': conn.hostname,
            'port': conn.port,
            'database': conn.database,
            'username': conn.username,
            'password': conn.password,
            'commandTimeout': conn.commandTimeout,
            'maxTransportObjects': conn.maxTransportObjects,
            'selectedDB': conn.selectedDB,
            'created_at': conn.created_at.isoformat(),
            'isAdmin': conn.isAdmin
        }
        for conn in all_connections
    ]

    return jsonify({'connections': connections_list}), 200

# Route to get all connections for admins
@app.route('/connections/admin/list', methods=['POST'])
@admin_required
def get_admin_connections():
    all_connections = ConnectionDetails.query.filter(ConnectionDetails.isAdmin == True).all()
    connections_list = [
        {
            'id': conn.id,
            'connectionName': conn.connectionName,
            'description': conn.description,
            'uid': conn.uid,
            'hostname': conn.hostname,
            'port': conn.port,
            'database': conn.database,
            'username': conn.username,
            'password': conn.password,
            'commandTimeout': conn.commandTimeout,
            'maxTransportObjects': conn.maxTransportObjects,
            'selectedDB': conn.selectedDB,
            'created_at': conn.created_at.isoformat()
        }
        for conn in all_connections
    ]
    return jsonify({'connections': connections_list}), 200

# Route to delete a connection
@app.route('/connections/delete', methods=['POST'])
@token_required
def delete_connection():
    data = request.get_json()
    connection_id = data.get('connectionId')
    uid = request.uid
    email = request.user_email

    if uid:
        connection = ConnectionDetails.query.filter_by(
            id=connection_id,
            uid=uid,
            isAdmin=False
        ).first()
        if not connection:
            return jsonify({'message': 'Connection not found or not owned by user'}), 404
        db.session.delete(connection)
        db.session.commit()
        return jsonify({'message': 'Connection deleted'}), 200
    elif email:
        admin = Admin.query.filter_by(email=email).first()
        connection = ConnectionDetails.query.filter_by(
            id=connection_id,
            admin_id=admin.id,
            isAdmin=True
        ).first()
        if not connection:
            return jsonify({'message': 'Connection not found or not owned by admin'}), 404
        db.session.delete(connection)
        db.session.commit()
        return jsonify({'message': 'Connection deleted'}), 200
    else:
        return jsonify({'message': 'Invalid token'}), 401

# Route to set LDAP configuration
@app.route('/ldap-config', methods=['POST'])
@admin_required
def set_ldap_config():
    data = request.get_json().get('ldapConfig', {})
    
    required_fields = ['ldapHost', 'baseDn', 'userRdn', 'ldapPort']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    try:
        int(data['ldapPort'])
    except ValueError:
        return jsonify({"error": "LDAP_PORT must be an integer"}), 400
    
    set_key('.env', 'LDAP_SERVER', data['ldapHost'])
    set_key('.env', 'LDAP_BASE_DN', data['baseDn'])
    set_key('.env', 'LDAP_USER_RDN', data['userRdn'])
    set_key('.env', 'LDAP_PORT', str(data['ldapPort']))
    
    return jsonify({
        "LDAP_SERVER": data['ldapHost'],
        "LDAP_BASE_DN": data['baseDn'],
        "LDAP_USER_RDN": data['userRdn'],
        "LDAP_PORT": data['ldapPort']
    }), 200

# Route to get LDAP configuration
@app.route('/get-ldap-config', methods=['POST'])
@admin_required
def get_ldap_config():
    env_vars = dotenv_values('.env')
    config = {
        "LDAP_SERVER": env_vars.get("LDAP_SERVER", ""),
        "LDAP_BASE_DN": env_vars.get("LDAP_BASE_DN", ""),
        "LDAP_USER_RDN": env_vars.get("LDAP_USER_RDN", ""),
        "LDAP_PORT": env_vars.get("LDAP_PORT", "")
    }
    return jsonify(config)

# Route to create a session
@app.route('/api/sessions', methods=['POST'])
@token_required
def create_session():
    data = request.get_json()
    uid = request.uid
    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401

    title = data.get('title')
    if not title:
        return jsonify({"error": "Title is required"}), 400
    session = Session(
        uid=uid,
        title=title,
        timestamp=datetime.utcnow()
    )
    db.session.add(session)
    db.session.commit()
    return jsonify({
        "id": session.id,
        "title": session.title,
        "timestamp": session.timestamp.isoformat(),
        "messages": []
    }), 201

# Route to get all sessions for a user
@app.route('/api/fetchsessions', methods=['POST'])
@token_required
def get_sessions():
    uid = request.uid
    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401

    sessions = Session.query.filter_by(uid=uid).order_by(Session.timestamp.desc()).all()
    sessions_list = [
        {
            "id": session.id,
            "title": session.title,
            "timestamp": session.timestamp.isoformat(),
            "messages": [
                {
                    "id": msg.id,
                    "content": msg.content,
                    "isBot": msg.is_bot,
                    "isFavorited": msg.is_favorited,
                    "parentId": msg.parent_id,
                    "timestamp": msg.timestamp.isoformat(),
                    "favoriteCount": Favorite.query.filter_by(question_id=msg.id, uid=uid).first().count if Favorite.query.filter_by(question_id=msg.id, uid=uid).first() else 0
                }
                for msg in session.messages
            ]
        }
        for session in sessions
    ]
    return jsonify(sessions_list), 200

# Route to get a specific session
@app.route('/api/sessions/<session_id>', methods=['GET'])
@token_required
def get_session(session_id):
    uid = request.uid
    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401

    session = Session.query.filter_by(id=session_id, uid=uid).first()
    if not session:
        return jsonify({"error": "Session not found or unauthorized"}), 404

    messages = Message.query.filter_by(session_id=session_id).all()
    messages_list = [
        {
            "id": msg.id,
            "content": msg.content,
            "isBot": msg.is_bot,
            "isFavorited": msg.is_favorited,
            "parentId": msg.parent_id,
            "timestamp": msg.timestamp.isoformat(),
            "favoriteCount": Favorite.query.filter_by(question_id=msg.id, uid=uid).first().count if Favorite.query.filter_by(question_id=msg.id, uid=uid).first() else 0
        }
        for msg in messages
    ]
    return jsonify({
        "id": session.id,
        "title": session.title,
        "timestamp": session.timestamp.isoformat(),
        "messages": messages_list
    }), 200

# Route to delete a session
@app.route('/api/sessions/<session_id>', methods=['DELETE'])
@token_required
def delete_session(session_id):  # Added session_id parameter
    uid = request.uid
    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401

    session = Session.query.filter_by(id=session_id, uid=uid).first()
    if not session:
        return jsonify({"error": "Session not found or unauthorized"}), 404

    # Update favorite status for messages
    for msg in session.messages:
        msg.is_favorited = False
        Favorite.query.filter_by(question_id=msg.id, uid=uid).delete()
    Message.query.filter_by(session_id=session_id).delete()
    db.session.delete(session)
    db.session.commit()
    return jsonify({"message": "Session deleted"}), 200

# Route to create a message
@app.route('/api/messages', methods=['POST'])
@token_required
def create_message():
    data = request.get_json()
    uid = request.uid
    session_id = data.get('session_id')
    content = data.get('content')
    is_bot = data.get('isBot', False)
    parent_id = data.get('parentId', None)
    is_favorited = data.get('isFavorited', False)

    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401
    if not session_id or not content:
        return jsonify({"error": "Session ID and content are required"}), 400

    session = Session.query.filter_by(id=session_id, uid=uid).first()
    if not session:
        return jsonify({"error": "Session not found or unauthorized"}), 404

    if is_bot and parent_id:
        parent_message = Message.query.filter_by(id=parent_id, session_id=session_id).first()
        if not parent_message or parent_message.is_bot:
            return jsonify({"error": "Invalid parent message"}), 400

    message = Message(
        session_id=session_id,
        content=content,
        is_bot=is_bot,
        parent_id=parent_id,
        timestamp=datetime.utcnow(),
        is_favorited=is_favorited
    )
    favorite = Favorite.query.filter_by(question_content=content, uid=uid).first()
    if favorite:
        favorite.count += 1
    db.session.add(message)
    db.session.commit()
    return jsonify({
        "id": message.id,
        "content": message.content,
        "isBot": message.is_bot,
        "isFavorited": message.is_favorited,
        "parentId": message.parent_id,
        "timestamp": message.timestamp.isoformat(),
        "favoriteCount": 0
    }), 201

# Route to update a message
@app.route('/api/messages/<message_id>', methods=['PUT'])
@token_required
def update_message(message_id):
    data = request.get_json()
    uid = request.uid
    content = data.get('content')
    print(f"Updating message {message_id} for user {uid}")

    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401
    if not content:
        return jsonify({"error": "Content is required"}), 400

    message = Message.query.join(Session).filter(
        Message.id == message_id,
        Session.uid == uid
    ).first()
    print(f"Message found: {message}")
    if not message:
        return jsonify({"error": "Message not found or unauthorized"}), 404

    message.content = content
    message.is_favorited = False
    message.timestamp = datetime.utcnow()
    message.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"message": "Message updated"}), 200

# Route to favorite a message
@app.route('/favorite', methods=['POST'])
@token_required
def add_favorite():
    try:
        data = request.get_json()
        question_id = data.get('questionId')
        question_content = data.get('questionContent')
        uid = request.uid

        if not question_id or not uid or not question_content:
            return jsonify({'error': 'Question ID, question content, and user ID are required'}), 400

        # Validate question message
        question_message = Message.query.filter_by(id=question_id).first()
        if not question_message or question_message.is_bot:
            return jsonify({'error': 'Invalid question message'}), 400

        # Find response message using parent_id
        response_message = Message.query.filter_by(parent_id=question_id).first()
        response_id = response_message.id if response_message else None
        response_query = data.get('responseQuery') if response_message else None

        # Update favorite status
        question_message.is_favorited = True
        if response_message:
            response_message.is_favorited = True

        # Update favorite entry
        favorite = Favorite.query.filter_by(question_content=question_content, uid=uid).first()
        if favorite:
            favorite.count += 1
            favorite.question_content = question_content
            favorite.response_id = response_id
            favorite.response_query = response_query
        else:
            favorite = Favorite(
                question_id=question_id,
                question_content=question_content,
                response_id=response_id,
                response_query=response_query,
                count=1,
                uid=uid
            )
            db.session.add(favorite)

        db.session.commit()
        return jsonify({"message": "Message marked favorite successfully!", "count": favorite.count}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route to get favorites
@app.route('/favorites', methods=['POST'])
@token_required
def get_favorites():
    try:
        uid = request.uid
        favorites = Favorite.query.filter_by(uid=uid).all()
        favorites_list = [
            {
                'question_id': fav.question_id,
                'question': fav.question_content,
                'query': fav.response_query,
                'count': fav.count,
                'isFavorited': bool(Message.query.filter_by(id=fav.question_id, is_favorited=True).first())
            }
            for fav in favorites
        ]
        return jsonify(favorites_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route to unfavorite a message
@app.route('/unfavorite', methods=['POST'])
@token_required
def delete_favorite():
    try:
        data = request.get_json()
        question_id = data.get('questionId')
        uid = request.uid
        question_message = Message.query.filter_by(id=question_id).first()
        response_message = Message.query.filter_by(parent_id=question_id).first() 
        favorite = Favorite.query.filter_by(question_content=question_message.content, uid=uid).first()
        if not favorite:
            return jsonify({'error': 'Favorite not found'}), 404

        if favorite.count <= 1:
            # Remove favorite and update message status
            if question_message:
                question_message.is_favorited = False
            if response_message:
                response_message.is_favorited = False
            db.session.delete(favorite)
            count = 0
        else:
            favorite.count -= 1
            count = favorite.count

        # Update message status
        if question_message:
            question_message.is_favorited = False
        if response_message:
            response_message.is_favorited = False
        db.session.commit()
        return jsonify({'message': f'Favorite {question_id} updated', 'count': count}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route to force delete a favorite
@app.route('/favorite/delete', methods=['POST'])
@token_required
def force_delete_favorite():
    try:
        data = request.get_json()
        question_id = data.get('questionId')
        uid = request.uid

        # Find the favorite
        favorite = Favorite.query.filter_by(question_id=question_id, uid=uid).first()
        if not favorite:
            return jsonify({'error': 'Favorite not found'}), 404

        # Unfavorite all messages with the same content
        if favorite.question_content:
            matching_messages = Message.query.filter_by(content=favorite.question_content).all()
            for msg in matching_messages:
                 response_message = Message.query.filter_by(parent_id=msg.id).first()
                 if response_message:
                    response_message.is_favorited = False
                 msg.is_favorited = False

        # Delete favorite
        db.session.delete(favorite)
        db.session.commit()

        return jsonify({'message': f'Favorite {question_id} permanently deleted'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


# Run the application
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)