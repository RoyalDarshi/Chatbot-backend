from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv, dotenv_values, set_key
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature
from datetime import datetime, timezone, timedelta
from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash
from ldap3 import Server, Connection, ALL, SUBTREE, AUTO_BIND_TLS_BEFORE_BIND, Tls
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn
import ssl
import json
import os
import uuid
import atexit
from apscheduler.schedulers.background import BackgroundScheduler

# Import database connection functions
import psycopg2
import mysql.connector
import pyodbc  # Added for MSSQL
# import pyodbc  # Added for MSSQL
import pymongo

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT', 'your-salt')

LDAP_SERVER = "ldap://150.239.171.184"
LDAP_BASE_DN = "dc=150,dc=239,dc=171,dc=184"
LDAP_USER_DN_TEMPLATE = "uid={},ou=people," + LDAP_BASE_DN
LDAP_PORT = 389
LDAP_SEARCH_FILTER = "(uid=%s)"

db = SQLAlchemy(app)

# Initialize the scheduler for checking stalled messages
scheduler = BackgroundScheduler()

def check_stalled_messages():
    with app.app_context():
        try:
            two_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=2)
            stalled_messages = Message.query.filter(
                Message.status == 'loading',
                Message.created_at <= two_minutes_ago
            ).all()
            for message in stalled_messages:
                message.content = "Sorry, an error occurred. Please try again."
                message.status = 'normal'
                message.updated_at = datetime.now(timezone.utc)
                session = Session.query.filter_by(id=message.session_id).first()
                if session:
                    session.timestamp = datetime.now(timezone.utc)
            db.session.commit()
        except Exception as e:
            print(f"Error in check_stalled_messages: {str(e)}")
            db.session.rollback()

scheduler.add_job(check_stalled_messages, 'interval', minutes=1)
scheduler.start()

# Shutdown hook to clean up loading messages
def cleanup_loading_messages():
    with app.app_context():
        try:
            stalled_messages = Message.query.filter_by(status='loading').all()
            for message in stalled_messages:
                message.content = "Sorry, an error occurred. Please try again."
                message.status = 'normal'
                message.updated_at = datetime.now(timezone.utc)
                session = Session.query.filter_by(id=message.session_id).first()
                if session:
                    session.timestamp = datetime.now(timezone.utc)
            db.session.commit()
        except Exception as e:
            print(f"Error in cleanup_loading_messages: {str(e)}")
            db.session.rollback()

atexit.register(cleanup_loading_messages)

# Define the database connection functions
def connect_postgresql(connection_params):
    conn = None
    try:
        connection_params['host'] = connection_params.pop('hostname')
        connection_params['user'] = connection_params.pop('username')
        connection_params['dbname'] = connection_params.pop('database')
        connection_params['connect_timeout'] = 5
        conn = psycopg2.connect(**connection_params)
        return "PostgreSQL connection successful!", 200
    except psycopg2.OperationalError as e:
        return f"PostgreSQL connection failed: {str(e)}", 400
    except psycopg2.Error as e:
        return f"PostgreSQL general error: {str(e)}", 500
    except Exception as e:
        return f"PostgreSQL unexpected error: {str(e)}", 500
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

def connect_mysql(connection_params):
    conn = None
    try:
        conn = mysql.connector.connect(**connection_params)
        return "MySQL connection successful!", 200
    except mysql.connector.Error as e:
        return f"MySQL connection failed: {str(e)}", 400
    except Exception as e:
        return f"MySQL unexpected error: {str(e)}", 500
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

def connect_mssql(connection_params):
    conn = None
    try:
        conn = pyodbc.connect(**connection_params)
        return "MS SQL connection successful!", 200
    except pyodbc.Error as e:
        return f"MS SQL connection failed: {str(e)}", 400
    except Exception as e:
        return f"MS SQL unexpected error: {str(e)}", 500
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

def connect_mongodb(connection_params):
    client = None
    try:
        username = connection_params.get('username', 'root')
        password = connection_params['password']
        hostname = connection_params['hostname']
        port = connection_params.get('port', 27017)
        database = connection_params.get('database', 'admin')
        uri = f"mongodb://{username}:{password}@{hostname}:{port}/{database}"
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.server_info()
        return "MongoDB connection successful!", 200
    except KeyError as e:
        return f"Missing required connection parameter: {str(e)}", 400
    except pymongo.errors.ServerSelectionTimeoutError as e:
        return f"MongoDB connection timeout: {str(e)}", 408
    except pymongo.errors.ConnectionFailure as e:
        return f"MongoDB connection failed: {str(e)}", 400
    except pymongo.errors.PyMongoError as e:
        return f"MongoDB general error: {str(e)}", 500
    except Exception as e:
        return f"MongoDB unexpected error: {str(e)}", 500
    finally:
        if client is not None:
            client.close()

db_functions = {
    'postgresql': connect_postgresql,
    'mysql': connect_mysql,
    'mssql': connect_mssql,
    'mongodb': connect_mongodb
}

# Define the User model
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Session(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    uid = db.Column(db.String(255), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    connection_name = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = db.Column(db.String(36), db.ForeignKey('session.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_bot = db.Column(db.Boolean, default=False, nullable=False)
    is_favorited = db.Column(db.Boolean, default=False, nullable=False)
    parent_id = db.Column(db.String(36), db.ForeignKey('message.id'), nullable=True)
    reaction = db.Column(db.String(10), nullable=True)
    dislike_reason = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    status = db.Column(db.String(20), default='normal', nullable=False, index=True)  # Added status field
    session = db.relationship('Session', backref=db.backref('messages', lazy=True))
    parent = db.relationship('Message', remote_side=[id], backref='responses')

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.String(255), nullable=False)
    question_content = db.Column(db.String(500), nullable=False)
    response_id = db.Column(db.String(255), nullable=True)
    response_query = db.Column(db.String(500), nullable=True)
    connection_name = db.Column(db.String(255), nullable=False)
    uid = db.Column(db.String(255), nullable=False)
    count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('question_content', 'connection_name', 'uid', name='_user_content_connection_uc'),)

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

class UserSettings(db.Model):
    uid = db.Column(db.String(255), primary_key=True)
    theme = db.Column(db.String(10), default='light')
    chat_font_size = db.Column(db.String(10), default='medium')
    notifications_enabled = db.Column(db.Boolean, default=True)
    auto_save_chats = db.Column(db.Boolean, default=True)

with app.app_context():
    db.create_all()

# Route to populate users (for development/testing only)
@app.route('/populate-users', methods=['POST'])
# @admin_required
def populate_users():
    try:
        # Check if users already exist to avoid duplicates
        if User.query.count() > 0:
            return jsonify({'message': 'Users already populated'}), 400

        users = [
            {
                'username': 'user1',
                'email': 'user1@example.com',
                'password': generate_password_hash('user1')
            },
            {
                'username': 'user2',
                'email': 'user2@example.com',
                'password': generate_password_hash('user2')
            },
            {
                'username': 'user3',
                'email': 'user3@example.com',
                'password': generate_password_hash('user3')
            },
            {
                'username': 'user4',
                'email': 'user4@example.com',
                'password': generate_password_hash('user4')
            }
        ]

        for user_data in users:
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                password=user_data['password']
            )
            db.session.add(user)

        db.session.commit()
        return jsonify({'message': '4 users created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

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
        if request.method in ['POST', 'PUT', 'PATCH'] and request.get_data() and request.content_type != 'application/json':
            return jsonify({"error": "Unsupported Media Type, Content-Type must be application/json"}), 415
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def admin_required(f):
    @token_required
    def decorated(*args, **kwargs):
        admin_email = request.user_email
        if not Admin.query.filter_by(email=admin_email).first():
            return jsonify({'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

@app.route('/login/user', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get("email")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        token = serializer.dumps({'uid': user.id}, salt=app.config['SECURITY_PASSWORD_SALT'])
        return jsonify({"message": "Login successful", "token": token}), 200
    return jsonify({"error": "Invalid credentials"}), 401

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
            user = User.query.filter_by(id=uid).first()
            if not user:
                return jsonify({'message': 'User not found', 'valid': False}), 401
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
    elif email:
        admin = Admin.query.filter_by(email=email).first()
        connection = ConnectionDetails.query.filter_by(
            id=connection_id,
            admin_id=admin.id,
            isAdmin=True
        ).first()
    else:
        return jsonify({'message': 'Invalid token'}), 401
    if not connection:
        return jsonify({'message': 'Connection not found or unauthorized'}), 404
    db.session.delete(connection)
    Session.query.filter_by(connection_name=connection.connectionName).update({Session.connection_name: ''})
    Favorite.query.filter_by(connection_name=connection.connectionName).update({Favorite.connection_name: ''})
    db.session.commit()
    return jsonify({'message': 'Connection deleted'}), 200

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
    connection=data.get('currentConnection')
    if not connection:
        return jsonify({"error": "Connection is required"}), 400
    session = Session(
        uid=uid,
        title=title,
        connection_name=connection,
        timestamp=datetime.now(timezone.utc)
    )
    db.session.add(session)
    db.session.commit()
    return jsonify({
        "id": session.id,
        "title": session.title,
        "timestamp": session.timestamp.isoformat(),
        "messages": []
    }), 201

@app.route('/api/fetchsessions', methods=['POST'])
@token_required
def get_sessions():
    uid = request.uid
    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401
    sessions = Session.query.filter_by(uid=uid).order_by(Session.timestamp.desc()).all()
    sessions_list = []
    for session in sessions:
        messages_list = []
        for msg in session.messages:
            favorite_count = 0
            if not msg.is_bot:
                favorite_entry = Favorite.query.filter_by(
                    question_content=msg.content,
                    uid=uid,
                    connection_name=session.connection_name
                ).first()
                if favorite_entry:
                    favorite_count = favorite_entry.count
            messages_list.append({
                "id": msg.id,
                "content": msg.content,
                "isBot": msg.is_bot,
                "isFavorited": msg.is_favorited,
                "parentId": msg.parent_id,
                "timestamp": msg.timestamp.isoformat(),
                "reaction": msg.reaction,
                "dislike_reason": msg.dislike_reason,
                "favoriteCount": favorite_count,
                "status": msg.status  # Added status
            })
        sessions_list.append({
            "id": session.id,
            "title": session.title,
            "connection": session.connection_name,
            "timestamp": session.timestamp.isoformat(),
            "messages": messages_list
        })
    return jsonify(sessions_list), 200

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
    messages_list = []
    for msg in messages:
        favorite_count = 0
        if not msg.is_bot:
            favorite_entry = Favorite.query.filter_by(
                question_content=msg.content,
                uid=uid,
                connection_name=session.connection_name
            ).first()
            if favorite_entry:
                favorite_count = favorite_entry.count
        messages_list.append({
            "id": msg.id,
            "content": msg.content,
            "isBot": msg.is_bot,
            "isFavorited": msg.is_favorited,
            "parentId": msg.parent_id,
            "timestamp": msg.timestamp.isoformat(),
            "reaction": msg.reaction,
            "dislike_reason": msg.dislike_reason,
            "favoriteCount": favorite_count,
            "status": msg.status  # Added status
        })
    db.session.commit()
    return jsonify({
        "id": session.id,
        "title": session.title,
        "connection": session.connection_name,
        "timestamp": session.timestamp.isoformat(),
        "messages": messages_list
    }), 200

@app.route('/api/sessions/<session_id>', methods=['PUT'])
@token_required
def update_session(session_id):
    data = request.get_json()
    uid = request.uid
    title = data.get('title')
    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401
    if not title:
        return jsonify({"error": "Title is required"}), 400
    session = Session.query.filter_by(id=session_id, uid=uid).first()
    if not session:
        return jsonify({"error": "Session not found or unauthorized"}), 404
    session.title = title
    session.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({
        "id": session.id,
        "title": session.title,
        "timestamp": session.timestamp.isoformat(),
        "messages": []
    }), 200

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
@token_required
def delete_session(session_id):
    uid = request.uid
    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401
    session = Session.query.filter_by(id=session_id, uid=uid).first()
    if not session:
        return jsonify({"error": "Session not found or unauthorized"}), 404
    Message.query.filter_by(session_id=session_id).delete()
    db.session.delete(session)
    db.session.commit()
    return jsonify({"message": "Session deleted"}), 200

@app.route('/api/messages', methods=['POST'])
@token_required
def create_message():
    data = request.get_json()
    uid = request.uid
    session_id = data.get('session_id')
    content = data.get('content')
    is_bot = data.get('isBot', False)
    parent_id = data.get('parentId', None)
    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401
    if not session_id:
        return jsonify({"error": "Session ID are required"}), 400
    session = Session.query.filter_by(id=session_id, uid=uid).first()
    if not session:
        return jsonify({"error": "Session not found or unauthorized"}), 404
    if is_bot and parent_id:
        parent_message = Message.query.filter_by(id=parent_id, session_id=session_id).first()
        if not parent_message or parent_message.is_bot:
            return jsonify({"error": "Invalid parent message"}), 400
    status = 'loading' if content == 'loading...' else 'normal'
    message = Message(
        session_id=session_id,
        content=content,
        is_bot=is_bot,
        parent_id=parent_id,
        timestamp=datetime.now(timezone.utc),
        is_favorited=False,
        status=status  # Added status
    )
    session.timestamp = datetime.now(timezone.utc)
    db.session.add(message)
    db.session.commit()
    return jsonify({
        "id": message.id,
        "content": message.content,
        "isBot": message.is_bot,
        "isFavorited": message.is_favorited,
        "parentId": message.parent_id,
        "timestamp": message.timestamp.isoformat(),
        "reaction": message.reaction,
        "dislike_reason": message.dislike_reason,
        "favoriteCount": 0,
        "status": message.status  # Added status
    }), 201

@app.route('/api/messages/<message_id>', methods=['PUT'])
@token_required
def update_message(message_id):
    data = request.get_json()
    uid = request.uid
    content = data.get('content')
    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401
    message = Message.query.join(Session).filter(
        Message.id == message_id,
        Session.uid == uid
    ).first()
    if not message:
        return jsonify({"error": "Message not found or unauthorized"}), 404
    session = Session.query.filter_by(id=message.session_id, uid=uid).first()
    if not session:
        return jsonify({"error": "Session not found or unauthorized"}), 404
    message.content = content
    message.timestamp = datetime.now(timezone.utc)
    message.updated_at = datetime.now(timezone.utc)
    session.timestamp = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"message": "Message updated"}), 200

@app.route('/api/getmessages/<message_id>', methods=['POST'])
@token_required
def get_message(message_id):
    uid = request.uid
    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401
    message = Message.query.filter_by(id=message_id).first()
    if not message:
        return jsonify({"error": "Message not found"}), 404
    session = Session.query.filter_by(id=message.session_id, uid=uid).first()
    if not session:
        return jsonify({"error": "Unauthorized access to message"}), 403
    response = {
        "id": message.id,
        "content": message.content,
        "isBot": message.is_bot,
        "isFavorited": message.is_favorited,
        "parentId": message.parent_id,
        "timestamp": message.timestamp.isoformat(),
        "reaction": message.reaction,
        "dislike_reason": message.dislike_reason,
        "status": message.status  # Added status
    }
    return jsonify(response), 200

@app.route('/api/messages/<message_id>/reaction', methods=['POST'])
@token_required
def set_message_reaction(message_id):
    data = request.get_json()
    reaction = data.get('reaction')
    dislike_reason = data.get('dislike_reason')
    uid = request.uid
    if not uid:
        return jsonify({"error": "Invalid token, UID required"}), 401
    message = Message.query.filter_by(id=message_id).first()
    if not message:
        return jsonify({"error": "Message not found"}), 404
    session = Session.query.filter_by(id=message.session_id, uid=uid).first()
    if not session:
        return jsonify({"error": "Unauthorized access to message"}), 403
    if not message.is_bot:
        return jsonify({"error": "Can only set reaction for bot messages"}), 400
    if reaction not in ['like', 'dislike', None]:
        return jsonify({"error": "Invalid reaction value"}), 400
    if reaction == 'dislike' and not dislike_reason:
        return jsonify({"error": "Dislike reason is required when disliking"}), 400
    message.reaction = reaction
    if reaction == 'dislike':
        message.dislike_reason = dislike_reason
    else:
        message.dislike_reason = None
    db.session.commit()
    return jsonify({"message": "Reaction set successfully"}), 200

@app.route('/favorite', methods=['POST'])
@token_required
def add_favorite():
    try:
        data = request.get_json()
        question_id = data.get('questionId')
        question_content = data.get('questionContent')
        connection = data.get('currentConnection')
        uid = request.uid
        response_query = data.get('responseQuery')
        if not question_id or not uid or not question_content or not connection:
            return jsonify({'error': 'Question ID, content, connection, and user ID are required'}), 400
        question_message = Message.query.filter_by(id=question_id).first()
        if not question_message or question_message.is_bot:
            return jsonify({'error': 'Invalid question message for favoriting'}), 400
        response_message = Message.query.filter_by(parent_id=question_id).first()
        response_id = response_message.id if response_message else None
        question_message.is_favorited = True
        if response_message:
            response_message.is_favorited = True
        favorite_entry = Favorite.query.filter_by(
            question_content=question_content,
            connection_name=connection,
            uid=uid
        ).first()
        if favorite_entry:
            favorite_entry.count += 1
            favorite_entry.question_id = question_id
            favorite_entry.response_id = response_id
            favorite_entry.response_query = response_query
        else:
            favorite_entry = Favorite(
                question_id=question_id,
                question_content=question_content,
                response_id=response_id,
                response_query=response_query,
                connection_name=connection,
                count=1,
                uid=uid
            )
            db.session.add(favorite_entry)
        db.session.commit()
        return jsonify({"message": "Message marked favorite successfully!", "isFavorited": True, "count": favorite_entry.count}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in add_favorite: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/favorites', methods=['POST'])
@token_required
def get_favorites():
    try:
        uid = request.uid
        favorites = Favorite.query.filter_by(uid=uid).order_by(Favorite.count.desc()).all()
        favorites_list = []
        for fav in favorites:
            question_msg = Message.query.filter_by(id=fav.question_id).first()
            is_favorited_in_message = question_msg.is_favorited if question_msg else False
            favorites_list.append({
                'question_id': fav.question_id,
                'question': fav.question_content,
                'query': fav.response_query,
                'count': fav.count,
                'isFavorited': is_favorited_in_message,
                'connection': fav.connection_name,
                'timestamp': fav.updated_at.isoformat(),
            })
        return jsonify(favorites_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/unfavorite', methods=['POST'])
@token_required
def delete_favorite():
    try:
        data = request.get_json()
        question_id = data.get('questionId')
        uid = request.uid
        current_connection = data.get('currentConnection')
        question_content = data.get('questionContent')
        if not question_id or not uid or not current_connection or not question_content:
            return jsonify({'error': 'Question ID, content, connection, and user ID are required'}), 400
        question_message = Message.query.filter_by(id=question_id).first()
        if not question_message:
            return jsonify({'error': 'Question message not found'}), 404
        response_message = Message.query.filter_by(parent_id=question_id).first()
        favorite_entry = Favorite.query.filter_by(
            question_content=question_content,
            uid=uid,
            connection_name=current_connection
        ).first()
        if not favorite_entry:
            return jsonify({'error': 'Favorite entry not found for this content and connection'}), 404
        favorite_entry.count -= 1
        count_after_decrement = favorite_entry.count
        if favorite_entry.count <= 0:
            db.session.delete(favorite_entry)
            count_after_decrement = 0
        if question_message:
            question_message.is_favorited = False
        if response_message:
            response_message.is_favorited = False
        db.session.commit()
        return jsonify({'message': f'Favorite updated, count: {count_after_decrement}', 'count': count_after_decrement, 'isFavorited': False}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in delete_favorite: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/favorite/delete', methods=['POST'])
@token_required
def force_delete_favorite():
    try:
        data = request.get_json()
        question_id = data.get('questionId')
        uid = request.uid
        if not question_id or not uid:
            return jsonify({'error': 'Question ID and user ID are required'}), 400
        question_message = Message.query.filter_by(id=question_id).first()
        if not question_message:
            return jsonify({'error': 'Question message not found'}), 404
        favorite_entry_for_content = Favorite.query.filter_by(
            question_content=question_message.content,
            uid=uid,
            connection_name=question_message.session.connection_name
        ).first()
        if not favorite_entry_for_content:
            return jsonify({'error': 'Favorite entry not found for this content'}), 404
        favorite_entry_for_content.count -= 1
        if favorite_entry_for_content.count <= 0:
            db.session.delete(favorite_entry_for_content)
        question_message.is_favorited = False
        response_message = Message.query.filter_by(parent_id=question_id).first()
        if response_message:
            response_message.is_favorited = False
        db.session.commit()
        return jsonify({'message': f'Favorite for question {question_id} updated and potentially deleted'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error in force_delete_favorite: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/recommended_questions', methods=['POST'])
@token_required
def get_recommended_questions():
    try:
        uid = request.uid
        recommended = Favorite.query.filter(
            Favorite.uid == uid,
            Favorite.count > 3,
            Favorite.connection_name !="",
        ).order_by(Favorite.count.desc()).limit(3).all()
        recommended_list = [
            {
                'question_id': fav.question_id,
                'question': fav.question_content,
                'query': fav.response_query,
                'count': fav.count,
                "connection": fav.connection_name,
            }
            for fav in recommended
        ]
        return jsonify(recommended_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/settings', methods=['POST'])
@token_required
def get_user_settings():
    try:
        uid = request.uid
        settings = UserSettings.query.filter_by(uid=uid).first()
        if not settings:
            settings = UserSettings(uid=uid)
            db.session.add(settings)
            db.session.commit()
        return jsonify({
            'chatFontSize': settings.chat_font_size,
            'notificationsEnabled': settings.notifications_enabled,
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/createsettings', methods=['POST'])
@token_required
def update_user_settings():
    try:
        data = request.get_json().get('settings', {})
        uid = request.uid
        settings = UserSettings.query.filter_by(uid=uid).first()
        if not settings:
            settings = UserSettings(uid=uid)
            db.session.add(settings)
        if 'theme' in data:
            settings.theme = data['theme']
        if 'chatFontSize' in data:
            settings.chat_font_size = data['chatFontSize']
        if 'notificationsEnabled' in data:
            settings.notifications_enabled = data['notificationsEnabled']
        if 'autoSaveChats' in data:
            settings.auto_save_chats = data['autoSaveChats']
        db.session.commit()
        return jsonify({'message': 'Settings updated'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/testdbcon', methods=['POST'])
def test_db_connection():
    data = request.get_json().get('connectionDetails')
    db_type = data.get('selectedDB')
    if db_type not in db_functions:
        return jsonify({'error': 'Unsupported or missing database type'}), 400
    connection_params = {
        'hostname': data.get('hostname'),
        'port': data.get('port'),
        'username': data.get('username'),
        'password': data.get('password'),
        'database': data.get('database')
    }
    if not all(connection_params.values()):
        return jsonify({'error': 'All connection parameters are required'}), 400
    try:
        message, status_code = db_functions[db_type](connection_params)
        return jsonify({'message': message}), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)