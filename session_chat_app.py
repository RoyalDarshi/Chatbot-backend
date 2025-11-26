from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv, dotenv_values, set_key
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature
from datetime import datetime, timezone, timedelta
from sqlalchemy import or_, func, and_
from werkzeug.security import check_password_hash, generate_password_hash
from ldap3 import Server, Connection, ALL, SUBTREE, AUTO_BIND_TLS_BEFORE_BIND, Tls
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn
import ssl
import json
import os
import uuid
import atexit
# from apscheduler.schedulers.background import BackgroundScheduler

# --- ADDED: Logging imports ---
import logging
from logging.handlers import RotatingFileHandler
import sys
# --- END ADDED ---

# Import database connection functions
import psycopg2
# import mysql.connector
# import pyodbc  # Added for MSSQL
import pymongo
import ibm_db  # <-- ADDED FOR DB2

# --- MODIFIED: Load .env first ---
load_dotenv()

# --- ADDED: Logging Configuration ---
LOG_FILE = os.getenv('LOG_FILE', 'app.log')
LOG_LEVEL_STR = os.getenv('LOG_LEVEL', 'INFO').upper()
LOG_LEVEL = getattr(logging, LOG_LEVEL_STR, logging.INFO)

# Formatter
log_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)'
)

# File Handler (Rotating)
try:
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=10*1024*1024, backupCount=5  # 10MB per file, 5 backups
    )
    file_handler.setFormatter(log_formatter)
except PermissionError:
    print(f"Warning: No permission to write to log file {LOG_FILE}. Logs will only go to console.")
    file_handler = None

# Console Handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_formatter)

# Root Logger Configuration
root_logger = logging.getLogger()
root_logger.setLevel(LOG_LEVEL)
root_logger.handlers.clear()  # Clear any default handlers
if file_handler:
    root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

# Set specific library log levels to be less noisy
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.WARNING) # Werkzeug is Flask's server
# --- END ADDED ---


app = Flask(__name__)
# --- MODIFIED: Set Flask's logger level from our config ---
app.logger.setLevel(LOG_LEVEL)

CORS(app, resources={r"/*": {"origins": "*"}})
# load_dotenv() # --- MODIFIED: Moved to top ---

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
# scheduler = BackgroundScheduler()

# def check_stalled_messages():
#     with app.app_context():
#         try:
#             ten_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=10) # <-- Aware time
#             stalled_messages = Message.query.filter(
#                 Message.is_bot == True,
#                 Message.status == 'loading',
#                 Message.created_at <= ten_minutes_ago
#             ).all()
            
#             # --- MODIFIED: Replaced print with logger ---
#             app.logger.debug(f"[Scheduler] Now: {datetime.utcnow()} | Checking messages older than: {ten_minutes_ago}")
            
#             if len(stalled_messages) > 0:
#                 app.logger.warning(f"[Scheduler] Found stalled messages: {len(stalled_messages)}")

#                 for message in stalled_messages:
#                     app.logger.warning(f"⏳ Stalled message detected: {message.id} (created at {message.created_at})")
#                     message.content = "Sorry, an error occurred. Please try again."
#                     message.status = 'normal'
#                     message.updated_at = datetime.utcnow()
#                     session = Session.query.filter_by(id=message.session_id).first()
#                     if session:
#                         session.timestamp = datetime.utcnow()
#                 db.session.commit()
#             else:
#                 app.logger.debug("[Scheduler] No stalled messages found.")
                
#         except Exception as e:
#             # --- MODIFIED: Replaced print with logger ---
#             app.logger.error(f"❌ Error in check_stalled_messages: {str(e)}", exc_info=True)
#             db.session.rollback()

# scheduler.add_job(check_stalled_messages, 'interval', minutes=10)
# scheduler.start()


# Shutdown hook to clean up loading messages
def cleanup_loading_messages():
    with app.app_context():
        app.logger.info("Running shutdown hook: cleanup_loading_messages...") # --- ADDED ---
        try:
            stalled_messages = Message.query.filter_by(status='loading', is_bot=True).all()
            if stalled_messages:
                app.logger.warning(f"Found {len(stalled_messages)} loading messages to clean up.")
                for message in stalled_messages:
                    message.content = "Sorry, an error occurred. Please try again."
                    message.status = 'error' # <-- MODIFIED TO 'error'
                    message.updated_at = datetime.now(timezone.utc)
                    session = Session.query.filter_by(id=message.session_id).first()
                    if session:
                        session.timestamp = datetime.now(timezone.utc)
                db.session.commit()
            app.logger.info("Shutdown hook finished.") # --- ADDED ---
        except Exception as e:
            # --- MODIFIED: Replaced print with logger ---
            app.logger.error(f"Error in cleanup_loading_messages: {str(e)}", exc_info=True)
            db.session.rollback()

atexit.register(cleanup_loading_messages)

# --- ADDED: Request/Error Logging ---
@app.before_request
def log_request_info():
    if request.path == '/health': # Optional: skip logging for health checks
        return
    log_data = f"Request: {request.method} {request.path} - From: {request.remote_addr}"
    if request.data:
        try:
            # Try to log JSON, but truncate if it's too large
            json_body = request.get_json()
            log_data += f" - Body: {str(json_body)[:200]}..."
        except Exception:
            log_data += " - Body: [Non-JSON Data]"
    app.logger.info(log_data)

@app.after_request
def log_response_info(response):
    if request.path == '/health':
        return response
    app.logger.info(f"Response: {request.method} {request.path} - Status: {response.status_code}")
    return response

@app.errorhandler(Exception)
def handle_unhandled_exception(e):
    # Log the full exception traceback
    app.logger.error(f"Unhandled Exception on endpoint {request.path}: {str(e)}", exc_info=True)
    # Return a generic 500 error to the client
    return jsonify({"error": "An internal server error occurred. Please try again later."}), 500
# --- END ADDED ---


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
        # --- ADDED: Exception logging ---
        app.logger.error(f"PostgreSQL connection failed: {str(e)}", exc_info=True)
        return f"PostgreSQL connection failed: {str(e)}", 400
    except psycopg2.Error as e:
        # --- ADDED: Exception logging ---
        app.logger.error(f"PostgreSQL general error: {str(e)}", exc_info=True)
        return f"PostgreSQL general error: {str(e)}", 500
    except Exception as e:
        # --- ADDED: Exception logging ---
        app.logger.error(f"PostgreSQL unexpected error: {str(e)}", exc_info=True)
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
        # --- ADDED: Exception logging ---
        app.logger.error(f"MySQL connection failed: {str(e)}", exc_info=True)
        return f"MySQL connection failed: {str(e)}", 400
    except Exception as e:
        # --- ADDED: Exception logging ---
        app.logger.error(f"MySQL unexpected error: {str(e)}", exc_info=True)
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
        # --- ADDED: Exception logging ---
        app.logger.error(f"MS SQL connection failed: {str(e)}", exc_info=True)
        return f"MS SQL connection failed: {str(e)}", 400
    except Exception as e:
        # --- ADDED: Exception logging ---
        app.logger.error(f"MS SQL unexpected error: {str(e)}", exc_info=True)
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
        # --- ADDED: Exception logging ---
        app.logger.error(f"MongoDB missing required connection parameter: {str(e)}", exc_info=True)
        return f"Missing required connection parameter: {str(e)}", 400
    except pymongo.errors.ServerSelectionTimeoutError as e:
        # --- ADDED: Exception logging ---
        app.logger.error(f"MongoDB connection timeout: {str(e)}", exc_info=True)
        return f"MongoDB connection timeout: {str(e)}", 408
    except pymongo.errors.ConnectionFailure as e:
        # --- ADDED: Exception logging ---
        app.logger.error(f"MongoDB connection failed: {str(e)}", exc_info=True)
        return f"MongoDB connection failed: {str(e)}", 400
    except pymongo.errors.PyMongoError as e:
        # --- ADDED: Exception logging ---
        app.logger.error(f"MongoDB general error: {str(e)}", exc_info=True)
        return f"MongoDB general error: {str(e)}", 500
    except Exception as e:
        # --- ADDED: Exception logging ---
        app.logger.error(f"MongoDB unexpected error: {str(e)}", exc_info=True)
        return f"MongoDB unexpected error: {str(e)}", 500
    finally:
        if client is not None:
            client.close()

# --- ADDED: DB2 Connection Function ---
# def connect_db2(connection_params):
#     conn = None
#     try:
#         hostname = connection_params['hostname']
#         port = connection_params['port']
#         database = connection_params['database']
#         username = connection_params['username']
#         password = connection_params['password']

#         # Create the DSN string for the connection
#         # --- MODIFIED: Trying 'Authentication=SERVER;' as 'PLAINTEXT' failed ---
#         dsn = (
#             f"DATABASE={database};"
#             f"HOSTNAME={hostname};"
#             f"PORT={port};"
#             f"PROTOCOL=TCPIP;"
#             f"Authentication=SERVER;"  # <-- This is the new fix to try
#         )
        
#         # Attempt to connect
#         conn = ibm_db.connect(dsn, username, password)
        
#         if conn:
#             return "DB2 connection successful!", 200
#         else:
#             # Get the error message from the ibm_db driver
#             error_msg = ibm_db.conn_errormsg()
#             app.logger.warning(f"DB2 connection failed: {error_msg}")
#             return f"DB2 connection failed: {error_msg}", 400

#     except KeyError as e:
#         app.logger.error(f"DB2 missing required connection parameter: {str(e)}", exc_info=True)
#         return f"Missing required connection parameter: {str(e)}", 400
#     except Exception as e:
#         # Catch other errors
#         error_msg = str(e)
#         try:
#             # Try to get a more specific DB2 error if available
#             error_msg = ibm_db.conn_errormsg() or error_msg
#         except:
#             pass # ibm_db might not be available to get the error
#         app.logger.error(f"DB2 unexpected error: {error_msg}", exc_info=True)
#         return f"DB2 unexpected error: {error_msg}", 500
#     finally:
#         if conn:
#             try:
#                 ibm_db.close(conn)
#             except Exception as e:
#                 app.logger.error(f"Error closing DB2 connection: {str(e)}", exc_info=True)
#                 pass
# # --- END ADDED ---

 
def test_db2_connection(connection_params):
    """Attempts to connect to DB2 and run a simple query."""
    
    # 1. Construct the Connection String (DSN)
    dsn = (
        "DATABASE={db};"
        "HOSTNAME={host};"
        "PORT={port};"
        "UID={user};"
        "PWD={pwd};"
    ).format(
        db=connection_params['database'],
        host=connection_params['hostname'],
        port=connection_params['port'],
        user=connection_params['username'],
        pwd=connection_params['password']
    )

    conn = None
    
    app.logger.info(f"Attempting to connect to DB2 at {connection_params['hostname']}:{connection_params['port']}...")
    
    try:
        # 2. Establish the Connection
        conn = ibm_db.connect(dsn, "", "")
        app.logger.info("✅ SUCCESS: Connection to DB2 server established.")

        # 3. Test with a Trivial Query
        sql = "SELECT 'Connection Test Successful' FROM SYSIBM.SYSDUMMY1"
        stmt = ibm_db.exec_immediate(conn, sql)
        
        if stmt:
            result = ibm_db.fetch_row(stmt)
            if result:
                test_message = ibm_db.result(stmt, 0)
                app.logger.info(f"✅ QUERY SUCCESS: Received expected test message: '{test_message}'")
                # --- ADDED: Return success tuple ---
                return "DB2 connection successful!", 200
            else:
                app.logger.warning("❌ QUERY FAILED: Could not retrieve data from SYSDUMMY1.")
                # --- ADDED: Return failure tuple ---
                return "DB2 connection succeeded, but query failed.", 400
        else:
            app.logger.warning("❌ QUERY FAILED: Statement execution failed.")
            # --- ADDED: Return failure tuple ---
            return "DB2 connection succeeded, but query execution failed.", 400

    except Exception as e:
        # 4. Handle Connection Errors
        app.logger.error("❌ DB2 CONNECTION FAILED")
        
        # Get the specific DB2 error message
        error_msg = ibm_db.conn_errormsg()
        if not error_msg:
             # Fallback if conn_errormsg() is empty
            error_msg = str(e) 
            
        app.logger.error(f"DRIVER ERROR: {error_msg}", exc_info=True)
        
        # --- ADDED: Return failure tuple ---
        return f"DB2 connection failed: {error_msg}", 400
    
    finally:
        # 5. Clean up the connection
        if conn:
            try:
                ibm_db.close(conn)
                app.logger.info("DB2 Connection closed.")
            except Exception as e:
                app.logger.error(f"Error closing DB2 connection: {str(e)}", exc_info=True)

db_functions = {
    'postgresql': connect_postgresql,
    'mysql': connect_mysql,
    'mssql': connect_mssql,
    'mongodb': connect_mongodb,
    'db2': test_db2_connection  # <-- ADDED
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

def seed_initial_users():
    """
    Checks if users exist in the database.
    If not, creates default users automatically.
    """
    try:
        # Check if any user exists to avoid duplicates
        if User.query.first() is not None:
            app.logger.info("Database already contains users. Skipping auto-population.")
            return

        app.logger.info("No users found. seeding default users...")

        users = [
            {
                'username': 'user1',
                'email': 'user1@example.com',
                'password': 'user1' # Plain text here, will be hashed below
            },
            {
                'username': 'user2',
                'email': 'user2@example.com',
                'password': 'user2'
            },
            {
                'username': 'user3',
                'email': 'user3@example.com',
                'password': 'user3'
            },
            {
                'username': 'user4',
                'email': 'user4@example.com',
                'password': 'user4'
            }
        ]

        for user_data in users:
            # Hash the password before storing
            hashed_pw = generate_password_hash(user_data['password'])
            
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                password=hashed_pw
            )
            db.session.add(user)

        db.session.commit()
        app.logger.info(f"Successfully auto-populated {len(users)} default users.")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error during user auto-population: {str(e)}", exc_info=True)

with app.app_context():
    db.create_all()
    seed_initial_users()

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def authenticate_user(username, password):
    error_message = "Unknown error occurred"
    try:
        # --- MODIFIED: Replaced print with logger ---
        app.logger.info(f"Attempting LDAP authentication for user: {username}")
        safe_username = escape_rdn(username)
        safe_filter = escape_filter_chars(username)
        user_dn = LDAP_USER_DN_TEMPLATE.format(safe_username)
        server = Server(LDAP_SERVER, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=user_dn, password=password, 
                        auto_bind=AUTO_BIND_TLS_BEFORE_BIND, receive_timeout=10)
        if not conn.bound:
            # --- ADDED: Logging ---
            app.logger.warning(f"LDAP bind failed for user: {username}. Invalid credentials or server issue.")
            return False, "LDAP bind failed. Invalid credentials or server issue."
        conn.search(LDAP_BASE_DN, 
                   f"(uid={safe_filter})", 
                   search_scope=SUBTREE, 
                   attributes=['cn', 'uid'])
        if conn.entries:
            user_entry = conn.entries[0]
            # --- MODIFIED: Replaced print with logger ---
            app.logger.info(f"Authentication successful for: {user_entry.uid.value}")
            return True, {
                "uid": user_entry.uid.value,
                "cn": user_entry.cn.value
            }
        # --- ADDED: Logging ---
        app.logger.warning(f"LDAP user not found in directory: {username}")
        return False, "User not found in LDAP directory."
    except Exception as e:
        error_message = f"LDAP Error: {str(e)}"
        # --- MODIFIED: Replaced print with logger ---
        app.logger.error(f"Authentication Failed for user {username}: {error_message}", exc_info=True)
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
            # --- MODIFIED: Replaced print with logger ---
            app.logger.warning(f"LDAP search failed for user {username}: {conn.result}")
            return False
        return len(conn.entries) > 0
    except Exception as e:
        # --- MODIFIED: Replaced print with logger ---
        app.logger.critical(f"[Critical Error] LDAP user_exists check failed: {str(e)}", exc_info=True)
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
            app.logger.warning("Token is required but not provided.") # --- ADDED ---
            return jsonify({'message': 'Token is required'}), 401
        try:
            data = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'])
            request.user_email = data.get('user_email')
            request.uid = data.get('uid')
        except BadSignature:
            app.logger.warning("Invalid token received.") # --- ADDED ---
            return jsonify({'message': 'Invalid token'}), 401
        if request.method in ['POST', 'PUT', 'PATCH'] and request.get_data() and request.content_type != 'application/json':
            app.logger.warning("Unsupported Media Type (non-JSON) received.") # --- ADDED ---
            return jsonify({"error": "Unsupported Media Type, Content-Type must be application/json"}), 415
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def admin_required(f):
    @token_required
    def decorated(*args, **kwargs):
        admin_email = request.user_email
        if not Admin.query.filter_by(email=admin_email).first():
            # --- ADDED: Logging ---
            app.logger.error(f"Admin access required for {request.path}, but user '{admin_email}' is not an admin.")
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
        app.logger.info(f"User '{username}' logged in successfully.") # --- ADDED ---
        return jsonify({"message": "Login successful", "token": token}), 200
    
    app.logger.warning(f"Failed login attempt for user: '{username}'.") # --- ADDED ---
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
        app.logger.info(f"Admin '{email}' logged in successfully.") # --- ADDED ---
        return jsonify({'token': token, 'isAdmin': True}), 200
    
    app.logger.warning(f"Failed login attempt for admin: '{email}'.") # --- ADDED ---
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
            app.logger.debug(f"Validated admin token for: {email}") # --- ADDED ---
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
                app.logger.warning(f"Token validation failed: User UID '{uid}' not found.") # --- ADDED ---
                return jsonify({'message': 'User not found', 'valid': False}), 401
            app.logger.debug(f"Validated user token for: {uid}") # --- ADDED ---
            return jsonify({
                'message': 'Token is valid',
                'valid': True,
                'uid': uid,
                'isAdmin': False 
            }), 200
        else:
            app.logger.warning("Token validation failed: Invalid token format.") # --- ADDED ---
            return jsonify({'message': 'Invalid token format', 'valid': False}), 401
    except BadSignature:
        app.logger.warning("Token validation failed: Invalid or expired token.") # --- ADDED ---
        return jsonify({'message': 'Invalid or expired token', 'valid': False}), 401
    except Exception as e: # --- ADDED: General exception handling ---
        app.logger.error(f"Error during token validation: {str(e)}", exc_info=True)
        return jsonify({'message': 'An error occurred during token validation', 'valid': False}), 500

@app.route('/user/change-password', methods=['POST'])
@token_required
def change_password():
    try:
        data = request.get_json()
        uid = request.uid
        old_password = data.get('oldPassword')
        new_password = data.get('newPassword')

        if not uid:
             return jsonify({"error": "User identification failed"}), 401
        
        if not old_password or not new_password:
            return jsonify({"error": "Old and new passwords are required"}), 400

        user = User.query.filter_by(id=uid).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        # 1. Verify the old password
        if not check_password_hash(user.password, old_password):
             return jsonify({"error": "Incorrect current password"}), 401
        
        # 2. Hash and save the new password
        user.password = generate_password_hash(new_password)
        db.session.commit()
        
        app.logger.info(f"Password changed successfully for user {uid}")
        return jsonify({"message": "Password changed successfully"}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error changing password for {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to change password'}), 500

@app.route('/connections/user/create', methods=['POST'])
@token_required
def create_user_connection():
    # --- ADDED: try/except block ---
    try:
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
        app.logger.info(f"User {uid} created connection '{new_connection.connectionName}'.") # --- ADDED ---
        return jsonify({'message': 'Connection created'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating user connection for {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to create connection'}), 500

@app.route('/connections/admin/create', methods=['POST'])
@admin_required
def create_admin_connection():
    # --- ADDED: try/except block ---
    try:
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
        app.logger.info(f"Admin {request.user_email} created connection '{new_connection.connectionName}'.") # --- ADDED ---
        return jsonify({'message': 'Admin connection created'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating admin connection for {request.user_email}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to create admin connection'}), 500

@app.route('/connections/user/list', methods=['POST'])
@token_required
def get_user_connections():
    # --- ADDED: try/except block ---
    try:
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
    except Exception as e:
        app.logger.error(f"Error fetching user connections for {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to fetch connections'}), 500

@app.route('/connections/admin/list', methods=['POST'])
@admin_required
def get_admin_connections():
    # --- ADDED: try/except block ---
    try:
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
    except Exception as e:
        app.logger.error(f"Error fetching admin connections for {request.user_email}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to fetch admin connections'}), 500

@app.route('/connections/delete', methods=['POST'])
@token_required
def delete_connection():
    # --- ADDED: try/except block ---
    try:
        data = request.get_json()
        connection_id = data.get('connectionId')
        uid = request.uid
        email = request.user_email
        connection_name_for_log = "" # --- ADDED ---
        
        if uid:
            connection = ConnectionDetails.query.filter_by(
                id=connection_id,
                uid=uid,
                isAdmin=False
            ).first()
        elif email:
            admin = Admin.query.filter_by(email=email).first()
            if not admin: # --- ADDED: Check if admin exists ---
                app.logger.error(f"Admin not found for email {email} during connection delete.")
                return jsonify({'message': 'Invalid token'}), 401
            connection = ConnectionDetails.query.filter_by(
                id=connection_id,
                admin_id=admin.id,
                isAdmin=True
            ).first()
        else:
            return jsonify({'message': 'Invalid token'}), 401
        
        if not connection:
            app.logger.warning(f"Connection not found or unauthorized for deletion. ID: {connection_id}, User: {uid or email}") # --- ADDED ---
            return jsonify({'message': 'Connection not found or unauthorized'}), 404
        
        connection_name_for_log = connection.connectionName # --- ADDED ---
        db.session.delete(connection)
        
        # --- ADDED: Log cascading updates ---
        app.logger.info(f"Updating sessions associated with deleted connection '{connection_name_for_log}'")
        Session.query.filter_by(connection_name=connection.connectionName).update({Session.connection_name: ''})
        
        app.logger.info(f"Updating favorites associated with deleted connection '{connection_name_for_log}'")
        Favorite.query.filter_by(connection_name=connection.connectionName).update({Favorite.connection_name: ''})
        
        db.session.commit()
        app.logger.info(f"Connection '{connection_name_for_log}' (ID: {connection_id}) deleted by {uid or email}.") # --- ADDED ---
        return jsonify({'message': 'Connection deleted'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting connection {connection_id} for {uid or email}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to delete connection'}), 500

@app.route('/ldap-config', methods=['POST'])
@admin_required
def set_ldap_config():
    # --- ADDED: try/except block ---
    try:
        data = request.get_json().get('ldapConfig', {})
        required_fields = ['ldapHost', 'baseDn', 'userRdn', 'ldapPort']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        try:
            int(data['ldapPort'])
        except ValueError:
            return jsonify({"error": "LDAP_PORT must be an integer"}), 400
        
        app.logger.warning(f"Admin {request.user_email} is updating LDAP configuration.") # --- ADDED ---
        set_key('.env', 'LDAP_SERVER', data['ldapHost'])
        set_key('.env', 'LDAP_BASE_DN', data['baseDn'])
        set_key('.env', 'LDAP_USER_RDN', data['userRdn'])
        set_key('.env', 'LDAP_PORT', str(data['ldapPort']))
        app.logger.info("LDAP configuration updated successfully.") # --- ADDED ---
        
        return jsonify({
            "LDAP_SERVER": data['ldapHost'],
            "LDAP_BASE_DN": data['baseDn'],
            "LDAP_USER_RDN": data['userRdn'],
            "LDAP_PORT": data['ldapPort']
        }), 200
    except Exception as e:
        app.logger.error(f"Error setting LDAP config by {request.user_email}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to set LDAP configuration'}), 500

@app.route('/get-ldap-config', methods=['POST'])
@admin_required
def get_ldap_config():
    # --- ADDED: try/except block ---
    try:
        env_vars = dotenv_values('.env')
        config = {
            "LDAP_SERVER": env_vars.get("LDAP_SERVER", ""),
            "LDAP_BASE_DN": env_vars.get("LDAP_BASE_DN", ""),
            "LDAP_USER_RDN": env_vars.get("LDAP_USER_RDN", ""),
            "LDAP_PORT": env_vars.get("LDAP_PORT", "")
        }
        return jsonify(config)
    except Exception as e:
        app.logger.error(f"Error getting LDAP config by {request.user_email}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to get LDAP configuration'}), 500

@app.route('/api/sessions', methods=['POST'])
@token_required
def create_session():
    # --- ADDED: try/except block ---
    try:
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
        app.logger.info(f"User {uid} created new session '{session.id}' with title '{title}'.") # --- ADDED ---
        return jsonify({
            "id": session.id,
            "title": session.title,
            "timestamp": session.timestamp.isoformat(),
            "messages": []
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating session for user {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to create session'}), 500

@app.route('/api/fetchsessions', methods=['POST'])
@token_required
def get_sessions():
    try:
        uid = request.uid
        data = request.get_json()
        filter_type = data.get('filter', 'all') # Get filter from request
        
        if not uid:
            return jsonify({"error": "Invalid token, UID required"}), 401

        # Base query
        query = Session.query.filter_by(uid=uid)

        # Date Filtering Logic
        now_utc = datetime.now(timezone.utc)
        today_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
        
        if filter_type == 'today':
            query = query.filter(Session.timestamp >= today_start)
        elif filter_type == 'yesterday':
            yesterday_start = today_start - timedelta(days=1)
            query = query.filter(and_(Session.timestamp >= yesterday_start, Session.timestamp < today_start))
        elif filter_type == 'last7days':
            seven_days_ago = today_start - timedelta(days=7)
            # Exclude today/yesterday if you want strict ranges, 
            # but usually "last 7 days" implies a range up to now. 
            # Based on your previous frontend logic, it was 2 to 7 days ago.
            # We will use the standard "past 7 days including today" or match your specific previous logic.
            # Matching previous logic: 7 days ago up to 2 days ago
            two_days_ago = today_start - timedelta(days=2)
            query = query.filter(and_(Session.timestamp >= seven_days_ago, Session.timestamp <= two_days_ago))
        elif filter_type == 'last1month':
            thirty_days_ago = today_start - timedelta(days=30)
            eight_days_ago = today_start - timedelta(days=8)
            query = query.filter(and_(Session.timestamp >= thirty_days_ago, Session.timestamp <= eight_days_ago))
        
        # Order by timestamp descending
        sessions = query.order_by(Session.timestamp.desc()).all()
        
        sessions_list = []
        
        for session in sessions:
            # OPTIMIZATION: Do not fetch all messages. 
            # 1. Get Count
            msg_count = Message.query.filter_by(session_id=session.id).count()

            # 2. Get Preview (First User Message)
            # We explicitly look for a message that has content to use as a preview
            first_msg = Message.query.filter(
                Message.session_id == session.id,
                Message.content != None,
                Message.content != ""
            ).order_by(Message.timestamp.asc()).first()
            
            preview_text = "No messages"
            if first_msg:
                preview_text = first_msg.content[:60] + ("..." if len(first_msg.content) > 60 else "")

            sessions_list.append({
                "id": session.id,
                "title": session.title,
                "connection": session.connection_name,
                "timestamp": session.timestamp.isoformat(),
                "messages": [], # Sending empty array to keep type consistency but save bandwidth
                "messageCount": msg_count, # New field
                "preview": preview_text    # New field
            })
            
        return jsonify(sessions_list), 200
    except Exception as e:
        app.logger.error(f"Error fetching sessions for user {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to fetch sessions'}), 500

@app.route('/api/sessions/<session_id>', methods=['GET'])
@token_required
def get_session(session_id):
    # --- ADDED: try/except block ---
    try:
        uid = request.uid
        if not uid:
            return jsonify({"error": "Invalid token, UID required"}), 401
        session = Session.query.filter_by(id=session_id, uid=uid).first()
        if not session:
            app.logger.warning(f"User {uid} failed to get session: Not found or unauthorized for session {session_id}.") # --- ADDED ---
            return jsonify({"error": "Session not found or unauthorized"}), 404
        
        messages = Message.query.filter_by(session_id=session_id).order_by(Message.timestamp.asc()).all()
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
        # db.session.commit() # --- REMOVED: No changes are made, commit is unnecessary ---
        return jsonify({
            "id": session.id,
            "title": session.title,
            "connection": session.connection_name,
            "timestamp": session.timestamp.isoformat(),
            "messages": messages_list
        }), 200
    except Exception as e:
        app.logger.error(f"Error fetching session {session_id} for user {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to fetch session'}), 500

@app.route('/api/sessions/<session_id>', methods=['PUT'])
@token_required
def update_session(session_id):
    # --- ADDED: try/except block ---
    try:
        data = request.get_json()
        uid = request.uid
        title = data.get('title')
        if not uid:
            return jsonify({"error": "Invalid token, UID required"}), 401
        if not title:
            return jsonify({"error": "Title is required"}), 400
        
        session = Session.query.filter_by(id=session_id, uid=uid).first()
        if not session:
            app.logger.warning(f"User {uid} failed to update session: Not found or unauthorized for session {session_id}.") # --- ADDED ---
            return jsonify({"error": "Session not found or unauthorized"}), 404
        
        session.title = title
        session.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        app.logger.info(f"User {uid} updated session '{session_id}' title to '{title}'.") # --- ADDED ---
        return jsonify({
            "id": session.id,
            "title": session.title,
            "timestamp": session.timestamp.isoformat(),
            "messages": []
        }), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating session {session_id} for user {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to update session'}), 500

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
@token_required
def delete_session(session_id):
    # --- ADDED: try/except block ---
    try:
        uid = request.uid
        if not uid:
            return jsonify({"error": "Invalid token, UID required"}), 401
        
        session = Session.query.filter_by(id=session_id, uid=uid).first()
        if not session:
            app.logger.warning(f"User {uid} failed to delete session: Not found or unauthorized for session {session_id}.") # --- ADDED ---
            return jsonify({"error": "Session not found or unauthorized"}), 404
        
        Message.query.filter_by(session_id=session_id).delete()
        db.session.delete(session)
        db.session.commit()
        app.logger.info(f"User {uid} deleted session '{session_id}'.") # --- ADDED ---
        return jsonify({"message": "Session deleted"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting session {session_id} for user {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to delete session'}), 500

@app.route('/api/messages', methods=['POST'])
@token_required
def create_message():
    # --- ADDED: try/except block ---
    try:
        data = request.get_json()
        uid = request.uid
        session_id = data.get('session_id')
        content = data.get('content')
        is_bot = data.get('isBot', False)
        parent_id = data.get('parentId', None)
        status = data.get('status', 'normal') # <-- ADDED
        
        if not uid:
            return jsonify({"error": "Invalid token, UID required"}), 401
        if not session_id:
            return jsonify({"error": "Session ID are required"}), 400
        
        session = Session.query.filter_by(id=session_id, uid=uid).first()
        if not session:
            app.logger.warning(f"User {uid} failed to create message: Session not found or unauthorized for session {session_id}.") # --- ADDED ---
            return jsonify({"error": "Session not found or unauthorized"}), 404
        
        if is_bot and parent_id:
            parent_message = Message.query.filter_by(id=parent_id, session_id=session_id).first()
            if not parent_message or parent_message.is_bot:
                app.logger.error(f"Invalid parent message {parent_id} for bot reply in session {session_id}.") # --- ADDED ---
                return jsonify({"error": "Invalid parent message"}), 400
        
        # Ensure status is valid
        if status not in ['normal', 'loading', 'error']:
            app.logger.warning(f"Invalid status '{status}' provided. Defaulting to 'normal'.")
            status = 'normal'

        message = Message(
            session_id=session_id,
            content=content,
            is_bot=is_bot,
            parent_id=parent_id,
            timestamp=datetime.now(timezone.utc),
            is_favorited=False,
            status=status  # <-- MODIFIED
        )
        session.timestamp = datetime.now(timezone.utc)
        db.session.add(message)
        db.session.commit()
        
        # --- ADDED: Logging ---
        log_content = (content[:50] + '...') if len(content) > 50 else content
        app.logger.info(f"User {uid} created message '{message.id}' in session '{session_id}'. Bot: {is_bot}. Status: {status}. Content: '{log_content}'")
        
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
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating message for user {request.uid} in session {session_id}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to create message'}), 500

@app.route('/api/messages/<message_id>', methods=['PUT'])
@token_required
def update_message(message_id):
    # --- ADDED: try/except block ---
    try:
        data = request.get_json()
        uid = request.uid
        content = data.get('content')
        status = data.get('status') # <-- ADDED

        if not uid:
            return jsonify({"error": "Invalid token, UID required"}), 401
        
        message = Message.query.join(Session).filter(
            Message.id == message_id,
            Session.uid == uid
        ).first()
        if not message:
            app.logger.warning(f"User {uid} failed to update message: Not found or unauthorized for message {message_id}.") # --- ADDED ---
            return jsonify({"error": "Message not found or unauthorized"}), 404
        
        # --- MODIFIED: This query was redundant, already joined above ---
        session = Session.query.filter_by(id=message.session_id, uid=uid).first()
        if not session:
            # This check is technically redundant if the join succeeded, but good for safety.
            app.logger.error(f"Data integrity issue: Message {message_id} found but session {message.session_id} not found for user {uid}.") # --- ADDED ---
            return jsonify({"error": "Session not found or unauthorized"}), 404
        
        if content is not None:
            message.content = content
        
        if status is not None:
             # Ensure status is valid
            if status not in ['normal', 'loading', 'error']:
                app.logger.warning(f"Invalid status '{status}' provided for update. Ignoring status update.")
            else:
                message.status = status
        
        message.timestamp = datetime.now(timezone.utc)
        message.updated_at = datetime.now(timezone.utc)
        session.timestamp = datetime.now(timezone.utc)
        db.session.commit()
        app.logger.info(f"User {uid} updated message '{message_id}'. Status: {message.status}.") # --- ADDED ---
        return jsonify({"message": "Message updated"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating message {message_id} for user {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to update message'}), 500

@app.route('/api/getmessages/<message_id>', methods=['POST'])
@token_required
def get_message(message_id):
    # --- ADDED: try/except block ---
    try:
        uid = request.uid
        if not uid:
            return jsonify({"error": "Invalid token, UID required"}), 401
        
        message = Message.query.filter_by(id=message_id).first()
        if not message:
            return jsonify({"error": "Message not found"}), 404
        
        session = Session.query.filter_by(id=message.session_id, uid=uid).first()
        if not session:
            app.logger.warning(f"User {uid} failed to get message: Unauthorized for message {message_id}.") # --- ADDED ---
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
    except Exception as e:
        app.logger.error(f"Error getting message {message_id} for user {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to get message'}), 500

@app.route('/api/messages/<message_id>/reaction', methods=['POST'])
@token_required
def set_message_reaction(message_id):
    # --- ADDED: try/except block ---
    try:
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
            app.logger.warning(f"User {uid} failed to set reaction: Unauthorized for message {message_id}.") # --- ADDED ---
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
        app.logger.info(f"User {uid} set reaction '{reaction}' for message '{message_id}'.") # --- ADDED ---
        return jsonify({"message": "Reaction set successfully"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error setting reaction for message {message_id} by user {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to set reaction'}), 500

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
        app.logger.info(f"User {uid} favorited message '{question_id}'. New count: {favorite_entry.count}") # --- ADDED ---
        return jsonify({"message": "Message marked favorite successfully!", "isFavorited": True, "count": favorite_entry.count}), 201
    except Exception as e:
        db.session.rollback()
        # --- MODIFIED: Replaced print with logger ---
        app.logger.error(f"Error in add_favorite for user {request.uid}, question {data.get('questionId')}: {str(e)}", exc_info=True)
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
            # increase count with 1
            fav.count += 1
            db.session.commit()
            
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
        # --- ADDED: Exception logging ---
        app.logger.error(f"Error in get_favorites for user {request.uid}: {str(e)}", exc_info=True)
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
        app.logger.info(f"User {uid} unfavorited message '{question_id}'. New count: {count_after_decrement}") # --- ADDED ---
        return jsonify({'message': f'Favorite updated, count: {count_after_decrement}', 'count': count_after_decrement, 'isFavorited': False}), 200
    except Exception as e:
        db.session.rollback()
        # --- MODIFIED: Replaced print with logger ---
        app.logger.error(f"Error in delete_favorite for user {request.uid}, question {data.get('questionId')}: {str(e)}", exc_info=True)
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
        app.logger.info(f"User {uid} force-deleted favorite for message '{question_id}'.") # --- ADDED ---
        return jsonify({'message': f'Favorite for question {question_id} updated and potentially deleted'}), 200
    except Exception as e:
        db.session.rollback()
        # --- MODIFIED: Replaced print with logger ---
        app.logger.error(f"Error in force_delete_favorite for user {request.uid}, question {data.get('questionId')}: {str(e)}", exc_info=True)
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
        # --- ADDED: Exception logging ---
        app.logger.error(f"Error in get_recommended_questions for user {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/settings', methods=['POST'])
@token_required
def get_user_settings():
    try:
        uid = request.uid
        settings = UserSettings.query.filter_by(uid=uid).first()
        if not settings:
            app.logger.info(f"No settings found for user {uid}, creating default settings.") # --- ADDED ---
            settings = UserSettings(uid=uid)
            db.session.add(settings)
            db.session.commit()
        return jsonify({
            'chatFontSize': settings.chat_font_size,
            'notificationsEnabled': settings.notifications_enabled,
        }), 200
    except Exception as e:
        db.session.rollback() # --- ADDED: Rollback on error ---
        # --- ADDED: Exception logging ---
        app.logger.error(f"Error in get_user_settings for user {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/createsettings', methods=['POST'])
@token_required
def update_user_settings():
    try:
        data = request.get_json().get('settings', {})
        uid = request.uid
        settings = UserSettings.query.filter_by(uid=uid).first()
        if not settings:
            app.logger.info(f"No settings found for user {uid} during update, creating new settings entry.") # --- ADDED ---
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
        app.logger.info(f"User {uid} updated settings: {data}") # --- ADDED ---
        return jsonify({'message': 'Settings updated'}), 200
    except Exception as e:
        db.session.rollback()
        # --- ADDED: Exception logging ---
        app.logger.error(f"Error in update_user_settings for user {request.uid}: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/testdbcon', methods=['POST'])
def test_db_connection():
    try:
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
        
        app.logger.info(f"Testing DB connection for {db_type} at {data.get('hostname')}:{data.get('port')}...") # --- ADDED ---
        
        message, status_code = db_functions[db_type](connection_params)
        
        if status_code == 200:
            app.logger.info(f"DB connection test successful for {db_type}.") # --- ADDED ---
        else:
            app.logger.warning(f"DB connection test failed for {db_type}. Status: {status_code}, Msg: {message}") # --- ADDED ---
            
        return jsonify({'message': message}), status_code
    except Exception as e:
        # --- ADDED: Exception logging ---
        app.logger.error(f"Error in test_db_connection: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    host = '0.0.0.0' # --- ADDED ---
    
    # --- ADDED: Startup log message ---
    app.logger.info(f"Starting Session Chat App on {host}:{port}...")
    app.logger.info(f"Log Level set to: {LOG_LEVEL_STR}")
    app.logger.info(f"Logging to file: {LOG_FILE}")

    # scheduler.add_job(check_stalled_messages, 'interval', minutes=10)
    # scheduler.start()
    # use_reloader=False
    
    app.run(host=host, port=port, debug=True)