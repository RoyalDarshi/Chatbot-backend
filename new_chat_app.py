from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv, dotenv_values, set_key
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature
from datetime import datetime, timezone
from sqlalchemy import or_
from werkzeug.security import check_password_hash,generate_password_hash
from ldap3 import Server, Connection, ALL, SUBTREE,AUTO_BIND_TLS_BEFORE_BIND,Tls
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn
import ssl
import json
import os

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
# LDAP_SERVER = "ldap://150.239.171.184:389"  # Replace with your RHDS server
# LDAP_BASE_DN = "dc=example,dc=com"
# LDAP_USER_DN_TEMPLATE = "uid={},ou=users,dc=example,dc=com"

# LDAP_SERVER = "ldap://150.239.171.184:389" # Replace with your RHDS server
# LDAP_BASE_DN = "dc=150,dc=239,dc=171,dc=184"
# LDAP_USER_DN_TEMPLATE = "uid={},ou=people,dc=150,dc=239,dc=171,dc=184"

# LDAP_SERVER = "ldap://150.239.171.184:389" # Replace with your RHDS server
# LDAP_BASE_DN = "dc=150,dc=239,dc=171,dc=184"
# LDAP_USER_DN_TEMPLATE = "uid={},ou=people,dc=150,dc=239,dc=171,dc=184"

LDAP_SERVER = "ldap://150.239.171.184"
LDAP_BASE_DN = "dc=150,dc=239,dc=171,dc=184"
LDAP_USER_DN_TEMPLATE = "uid={},ou=people," + LDAP_BASE_DN  # Ensure it's UID-based
LDAP_PORT = 389  # or 636 for LDAPS
LDAP_SEARCH_FILTER = "(uid=%s)" # for search

# ldapsearch -x -H ldap://150.239.171.184:389 -D "uid=user1,ou=people,dc=150,dc=239,dc=171,dc=184" -w user1

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define the Admin model
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

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

# Drop and recreate tables (for development only)
with app.app_context():
    # db.drop_all()  # Drop existing tables
    db.create_all()  # Recreate tables with updated schema

# Create a serializer for token handling
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# def authenticate_user(username, password):
#     try:
#         print("username: " + username)
#         # Initialize LDAP connection
#         server = Server(LDAP_SERVER, get_info=ALL)
#         conn = Connection(server,user=LDAP_USER_DN_TEMPLATE.format(username), password=password, auto_bind=True,receive_timeout=5 )
#         print(conn)
#         # Search for user details
#         conn.search(LDAP_BASE_DN, f"(uid={username})", search_scope=SUBTREE, attributes=['cn', 'uid'])
#         if conn.entries:
#             user_entry = conn.entries[0]
#             return True, {"uid": user_entry.uid.value, "cn": user_entry.cn.value}
#         return False, None
#     except Exception as e:
#         return False, str(e)

#  def authenticate_user(username, password):
#     error_message = "Unknown error occurred" # Initialize error message
#     try:
#         print(f"Attempting LDAP authentication for user: {username}")

#         # Initialize LDAP connection
#         server = Server(LDAP_SERVER, get_info=ALL)
#         user_dn = LDAP_USER_DN_TEMPLATE.format(username)
#         conn = Connection(server, user=user_dn, password=password, auto_bind=AUTO_BIND_NO_TLS, receive_timeout=10)

#         print(f"LDAP Connection Status: {conn.result}")

#         # Ensure bind was successful before searching
#         if not conn.bind():
#             return False, "LDAP bind failed."

#         # Search for user details
#         conn.search(LDAP_BASE_DN, f"(uid={username})", search_scope=SUBTREE, attributes=['cn', 'uid'])

#         if conn.entries:
#             user_entry = conn.entries[0]
#             print(user_entry)
#             return True, {"uid": user_entry.uid.value, "cn": user_entry.cn.value}
#         else:
#             return False, "User not found in LDAP."

#     except Exception as e:
#         error_message = str(e) # Capture the error message
#         print(f"LDAP Authentication Failed: {error_message}")

#     return False, error_message # Return the stored error message

def authenticate_user(username, password):
    error_message = "Unknown error occurred"
    try:
        print(f"Attempting LDAP authentication for user: {username}")

        # Escape username to prevent LDAP injection
        safe_username = escape_rdn(username)
        safe_filter = escape_filter_chars(username)

        # Construct user DN safely using the escaped username
        user_dn = LDAP_USER_DN_TEMPLATE.format(safe_username)

        # Initialize secure LDAP connection with TLS
        server = Server(LDAP_SERVER, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=user_dn, password=password, 
                         auto_bind=AUTO_BIND_TLS_BEFORE_BIND, receive_timeout=10)

        # Check if binding was successful
        if not conn.bound:
            return False, "LDAP bind failed. Invalid credentials or server issue."

        # Search for user details with safe filter
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
    
# Token verification decorator
def token_required(f):
    def decorated(*args, **kwargs):
        token = request.json.get('token', '')
        if not token:
            return jsonify({'message': 'Token is required'}), 401
        try:
            data = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'])
            request.user_email = data.get('user_email')
        except BadSignature:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# Admin verification decorator
def admin_required(f):
    @token_required
    def decorated(*args, **kwargs):
        admin_email=request.user_email
        if not Admin.query.filter_by(email=admin_email).first():
            return jsonify({'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def user_exists_ldap(username):
    """LDAP user check with service account authentication and permission debugging"""
    # Configuration - Update these values
    LDAP_SERVER = "150.239.171.184"
    LDAP_BASE_DN = "dc=example,dc=com"  # Start with root domain
    SERVICE_ACCOUNT_DN = "cn=admin,dc=example,dc=com"
    SERVICE_PASSWORD = "your_admin_password"
    
    conn = None
    try:
        # 1. Configure secure connection
        server = Server(
            host=f"ldap://{LDAP_SERVER}",
            port=389,
            tls=Tls(
                validate=ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLSv1_2
            ),
            get_info=ALL
        )

        # 2. Authenticate with service account
        conn = Connection(
            server,
            user=SERVICE_ACCOUNT_DN,
            password=SERVICE_PASSWORD,
            auto_bind=True,
            authentication="SIMPLE"
        )
        
        # 3. Verify authentication
        print("\n[Authentication Verification]")
        print(f"Bound DN: {conn.extend.standard.who_am_i()}")
        print(f"Server Info: {server.info}")

        # 4. Configure search with diagnostic attributes
        search_params = {
            'search_base': LDAP_BASE_DN,
            'search_filter': f"(uid={escape_filter_chars(username)})",
            'search_scope': SUBTREE,
            'attributes': ['*', '+'],  # Request all operational attributes
            'size_limit': 2,
            'get_operational_attributes': True
        }

        # 5. Execute search with error checking
        print("\n[Search Execution]")
        if not conn.search(**search_params):
            print(f"Search failed: {conn.result}")
            print("Potential causes:")
            print("- Insufficient permissions (ACL restrictions)")
            print("- Invalid search base/filter")
            return False

        # 6. Analyze results
        print("\n[Search Results Analysis]")
        print(f"Entries found: {len(conn.entries)}")
        print(f"Response type: {conn.result['type']}")
        print(f"Server response: {conn.result['description']}")
        
        if len(conn.entries) == 0:
            print("\n[Debugging Steps]")
            print("1. Verify the user exists in the directory:")
            print(f"   ldapsearch -H ldap://{LDAP_SERVER} -D '{SERVICE_ACCOUNT_DN}' -w {SERVICE_PASSWORD} -b '{LDAP_BASE_DN}' '(uid={username})'")
            print("2. Check service account permissions:")
            print(f"   ldapsearch -H ldap://{LDAP_SERVER} -D '{SERVICE_ACCOUNT_DN}' -w {SERVICE_PASSWORD} -b '{SERVICE_ACCOUNT_DN}' aclRights")

        return len(conn.entries) > 0

    except Exception as e:
        print(f"\n[Critical Error] {str(e)}")
        return False
    finally:
        if conn and not conn.closed:
            conn.unbind()

# User login route
@app.route('/login/user', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get("email")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # success, result = authenticate_user(username, password)
    success=True
    if success:
        # print(result)
        # token=serializer.dumps({'uid': result.get("uid")}, salt=app.config['SECURITY_PASSWORD_SALT'])
        token=serializer.dumps({'uid': "user1"}, salt=app.config['SECURITY_PASSWORD_SALT'])
        return jsonify({"message": "Login successful", "token": token}), 200
    else:
        return jsonify({"error": 'result'}), 401

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
        if(decoded_data.get('user_email')):
            email = decoded_data.get('user_email')
            if not email:
                return jsonify({'message': 'Invalid token format', 'valid': False}), 401
            admin = Admin.query.filter_by(email=email).first()
            is_admin = bool(admin)
            return jsonify({
                'message': 'Token is valid',
                'valid': True,
                'email': email,
                'isAdmin': is_admin
            }), 200
        elif(decoded_data.get('uid')):
            uid=decoded_data.get('uid')
            print(uid)
            if not uid:
                return jsonify({'message': 'Invalid token format', 'valid': False}), 401
            # Check if user exists in LDAP
            # user_exists = user_exists_ldap(uid)
            # if user_exists is None:
            #     return jsonify({'message': 'LDAP error occurred', 'valid': False}), 500
            # if not user_exists:
            #     return jsonify({'message': 'User not found in LDAP', 'valid': False}), 404
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
    uid=serializer.loads(data.get("token"), salt=app.config['SECURITY_PASSWORD_SALT'])
     # Encode the password
    password = connection_details.get('password', '')
    hashed_password = serializer.dumps({'password': password}, salt=app.config['SECURITY_PASSWORD_SALT'])

    new_connection = ConnectionDetails(
        uid=uid.get("uid"),  # Use the UID from the token
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

    # Encode the password
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
        password=hashed_password,  # Store encoded password
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
    data = request.get_json()
    uid = serializer.loads(data.get("token"), salt=app.config['SECURITY_PASSWORD_SALT']).get("uid")

    # Fetch user connections
    user_connections = ConnectionDetails.query.filter(ConnectionDetails.uid == uid).all()
    
    # Fetch admin connections
    connections = ConnectionDetails.query.filter(ConnectionDetails.isAdmin == True).all()

    # Combine both lists before processing
    all_connections = user_connections + connections

    # Process and format the connections into a response list
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
            'created_at': conn.created_at,
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
    connections_list = []
    for conn in all_connections:
        connections_list.append({
            'id': conn.id,
            'connectionName': conn.connectionName,
            'description': conn.description,
            'uid': conn.uid,
            'hostname' : conn.hostname,
            'port' : conn.port,
            'database' : conn.database,
            'username' : conn.username,
            'password' : conn.password,
            'commandTimeout' : conn.commandTimeout,
            'maxTransportObjects' : conn.maxTransportObjects,
            'selectedDB' : conn.selectedDB,
            'created_at' : conn.created_at
        })
    return jsonify({'connections': connections_list}), 200

# Route to delete a user's own connection
@app.route('/connections/delete', methods=['POST'])
@token_required
def delete_connection():
    data = request.get_json()
    connection_id = data.get('connectionId')
    tokens=data.get("token")
    decoded_token=serializer.loads(tokens, salt=app.config['SECURITY_PASSWORD_SALT'])
    uid=decoded_token.get("uid")
    email=decoded_token.get("user_email")
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
        print(email)
        admin=Admin.query.filter_by(email=email).first()
        connection = ConnectionDetails.query.filter_by(
            id=connection_id,
            admin_id=admin.id,
            isAdmin=True
        ).first()
        if not connection:
            return jsonify({'message': 'Connection not found or not owned by user'}), 404
        db.session.delete(connection)
        db.session.commit()
        return jsonify({'message': 'Connection deleted'}), 200
    else:
        return jsonify({'message': 'Invalid token'}), 401
    
@app.route('/ldap-config', methods=['POST'])
@admin_required
def set_ldap_config():
    """Update LDAP configuration in .env file"""
    data = request.get_json().get('ldapConfig', {})
    
    # Validate required fields
    required_fields = ['ldapHost', 'baseDn', 'userRdn', 'ldapPort']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Validate LDAP_PORT is integer
    try:
        int(data['ldapPort'])
    except ValueError:
        return jsonify({"error": "LDAP_PORT must be an integer"}), 400
    
    # Update .env file
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
    """Retrieve current LDAP configuration from .env file"""
    env_vars = dotenv_values('.env')
    config = {
        "LDAP_SERVER": env_vars.get("LDAP_SERVER", ""),
        "LDAP_BASE_DN": env_vars.get("LDAP_BASE_DN", ""),
        "LDAP_USER_RDN": env_vars.get("LDAP_USER_RDN", ""),
        "LDAP_PORT": env_vars.get("LDAP_PORT", "")
    }
    return jsonify(config)

@app.route('/favorite', methods=['POST'])
@token_required
def add_favorite():
    try:
        data = request.json
        print(data)
        question_id = data.get('question').get('id')    
        response_id = data.get('response').get('id')
        question_content = data.get('question').get('content')
        response_query = data.get('response').get('query')
        print(question_id)
        print(response_id)
        print(question_content)
        print(response_query)
        uid =serializer.loads(data.get('token'), salt=app.config['SECURITY_PASSWORD_SALT']).get("uid") 
        print(uid)
        if not question_id or not response_id or not uid or not question_content or not response_query:
            return jsonify({'error': 'Question ID, response ID, and user ID are required'}), 400
        print("before favorite")
        favorite = Favorite.query.filter_by(question_id=question_id).first()
        print("favorite")
        if favorite:
            favorite.count += 1
        else:
            favorite = Favorite(question_id=question_id,question_content=question_content,response_id=response_id,response_query=response_query, count=1, uid=uid)
            db.session.add(favorite)

        db.session.commit()
        return jsonify({"message":"Message marked favourite successfully!"}), 201
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/favorites', methods=['POST'])
@token_required
def get_favorites():
    try:
        favorites = Favorite.query.all()
        return jsonify([{ 'question_id': fav.question_id,'question':fav.question_content, 'query': fav.response_query, 'count': fav.count, } for fav in favorites]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/unfavorite', methods=['POST'])
@token_required
def delete_favorite():
    try:
        data= request.json
        message_id = data.get('messageId')
        favorite = Favorite.query.filter_by(question_id=message_id).first()
        if favorite:
            if favorite.count <= 1:
                db.session.delete(favorite)
            else:
                favorite.count -= 1
            db.session.commit()
            return jsonify({'message': f'Favorite {message_id} updated', 'count': favorite.count}), 200
        return jsonify({'error': 'Question ID not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/favorite/delete', methods=['POST'])
@token_required
def force_delete_favorite():
    try:
        data= request.json
        print(data)
        message_id = data.get('messageId')
        favorite = Favorite.query.filter_by(question_id=message_id).first()
        if favorite:
            db.session.delete(favorite)
            db.session.commit()
            return jsonify({'message': f'Favorite {message_id} permanently deleted'}), 200
        return jsonify({'error': 'Question ID not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Run the application
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)