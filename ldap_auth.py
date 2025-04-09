from flask import Flask, request, jsonify, session
from flask_cors import CORS
from ldap3 import Server, Connection, ALL, SUBTREE
from dotenv import load_dotenv, dotenv_values
import os
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management
CORS(app, supports_credentials=True)  # Enable CORS for React front-end

# LDAP Configuration
LDAP_SERVER = "ldap://150.239.171.184:389"  # Replace with your RHDS server
LDAP_BASE_DN = "dc=example,dc=com"
LDAP_USER_DN_TEMPLATE = "uid={},ou=users,dc=example,dc=com"

def authenticate_user(username, password):
    try:
        print("username: " + username)
        # Initialize LDAP connection
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(server,user=LDAP_USER_DN_TEMPLATE.format(username), password=password, auto_bind=True,receive_timeout=5 )
        print(conn)
        # Search for user details
        conn.search(LDAP_BASE_DN, f"(uid={username})", search_scope=SUBTREE, attributes=['cn', 'uid'])
        if conn.entries:
            user_entry = conn.entries[0]
            return True, {"uid": user_entry.uid.value, "cn": user_entry.cn.value}
        return False, None
    except Exception as e:
        return False, str(e)

def update_or_create_env_variable(env_content, key, value):
    pattern = rf"^{key}=.*$"
    replacement = f"{key}={value}"

    if re.search(pattern, env_content, re.MULTILINE):
        return re.sub(pattern, replacement, env_content, flags=re.MULTILINE)
    else:
        return f"{env_content}\n{replacement}"

def store_ldap_details(db, request, serializer, os):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400

        ldap_host = data.get('ldapHost')
        ldap_port = data.get('ldapPort')
        ldap_base_dn = data.get('baseDn')
        ldap_user_dn = data.get('userDn')

        # Validate that all required fields are present
        if not all([ldap_host, ldap_port, ldap_base_dn, ldap_user_dn]):
            return jsonify({'error': 'Missing LDAP details'}), 400

        # Read the .env file as raw text for spacing preservation
        with open(".env", "r") as f:
            env_content = f.read()

        # Update or create each key-value pair using regex
        env_content = update_or_create_env_variable(env_content, 'LDAP_HOST', ldap_host)
        env_content = update_or_create_env_variable(env_content, 'LDAP_PORT', str(ldap_port))
        env_content = update_or_create_env_variable(env_content, 'LDAP_BASE_DN', ldap_base_dn)
        env_content = update_or_create_env_variable(env_content, 'LDAP_USER_DN', ldap_user_dn)

        # Write the updated content back to .env
        with open(".env", "w") as f:
            f.write(env_content)

        # Update os.environ for immediate use
        os.environ['LDAP_HOST'] = ldap_host
        os.environ['LDAP_PORT'] = str(ldap_port)
        os.environ['LDAP_BASE_DN'] = ldap_base_dn
        os.environ['LDAP_USER_DN'] = ldap_user_dn



        return jsonify({'message': 'LDAP details stored successfully'}), 200

    except Exception as e:
        print(f"Error storing LDAP details: {e}")
        return jsonify({'error': 'Internal server error'}), 500


def login(db,request,serializer,os):
    data = request.get_json()
    print(data)
    username = data.get("email")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    success, result = authenticate_user(username, password)
    if success:
        # Store user info in session
        session["user"] = result
        return jsonify({"message": "Login successful", "user": result}), 200
    else:
        return jsonify({"error": result}), 401

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"message": "Logout successful"}), 200

@app.route("/user", methods=["GET"])
def get_user():
    user = session.get("user")
    if user:
        return jsonify({"user": user}), 200
    return jsonify({"error": "Not logged in"}), 401
