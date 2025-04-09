from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from models import db
import os
from itsdangerous import URLSafeTimedSerializer, BadSignature
import jwt
import logging

# Import route modules
from auth_routes import (
    signup_route, login_route, admin_login, reset_password_route,
    google_login_route, linkedin_login_route, validate_token_route,
    store_ldap_details_route
)
from connections_routes import (
    create_db_connection_route, get_user_connections_route, delete_user_connection_route,
    create_default_db_connection_route, get_default_connections, delete_default_connection
)
from admin_routes import create_ldap_details, test_db_connection

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Load environment variables
load_dotenv()

# Configure app
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT', 'your-salt')
DBCON_SERVER_URL = os.getenv("DBCON_SERVER_URL", "http://localhost:5001")

# Initialize SQLAlchemy
db.init_app(app)

# Create database tables
with app.app_context():
    db.create_all()

# Initialize serializers
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Logging setup
logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Authentication decorators
def token_required(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', request.json.get('userId', ''))
        if not token:
            request.user_data = {}
            return jsonify({'message': 'Token missing', 'error': None}), 401
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            request.user_data = data
        except jwt.ExpiredSignatureError:
            request.user_data = {}
            return jsonify({'message': 'Token has expired', 'error': None}), 401
        except jwt.InvalidTokenError:
            try:
                data = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
                request.user_data = data
            except BadSignature:
                request.user_data = {}
                return jsonify({'message': 'Invalid token', 'error': None}), 401
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def admin_required(f):
    @token_required
    def decorated(*args, **kwargs):
        if 'admin_id' not in request.user_data:
            return jsonify({'message': 'Admin access required', 'error': None}), 403
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# Register routes
app.route('/store-ldap', methods=['POST'])(store_ldap_details_route)
app.route('/signup', methods=['POST'])(signup_route)
app.route('/login', methods=['POST'])(login_route)
app.route('/admin-login', methods=['POST'])(admin_login)
app.route('/reset-password', methods=['POST'])(reset_password_route)
app.route('/google-login', methods=['POST'])(google_login_route)
app.route('/linkedin-login', methods=['POST'])(linkedin_login_route)
app.route('/validate-token', methods=['POST'])(validate_token_route)
app.route('/createdbcon', methods=['POST'])(token_required(create_db_connection_route))
app.route('/getuserconnections', methods=['POST'])(token_required(get_user_connections_route))
app.route('/deleteuserconnection', methods=['POST'])(token_required(delete_user_connection_route))
app.route('/create-default-dbcon', methods=['POST'])(admin_required(create_default_db_connection_route))
app.route('/getdefaultconnections', methods=['GET'])(admin_required(get_default_connections))
app.route('/delete-default-connection', methods=['POST'])(admin_required(delete_default_connection))
app.route('/create-ldap', methods=['POST'])(admin_required(create_ldap_details))
app.route('/testdbcon', methods=['POST'])(test_db_connection)

# Run the app
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_ENV') == 'development')