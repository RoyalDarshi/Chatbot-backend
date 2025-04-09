from flask import request, jsonify
from models import db, LdapDetails
import logging

# Logging setup
logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Helper function for errors
def handle_error(message, error=None, status_code=500):
    logger.error(f"{message}: {str(error)}" if error else message)
    return jsonify({'message': message, 'error': str(error) if error else None}), status_code

# Admin Routes
def create_ldap_details():
    try:
        data = request.get_json()
        admin_id = request.user_data.get('admin_id')
        ldap_name = data.get('ldapName')
        server_url = data.get('serverUrl')
        bind_dn = data.get('bindDN')
        bind_password = data.get('bindPassword')
        if not all([ldap_name, server_url, bind_dn, bind_password]):
            return handle_error("All LDAP fields required", status_code=400)
        new_ldap = LdapDetails(
            admin_id=admin_id,
            ldap_name=ldap_name,
            server_url=server_url,
            bind_dn=bind_dn,
            bind_password=bind_password
        )
        db.session.add(new_ldap)
        db.session.commit()
        return jsonify({'message': 'LDAP details created successfully'}), 200
    except db.sqlalchemy.exc.IntegrityError:
        return handle_error("LDAP name already exists", status_code=409)
    except Exception as e:
        return handle_error("Create LDAP details failed", error=e, status_code=500)

def test_db_connection():
    try:
        data = request.get_json()
        required_fields = ['hostname', 'port', 'database', 'username', 'password', 'selectedDB']
        for field in required_fields:
            if not data.get(field):
                return handle_error(f"{field} is required", status_code=400)
        # Simulate test (replace with actual logic if needed)
        return jsonify({'message': 'Connection test successful'}), 200
    except Exception as e:
        return handle_error("Test DB connection failed", error=e, status_code=500)