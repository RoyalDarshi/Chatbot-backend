from flask import request, jsonify
from connections import (
    create_db_connection,
    create_default_db_connection,
    get_user_connections,
    delete_user_connection
)
from models import db, DefaultConnectionDetails
from itsdangerous import URLSafeTimedSerializer, BadSignature
from datetime import datetime, timezone
import os
import logging

logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

def handle_error(message, error=None, status_code=500):
    logger.error(f"{message}: {str(error)}" if error else message)
    return jsonify({'message': message, 'error': str(error) if error else None}), status_code

def create_default_db_connection_route():
    try:
        if not hasattr(request, 'user_data'):
            return handle_error("Authentication data missing", status_code=403)
        admin_id = request.user_data.get('admin_id')
        if not admin_id:
            return handle_error("Admin authentication required", status_code=403)

        data = request.get_json()
        if not data or 'connectionDetails' not in data:
            return handle_error("Connection details required", status_code=400)

        response = create_default_db_connection(
            db=db,
            request=request,
            admin_id=admin_id  # Only pass required arguments
        )
        return response
    except Exception as e:
        return handle_error("Create default DB connection failed", error=e, status_code=500)

# Other routes unchanged
def create_db_connection_route():
    try:
        return create_db_connection(db, request, URLSafeTimedSerializer, os, datetime, timezone, BadSignature)
    except Exception as e:
        return handle_error("Create DB connection failed", error=e, status_code=500)

def get_user_connections_route():
    try:
        return get_user_connections(db, request, URLSafeTimedSerializer, os, BadSignature, datetime)
    except Exception as e:
        return handle_error("Get user connections failed", error=e, status_code=500)

def delete_user_connection_route():
    try:
        return delete_user_connection(db, request, URLSafeTimedSerializer, os, BadSignature)
    except Exception as e:
        return handle_error("Delete user connection failed", error=e, status_code=500)

def get_default_connections():
    try:
        default_connections = DefaultConnectionDetails.query.all()
        connections = [{
            'id': conn.id,
            'admin_id': conn.admin_id,
            'connectionName': conn.connectionName,
            'description': conn.description,
            'hostname': conn.hostname,
            'port': conn.port,
            'database': conn.database,
            'commandTimeout': conn.commandTimeout,
            'maxTransportObjects': conn.maxTransportObjects,
            'username': conn.username,
            'password': conn.password,
            'selectedDB': conn.selectedDB,
            'created_at': conn.created_at.strftime('%Y-%m-%d %H:%M:%S') if conn.created_at else None
        } for conn in default_connections]
        return jsonify({'connections': connections}), 200
    except Exception as e:
        return handle_error("Get default connections failed", error=e, status_code=500)

def delete_default_connection():
    try:
        if not hasattr(request, 'user_data') or 'admin_id' not in request.user_data:
            return handle_error("Admin authentication required", status_code=403)

        data = request.get_json()
        connection_id = data.get('connectionId')
        admin_id = request.user_data.get('admin_id')
        if not connection_id:
            return handle_error("Connection ID required", status_code=400)
        connection = DefaultConnectionDetails.query.filter_by(id=connection_id, admin_id=admin_id).first()
        if not connection:
            return handle_error("Connection not found or unauthorized", status_code=404)
        db.session.delete(connection)
        db.session.commit()
        return jsonify({'message': 'Connection deleted successfully'}), 200
    except Exception as e:
        return handle_error("Delete default connection failed", error=e, status_code=500)