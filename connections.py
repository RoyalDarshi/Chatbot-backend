from flask import jsonify
from models import ConnectionDetails, DefaultConnectionDetails
from itsdangerous import BadSignature
from datetime import datetime, timezone

def create_db_connection(db, request, URLSafeTimedSerializer, os, datetime, timezone, BadSignature):
    data = request.get_json()
    token = data.get('userId')  # Token contains user_email
    connection_details = data.get('connectionDetails')

    if not token or not connection_details:
        return jsonify({'message': 'Token and connection details are required'}), 400

    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        decoded_token = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'))
        user_email = decoded_token.get('user_email')
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 401

    new_connection = ConnectionDetails(
        user_email=user_email,
        connectionName=connection_details.get('connectionName'),
        description=connection_details.get('description', ''),
        hostname=connection_details.get('hostname'),
        port=connection_details.get('port'),
        database=connection_details.get('database'),
        commandTimeout=connection_details.get('commandTimeout', '30'),
        maxTransportObjects=connection_details.get('maxTransportObjects', '1000'),
        username=connection_details.get('username'),
        password=connection_details.get('password'),
        selectedDB=connection_details.get('selectedDB'),
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(new_connection)
    db.session.commit()
    return jsonify({'message': 'Connection details saved successfully'}), 200

def create_default_db_connection(db, request, admin_id=None):
    try:
        data = request.get_json()
        connection_details = data.get('connectionDetails')
        if not connection_details:
            return jsonify({'message': 'Connection details are required'}), 400
        
        if not admin_id:
            return jsonify({'message': 'Admin authentication required'}), 403

        new_connection = DefaultConnectionDetails(
            admin_id=admin_id,
            connectionName=connection_details.get('connectionName'),
            description=connection_details.get('description', ''),
            hostname=connection_details.get('hostname'),
            port=connection_details.get('port'),
            database=connection_details.get('database'),
            commandTimeout=connection_details.get('commandTimeout', '30'),
            maxTransportObjects=connection_details.get('maxTransportObjects', '1000'),
            username=connection_details.get('username'),
            password=connection_details.get('password'),
            selectedDB=connection_details.get('selectedDB'),
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(new_connection)
        db.session.commit()
        return jsonify({'message': 'Connection details saved successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to create default connection', 'error': str(e)}), 500

def get_user_connections(db, request, URLSafeTimedSerializer, os, BadSignature, datetime):
    data = request.get_json()
    token = data.get('userId')
    if not token:
        return jsonify({'message': 'Token is required'}), 400

    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        decoded_token = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'))
        user_email = decoded_token.get('user_email')
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 401

    connections = ConnectionDetails.query.filter_by(user_email=user_email).all()
    default_connections = DefaultConnectionDetails.query.all()
    connections_list = []

    for default_conn in default_connections:
        connections_list.append({
            'id': default_conn.id,
            'connectionName': default_conn.connectionName,
            'description': default_conn.description,
            'hostname': default_conn.hostname,
            'port': default_conn.port,
            'database': default_conn.database,
            'commandTimeout': default_conn.commandTimeout,
            'maxTransportObjects': default_conn.maxTransportObjects,
            'username': default_conn.username,
            'password': default_conn.password,
            'selectedDB': default_conn.selectedDB,
            'created_at': default_conn.created_at.strftime('%Y-%m-%d %H:%M:%S') if default_conn.created_at else None,
        })

    for conn in connections:
        connections_list.append({
            'id': conn.id,
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
            'created_at': conn.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })

    return jsonify({'connections': connections_list}), 200

def delete_user_connection(db, request, URLSafeTimedSerializer, os, BadSignature):
    data = request.get_json()
    token = data.get('userId')
    connection_id = data.get('connectionId')
    if not token or not connection_id:
        return jsonify({'message': 'Token and connection ID are required'}), 400

    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        decoded_token = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'))
        user_email = decoded_token.get('user_email')
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 401

    connection = ConnectionDetails.query.filter_by(id=connection_id, user_email=user_email).first()
    if not connection:
        return jsonify({'message': 'Connection not found or does not belong to the user'}), 404

    db.session.delete(connection)
    db.session.commit()
    return jsonify({'message': 'Connection deleted successfully'}), 200