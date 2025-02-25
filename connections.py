# connections.py
from flask import jsonify
from models import ConnectionDetails

# def test_db_connection():
#     return jsonify({'message': 'Connection made successfully'}), 200

def create_db_connection(db, request, URLSafeTimedSerializer, os, datetime, timezone, BadSignature):
    data = request.get_json()
    token = data.get('userId')
    connection_details = data.get('connectionDetails')

    if not token or not connection_details:
        return jsonify({'message': 'Token and connection details are required'}), 400

    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        decoded_token = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'))
        user_id = decoded_token.get('user_id')
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 401

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
        isPrimary=connection_details.get('isPrimary', False),
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(new_connection)
    db.session.commit()

    return jsonify({'message': 'Connection details saved successfully'}), 200

def get_user_connections(db, request, URLSafeTimedSerializer, os, BadSignature, datetime):
    data = request.get_json()
    token = data.get('userId')

    if not token:
        return jsonify({'message': 'Token is required'}), 400

    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        decoded_token = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'))
        user_id = decoded_token.get('user_id')
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 401

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

def set_primary_connection(db, request, URLSafeTimedSerializer, os, BadSignature):
    data = request.get_json()
    token = data.get('userId')
    connection_id = data.get('connectionId')

    if not token or not connection_id:
        return jsonify({'message': 'Token and connection ID are required'}), 400

    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        decoded_token = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'))
        user_id = decoded_token.get('user_id')
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 401

    connection_to_update = ConnectionDetails.query.filter_by(id=connection_id, user_id=user_id).first()

    if not connection_to_update:
        return jsonify({'message': 'Connection not found'}), 404

    existing_primary = ConnectionDetails.query.filter_by(user_id=user_id, isPrimary=True).first()

    if existing_primary:
        existing_primary.isPrimary = False
        db.session.commit()

    connection_to_update.isPrimary = True
    db.session.commit()

    return jsonify({'message': 'Primary connection updated successfully'}), 200

def unset_primary_connection(db, request, URLSafeTimedSerializer, os, BadSignature):
    data = request.get_json()
    token = data.get('userId')
    connection_id = data.get('connectionId')

    if not token or not connection_id:
        return jsonify({'message': 'Token and connection ID are required'}), 400

    serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    try:
        decoded_token = serializer.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'))
        user_id = decoded_token.get('user_id')
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 401

    connection_to_update = ConnectionDetails.query.filter_by(id=connection_id, user_id=user_id).first()

    if not connection_to_update:
        return jsonify({'message': 'Connection not found'}), 404

    if not connection_to_update.isPrimary:
        return jsonify({'message': 'This connection is already not primary'}), 400

    connection_to_update.isPrimary = False
    db.session.commit()

    return jsonify({'message': 'Connection is no longer marked as primary'}), 200