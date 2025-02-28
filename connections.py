# connections.py
from flask import jsonify
from models import ConnectionDetails

def test_db_connection():
    return jsonify({'message': 'Connection made successfully'}), 200

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
        selectedDB=connection_details.get('selectedDB'),
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
            'password': conn.password,
            'selectedDB': conn.selectedDB,
            'created_at': conn.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        for conn in connections
    ]

    return jsonify({'connections': connections_list}), 200
