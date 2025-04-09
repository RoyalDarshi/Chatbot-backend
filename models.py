from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Hashed password

class ConnectionDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)  # From LDAP authentication
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
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))

class DefaultConnectionDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    connectionName = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(255))
    hostname = db.Column(db.String(120), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    database = db.Column(db.String(120), nullable=False)
    commandTimeout = db.Column(db.Integer)
    maxTransportObjects = db.Column(db.Integer)
    username = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    selectedDB = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)  # Still needed for reset flow
    token = db.Column(db.String(255), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)

class LdapDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    ldap_name = db.Column(db.String(120), nullable=False, unique=True)
    server_url = db.Column(db.String(255), nullable=False)
    bind_dn = db.Column(db.String(255), nullable=False)
    bind_password = db.Column(db.String(255), nullable=False)