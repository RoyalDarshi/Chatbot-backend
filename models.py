# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone


db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False) # Store the hashed password

class ConnectionDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    connectionName = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(255))
    hostname = db.Column(db.String(120), nullable=False)
    port = db.Column(db.String(10), nullable=False)
    database = db.Column(db.String(120), nullable=False)
    commandTimeout = db.Column(db.String(10))
    maxTransportObjects = db.Column(db.String(10))
    username = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    applicationName = db.Column(db.String(120))
    clientAccountingInformation = db.Column(db.String(120))
    clientHostname = db.Column(db.String(120))
    clientUser = db.Column(db.String(120))
    selectedDB = db.Column(db.String(120), nullable=False)
    isPrimary = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)