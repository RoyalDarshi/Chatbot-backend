from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize SQLAlchemy (standalone instance)
db = SQLAlchemy()

# Define the Admin model (must match the app)
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Function to add an admin user
def add_admin(email: str, password: str, app) -> None:
    with app.app_context():  # Move all operations into the context
        try:
            # Generate a secure hash of the password
            hashed_password = generate_password_hash(password, method="scrypt")

            # Check if the admin already exists
            existing_admin = Admin.query.filter_by(email=email).first()
            if existing_admin:
                print(f"Admin '{email}' already exists in the database.")
                return

            # Create new admin user
            new_admin = Admin(
                email=email,
                password=hashed_password
            )

            # Add to the database
            db.session.add(new_admin)
            db.session.commit()
            print(f"Admin '{email}' added successfully with hashed password.")

        except Exception as e:
            print(f"Error: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    # Create a temporary Flask app for database context
    from flask import Flask
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///users.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    # Create tables if they don’t exist
    with app.app_context():
        db.create_all()

    # Prompt user for email and password
    email = input("Enter admin email: ").strip()
    password = input("Enter admin password: ").strip()

    if not email or not password:
        print("Email and password cannot be empty.")
    else:
        add_admin(email, password, app)