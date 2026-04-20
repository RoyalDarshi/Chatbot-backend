import sqlite3
import os

db_path = os.path.join('instance', 'users.db')
conn = sqlite3.connect(db_path)

# Check existing columns
cols = [row[1] for row in conn.execute("PRAGMA table_info(user)")]
print("Existing columns:", cols)

if 'allowed_to_create_public_connection' not in cols:
    conn.execute("ALTER TABLE user ADD COLUMN allowed_to_create_public_connection BOOLEAN DEFAULT 1")
    conn.commit()
    print("SUCCESS: Added 'allowed_to_create_public_connection' column to user table.")
else:
    print("Column already exists, nothing to do.")

conn.close()
