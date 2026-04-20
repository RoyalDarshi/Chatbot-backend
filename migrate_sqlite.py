import sqlite3
import os

db_path = os.path.join('instance', 'users.db')

if not os.path.exists(db_path):
    print(f"DB not found at {db_path}")
    exit(0)

conn = sqlite3.connect(db_path)

try:
    print("Rebuilding connection_details Table...")
    # Get all indices
    indices = conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='connection_details'").fetchall()
    has_global_unique = False
    for idx_name in indices:
        if 'connectionName' in idx_name[0] or 'autoindex' in idx_name[0]:
            has_global_unique = True

    
    conn.execute('''
    CREATE TABLE new_connection_details (
        id INTEGER PRIMARY KEY, 
        admin_id INTEGER, 
        uid VARCHAR(120) NOT NULL, 
        connectionName VARCHAR(120) NOT NULL, 
        description VARCHAR(255), 
        hostname VARCHAR(120) NOT NULL, 
        port INTEGER NOT NULL, 
        "database" VARCHAR(120) NOT NULL, 
        commandTimeout INTEGER, 
        maxTransportObjects INTEGER, 
        username VARCHAR(120) NOT NULL, 
        password VARCHAR(120) NOT NULL, 
        selectedDB VARCHAR(120) NOT NULL, 
        isAdmin BOOLEAN NOT NULL, 
        isPublic BOOLEAN NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL
    )
    ''')
    conn.execute('INSERT INTO new_connection_details SELECT id, admin_id, uid, connectionName, description, hostname, port, "database", commandTimeout, maxTransportObjects, username, password, selectedDB, isAdmin, isPublic, created_at FROM connection_details')
    conn.execute('DROP TABLE connection_details')
    conn.execute('ALTER TABLE new_connection_details RENAME TO connection_details')
    
    # Add new unique constraints
    conn.execute('CREATE UNIQUE INDEX _user_connection_uc ON connection_details (uid, connectionName)')
    # If admin creates multiple, we skip this since admin_id is mostly null for user connections
    # We enforce admin's uniqueness in application code or another index:
    # Actually wait, if uid is '', it is not NULL, so _user_connection_uc will enforce ( '', connectionName ). That is perfect!
    
    print("Successfully rebuilt connection_details.")
except Exception as e:
    print("Error migrating connection_details:", e)

try:
    print("Rebuilding favorite Table...")
    conn.execute('''
    CREATE TABLE new_favorite (
        id INTEGER NOT NULL, 
        question_id VARCHAR(255) NOT NULL, 
        question_content VARCHAR(500) NOT NULL, 
        response_id VARCHAR(255), 
        response_query VARCHAR(500), 
        connection_name VARCHAR(255) NOT NULL, 
        uid VARCHAR(255) NOT NULL, 
        count INTEGER, 
        created_at DATETIME, 
        updated_at DATETIME, 
        con_id INTEGER,
        PRIMARY KEY (id)
    )
    ''')
    conn.execute('INSERT INTO new_favorite (id, question_id, question_content, response_id, response_query, connection_name, uid, count, created_at, updated_at) SELECT id, question_id, question_content, response_id, response_query, connection_name, uid, count, created_at, updated_at FROM favorite')
    conn.execute('DROP TABLE favorite')
    conn.execute('ALTER TABLE new_favorite RENAME TO favorite')
    
    # Update constraints to use con_id instead of connection_name
    conn.execute('CREATE UNIQUE INDEX _user_content_connection_uc ON favorite (question_content, con_id, uid)')
    
    print("Successfully rebuilt favorite.")
except Exception as e:
    print("Error migrating favorite:", e)

conn.commit()
conn.close()
