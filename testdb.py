from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
import mysql.connector
import ibm_db
import cx_Oracle
import pyodbc
from sqlalchemy import create_engine

def close_connection(conn, db_type):
    if not conn:
        return  # If conn is None, there's nothing to close

    try:
        if db_type == 'postgresql' or db_type == 'mysql' or db_type == 'redshift':
            conn.close()
        elif db_type == 'db2':
            import ibm_db
            ibm_db.close(conn)
        elif db_type == 'oracle':
            conn.close()  # Assuming using cx_Oracle which has a close method similar to psycopg2
        elif db_type == 'mssql':
            conn.close()  # pyodbc, pymssql
        # Add additional database types and their close methods as needed
    except Exception as e:
        print(f"Failed to close the connection: {str(e)}")



def connect_to_db(db_type, connection_params):
    conn = None
    try:
        if db_type == 'postgresql':
            conn = psycopg2.connect(**connection_params)
        elif db_type == 'mysql':
            conn = mysql.connector.connect(**connection_params)
        elif db_type == 'db2':
            conn_str = (
                f"DATABASE={connection_params['database']};"
                f"HOSTNAME={connection_params['hostname']};"
                f"PORT={connection_params['port']};"
                f"PROTOCOL=TCPIP;"
                f"UID={connection_params['username']};"
                f"PWD={connection_params['password']};"
            )
            conn = ibm_db.connect(conn_str, "", "")
        elif db_type == 'oracle':
            dsn = cx_Oracle.makedsn(connection_params['hostname'], connection_params['port'], service_name=connection_params['database'])
            conn = cx_Oracle.connect(user=connection_params['username'], password=connection_params['password'], dsn=dsn)
        elif db_type == 'mssql':
            conn = pyodbc.connect(
                'DRIVER={ODBC Driver 17 for SQL Server};'
                f"SERVER={connection_params['hostname']};"
                f"DATABASE={connection_params['database']};"
                f"UID={connection_params['username']};"
                f"PWD={connection_params['password']}"
            )
        elif db_type == 'redshift':
            engine = create_engine(
                f"postgresql+psycopg2://{connection_params['username']}:"
                f"{connection_params['password']}@{connection_params['hostname']}:"
                f"{connection_params['port']}/{connection_params['database']}"
            )
            conn = engine.connect()
        
        return "Connection successful!"
    except Exception as e:
        return None, f"Failed to connect: {str(e)}"
    
    finally:
        close_connection(conn, db_type)

def test_db_connection():
    data = request.get_json()
    db_type = data.get('selectedDB')
    connection_params = {
        'hostname': data.get('hostname'),
        'port': data.get('port'),
        'username': data.get('username'),
        'password': data.get('password'),
        'database': data.get('database')
    }
    
    if not db_type or not connection_params['hostname']:
        return jsonify({'error': 'Database type and parameters are required'}), 400
