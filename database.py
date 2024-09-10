import bcrypt
import pymysql
from flask import current_app

def get_db_connection():
    return pymysql.connect(
        host=current_app.config['MYSQL_HOST'],
        user=current_app.config['MYSQL_USER'],
        password=current_app.config['MYSQL_PASSWORD'],
        database=current_app.config['MYSQL_DB']
    )

def create_database_and_table():
    connection = pymysql.connect(
        host=current_app.config['MYSQL_HOST'],
        user=current_app.config['MYSQL_USER'],
        password=current_app.config['MYSQL_PASSWORD']
    )
    cursor = connection.cursor()

    # Create database if it doesn't exist
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {current_app.config['MYSQL_DB']}")
    
    # Connect to the database
    connection.select_db(current_app.config['MYSQL_DB'])

    # Create table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ocrdata (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255),
            filename VARCHAR(255),
            input1 TEXT,
            input2 TEXT,
            input3 TEXT,
            input4 TEXT,
            input5 TEXT,
            extracted_text TEXT,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE,
            password_hash VARCHAR(255),
            role VARCHAR(50)
        )
    """)

    
    connection.commit()
    cursor.close()
    connection.close()

def insert_data(username, filename, inputs, extracted_text):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO ocrdata (username, filename, input1, input2, input3, input4, input5, extracted_text) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (username, filename, *inputs, extracted_text)
    )

    connection.commit()
    cursor.close()
    connection.close()
    
def get_user_by_username(username):
    connection = get_db_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT username, password_hash, role FROM user WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    connection.close()
    return user

def create_user(username, password, role):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("INSERT INTO user (username, password_hash, role) VALUES (%s, %s, %s)", (username, hashed.decode('utf-8'), role))
        connection.commit()
    except pymysql.MySQLError as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        connection.close()

