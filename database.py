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
            filename VARCHAR(255),
            input1 TEXT,
            input2 TEXT,
            input3 TEXT,
            input4 TEXT,
            input5 TEXT,
            extracted_text TEXT
        )
    """)

    connection.commit()
    cursor.close()
    connection.close()

def insert_data(filepath, inputs, extracted_text):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO ocrdata (filename, input1, input2, input3, input4, input5, extracted_text) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (filepath, *inputs, extracted_text)
    )

    connection.commit()
    cursor.close()
    connection.close()

