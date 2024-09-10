import datetime
from flask import Flask, flash, render_template, request, jsonify, redirect, session, url_for
import cv2
import numpy as np
import pymysql
import pytesseract
from pdf2image import convert_from_path
import base64
import tempfile
import re
from functools import wraps
import bcrypt
from database import create_database_and_table, get_db_connection, insert_data, get_user_by_username, create_user

app = Flask(__name__)
app.secret_key = 'secret_key'
# app.permanent_session_lifetime = datetime.timedelta(minutes=10)


# MySQL configurations
app.config['MYSQL_HOST'] = 'database-1.czew08qiqixz.ap-south-1.rds.amazonaws.com'
app.config['MYSQL_USER'] = 'admin'
app.config['MYSQL_PASSWORD'] = 'Ardur311012'
app.config['MYSQL_DB'] = 'ocr_database'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Initialize the database and table
with app.app_context():
    create_database_and_table()
    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))  # Redirect to login if not logged in
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session:
                return redirect(url_for('login'))  # Redirect to login if not logged in
            user_role = session.get('role')  # Get user role from session
            if user_role not in allowed_roles:
                flash('You do not have access to this page.')
                return redirect(url_for('dashboard'))  # Redirect to dashboard if unauthorized
            return f(*args, **kwargs)
        return decorated_function
    return wrapper


def preprocess_image(image):
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    thresh = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 11, 2)
    denoised = cv2.fastNlMeansDenoising(thresh, None, 30, 7, 21)
    inverted = cv2.bitwise_not(denoised)
    white_background = np.full_like(image, 255)
    result = cv2.bitwise_and(white_background, white_background, mask=inverted)
    return result

def extract_text_from_image(image):
    preprocessed_image = preprocess_image(image)
    custom_config = r'--oem 3 --psm 6'
    text = pytesseract.image_to_string(preprocessed_image, config=custom_config)
    return clean_text(text)

def handle_file_upload(file):
    ext = file.filename.split('.')[-1].lower()
    if ext in ['png', 'jpg', 'jpeg', 'tiff', 'tif', 'bmp']:
        file_bytes = np.frombuffer(file.read(), np.uint8)
        image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        return image, extract_text_from_image(image)
    elif ext == 'pdf':
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_pdf:
            file.save(temp_pdf.name)
            images = convert_from_path(temp_pdf.name)
            image = np.array(images[0])
            image = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)  # Convert RGB to BGR for OpenCV compatibility
            return image, extract_text_from_image(image)
    return None, "Unsupported file format"

def create_user(username, password, role):
    # Check if username already exists
    connection = get_db_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT username FROM user WHERE username = %s", (username,))
    existing_user = cursor.fetchone()
    cursor.close()
    connection.close()

    if existing_user:
        return False  # User already exists

    # Create hashed password and insert into the database
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO user (username, password_hash, role) VALUES (%s, %s, %s)", (username, hashed, role))
    connection.commit()
    cursor.close()
    connection.close()
    return True

@app.route('/dashboard')
@login_required
def dashboard():
    # Pass username to the template if needed
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/qc')
@login_required
@role_required(['qc', 'lead'])  # Only QC and Lead roles can access the QC page
def qc():
    username = session.get('username')
    return render_template('qc.html', username=username)

@app.route('/lead')
@login_required
@role_required(['lead'])  # Only Lead role can access the Lead page
def lead():
    username = session.get('username')
    return render_template('lead.html', username=username)

@app.route('/register', methods=['GET', 'POST'])
def register():
    username_exists = False
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')  # Capture role from the form

        # Ensure all fields are filled
        if not username or not password or not confirm_password or not role:
            flash('All fields, including role, are required.')
            return render_template('register.html', username_exists=username_exists, username=username)

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('register.html', username_exists=username_exists, username=username)

        # Check if the username already exists
        existing_user = get_user_by_username(username)  # Assuming this function checks for an existing user
        if existing_user:
            username_exists = True
            flash('Username already exists. Please choose a different username.')
            return render_template('register.html', username_exists=username_exists, username=username)

        # If the username is new, create the user with the selected role
        create_user(username, password, role)

        flash('Registration successful! You can now log in.')
        return redirect(url_for('login'))

    return render_template('register.html', username_exists=username_exists, username=request.form.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = get_user_by_username(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            session['logged_in'] = True
            session['username'] = username  # Store the username in the session
            session['role'] = user['role']  # Store the user's role in the session
            return redirect(url_for('dashboard'))  # Redirect to the main app after successful login
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('logged_in')
    session.pop('username')
    return redirect(url_for('login'))

@app.route('/')
@role_required(['dataentry', 'qc', 'lead'])  # All roles can access the index page
@login_required
def index():
    username = session.get('username')
    if username is None:
        flash('Please log in first.')
        return redirect(url_for('login'))  # Ensure redirection if username is None
    return render_template('index.html', username=username)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file uploaded'})
    image, text = handle_file_upload(file)
    if image is None:
        return jsonify({'error': text})
    _, image_encoded = cv2.imencode('.png', image)
    image_base64 = base64.b64encode(image_encoded).decode('utf-8')
    return jsonify({
        'image': image_base64,
        'text': text,
        'filepath': file.filename
    })
    
@app.route('/check_role_access/<role>', methods=['GET'])
def check_role_access(role):
    # Get the user's role from session
    user_role = session.get('role')
    
    # Logic to check if the user has access based on role hierarchy
    if role == 'dataentry' and user_role not in ['dataentry', 'qc', 'lead']:
        return jsonify({'access': False, 'message': 'Access Denied: You do not have permission to access Data Entry.'})
    elif role == 'qc' and user_role not in ['qc', 'lead']:
        return jsonify({'access': False, 'message': 'Access Denied: You do not have permission to access QC.'})
    elif role == 'lead' and user_role != 'lead':
        return jsonify({'access': False, 'message': 'Access Denied: You do not have permission to access Lead.'})

    # If access is granted
    return jsonify({'access': True})


def clean_text(text):
    # Remove specific unwanted patterns or words
    text = re.sub(r'Vv', 'V', text)
    text = re.sub(r'Bewember', 'December', text)
    text = re.sub(r'DAMPABAS', 'Lampasas', text)
    text = re.sub(r'Sohn', 'John', text)
    text = re.sub(r'|', '', text)
    text = re.sub(r'__', '', text)  # Remove double underscores
    text = re.sub(r'eeeny', '', text)
    text = re.sub(r'r2csccr', '', text)
    text = re.sub(r'ooo', '', text)
    text = re.sub(r'acco.', '', text)
    text = re.sub(r'ccccccccscsceessseets', '', text)
    text = re.sub(r'wee', '', text)
    text = re.sub(r'eee', '', text)
    text = re.sub(r'Btock', 'Block', text) 
    text = re.sub(r'[^\w\s.,?!()_~]', '', text)
    lines = text.splitlines()
    spaced_text = '\n\n'.join(line.strip() for line in lines if line.strip())
    spaced_text = re.sub(r'(\d{1,2}/\d{1,2}/\d{4})', r'\1\n', spaced_text)
    paragraphs = re.split(r'\n\s*\n', spaced_text)
    formatted_text = '\n\n'.join(paragraph.strip() for paragraph in paragraphs if paragraph.strip())
    return formatted_text

@app.route('/submit', methods=['POST'])
@login_required  # Ensure the user is logged in
def submit_data():
    username = session.get('username')  # Retrieve username from session
    inputs = [request.form.get(f'input{i+1}') for i in range(5)]
    extracted_text = request.form.get('extractedText')
    filename = request.form.get('filepath')

    if any(not field for field in inputs + [extracted_text, filename]):
        return jsonify({'success': False, 'error': 'All fields must be filled.'})

    # Insert data into the database, including username and created time
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO ocrdata (username, filename, input1, input2, input3, input4, input5, extracted_text)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (username, filename, *inputs, extracted_text))
    connection.commit()
    cursor.close()
    connection.close()

    return jsonify({'success': True})

@app.route('/review')
def review():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('review.html', username=session['username'])

@app.route('/get_submissions')
def get_submissions():
    if 'username' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    username = session['username']
    date = request.args.get('date')

    if date:
        try:
            # Ensure the date format is correct
            formatted_date = datetime.datetime.strptime(date, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
    else:
        # Default to today's date if no date is provided
        formatted_date = datetime.date.today()

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    
    query = '''
        SELECT filename, input1, input2, input3, input4, input5, created_time
        FROM ocrdata
        WHERE username = %s AND DATE(created_time) = %s
    '''
    
    cursor.execute(query, (username, formatted_date))
    submissions = cursor.fetchall()
    conn.close()

    return jsonify({'submissions': submissions})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
