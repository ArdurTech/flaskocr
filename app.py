from flask import Flask, flash, render_template, request, jsonify, redirect, session, url_for
import cv2
import numpy as np
import pymysql
import pytesseract
from pdf2image import convert_from_path
import base64
import tempfile
import re
<<<<<<< HEAD
from functools import wraps
=======
>>>>>>> e33f909d056401d15e2e4e590ed182d7a0755ccc
import bcrypt
from database import create_database_and_table, get_db_connection, insert_data, get_user_by_username, create_user

app = Flask(__name__)
app.secret_key = 'secret_key'

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

<<<<<<< HEAD
def create_user(username, password):
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
    cursor.execute("INSERT INTO user (username, password_hash) VALUES (%s, %s)", (username, hashed))
    connection.commit()
    cursor.close()
    connection.close()
    return True

=======
>>>>>>> e33f909d056401d15e2e4e590ed182d7a0755ccc
@app.route('/register', methods=['GET', 'POST'])
def register():
    username_exists = False
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            flash('All fields are required.')
            return render_template('register.html', username_exists=username_exists, username=username)

        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('register.html', username_exists=username_exists, username=username)

        if create_user(username, password):
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))

        username_exists = True

    return render_template('register.html', username_exists=username_exists, username=request.form.get('username'))

<<<<<<< HEAD
=======
def create_user(username, password):
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
    cursor.execute("INSERT INTO user (username, password_hash) VALUES (%s, %s)", (username, hashed))
    connection.commit()
    cursor.close()
    connection.close()
    return True

>>>>>>> e33f909d056401d15e2e4e590ed182d7a0755ccc
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = get_user_by_username(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            session['logged_in'] = True
            session['username'] = username  # Store the username in the session
            return redirect(url_for('index'))  # Redirect to the main app after successful login
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
<<<<<<< HEAD
    session.pop('logged_in')
    session.pop('username')
=======
    session.pop('logged_in', None)
    session.pop('username', None)
>>>>>>> e33f909d056401d15e2e4e590ed182d7a0755ccc
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
<<<<<<< HEAD
    username = session.get('username')
    if username is None:
        flash('Please log in first.')
        return redirect(url_for('login'))  # Ensure redirection if username is None
=======
    username = session.get('username')  # Retrieve username from session or database
>>>>>>> e33f909d056401d15e2e4e590ed182d7a0755ccc
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

def clean_text(text):
    # Remove specific unwanted patterns or words
    text = re.sub(r'Vv', 'V', text)
    text = re.sub(r'Bewember', 'December', text)
    text = re.sub(r'DAMPABAS', 'Lampasas', text)
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
def submit_data():
    inputs = [request.form.get(f'input{i+1}') for i in range(5)]
    extracted_text = request.form.get('extractedText')
    filepath = request.form.get('filepath')

    if any(not field for field in inputs + [extracted_text, filepath]):
        return jsonify({'success': False, 'error': 'All fields must be filled.'})

    insert_data(filepath, inputs, extracted_text)

    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
