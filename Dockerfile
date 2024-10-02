# Use the latest official Python image
FROM python:latest

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Update and install required system packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    tesseract-ocr \
    poppler-utils \
    libgl1-mesa-glx \
    libglib2.0-0 \
    pkg-config \
    libmariadb-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    Flask==3.0.3 \
    Flask-MySQLdb==2.0.0 \
    PyMySQL==1.1.1 \
    numpy==1.26.4 \
    opencv-python==4.10.0.84 \
    opencv-python-headless==4.10.0.84 \
    pdf2image==1.17.0 \
    pytesseract==0.3.10 \
    bcrypt==4.2.0 \
    reportlab==4.2.2 \
    urllib3==1.26.19 \
    pandas==2.2.2 
    
# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable
ENV FLASK_APP=app.py

# Run app.py when the container launches
CMD ["python", "app.py"]
