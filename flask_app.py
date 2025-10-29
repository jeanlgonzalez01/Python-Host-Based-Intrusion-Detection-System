"""
Host Intrusion Detection System (HIDS) - Web Interface

This Flask application provides a web interface for monitoring system resources,
file activities, processes, and network traffic through the HIDS database.

Key Features:
- User authentication
- System resource monitoring (memory, CPU)
- Network interface status
- File activity monitoring
- Process monitoring
- Network traffic inspection

Author: Jean L. González Milán
"""

from flask import Flask, render_template, request, jsonify
import psutil  # For system monitoring
import sqlite3  # Database interaction
import hashlib  # Password hashing

# Initialize Flask application
app = Flask(__name__)

def get_db_connection():
    """
    Establishes and returns a connection to the SQLite database.
    
    Returns:
        sqlite3.Connection: Database connection object with row factory set
                           to return dictionaries for easier data handling.
    """
    conn = sqlite3.connect('hids_database.db')
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn

def hash_password(password):
    """
    Hashes a password using SHA-256.
    
    Note: In production, consider using a more secure method like bcrypt or Argon2
          with proper salting for password storage.
    
    Args:
        password (str): Plain text password to hash
        
    Returns:
        str: SHA-256 hash of the password
    """
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def index():
    """
    Main entry point for the web interface.
    
    Returns:
        Rendered template: The index.html page
    """
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """
    Handles user authentication.
    
    Expects JSON payload with 'username' and 'password'.
    Verifies credentials against the User table in the database.
    
    Returns:
        JSON response: Success status (200 for success, 401 for failure)
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM User WHERE username = ?', (username,)).fetchone()
    conn.close()

    if user:
        # Verify the hashed password matches
        if user['password_hash'] == hash_password(password):
            return jsonify({"success": True}), 200
    
    return jsonify({"success": False}), 401

@app.route('/memory_stats')
def memory_stats():
    """
    Provides current memory usage statistics.
    
    Returns:
        JSON: Memory information including:
              - total memory (GB)
              - used memory (GB)
              - available memory (GB)
              - usage percentage
    """
    vm = psutil.virtual_memory()
    memory_data = {
        'total': vm.total / 1e9,         # Convert bytes to GB
        'used': vm.used / 1e9,           # Convert bytes to GB
        'available': vm.available / 1e9, # Convert bytes to GB
        'percentage': vm.percent          # Memory usage percentage
    }
    return jsonify(memory_data)

@app.route('/cpu_stats')
def cpu_stats():
    """
    Provides current CPU usage statistics.
    
    Returns:
        JSON: CPU information including:
              - current usage percentage
              - total thread count
    """
    cpu_usage = psutil.cpu_percent(interval=1)
    thread_count = psutil.cpu_count(logical=True)
    cpu_data = {
        'cpu_usage': cpu_usage,
        'thread_count': thread_count
    }
    return jsonify(cpu_data)

@app.route('/network_information')
def network_information():
    """
    Provides network interface status information.
    
    Returns:
        JSON: List of network interfaces with:
              - interface name
              - status (Up/Down)
              - speed (Mbps)
    """
    network_data = []
    for key, stats in psutil.net_if_stats().items():
        name = key
        up = "Up" if stats.isup else "Down"
        speed = stats.speed
        network_data.append({
            'Network': name,
            'Status': up,
            'Speed': speed
        })
    return jsonify(network_data)

@app.route('/file_monitor')
def files_view():
    """
    Retrieves file monitoring data from the FilesView.
    
    Returns:
        JSON: List of file records with all columns from FilesView,
              ordered by creation time (newest first)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Query to select all records from the FilesView view
    cursor.execute('SELECT * FROM FilesView order by creation_time desc;')
    rows = cursor.fetchall()
    
    # Get column names for proper JSON serialization
    column_names = [description[0] for description in cursor.description]
    
    # Convert rows to a list of dictionaries
    files_data = [dict(zip(column_names, row)) for row in rows]
    
    # Handle any binary data in the results
    for item in files_data:
        for key, value in item.items():
            if isinstance(value, bytes):
                item[key] = value.decode('utf-8', errors='ignore')
    
    # Clean up database resources
    cursor.close()
    conn.close()
    
    return jsonify(files_data)

@app.route('/process_monitor')
def ProcessesView():
    """
    Retrieves process monitoring data from the ProcessesView.
    
    Returns:
        JSON: List of process records with all columns from ProcessesView,
              ordered by start time (oldest first)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * from ProcessesView order by start_time;")
    rows = cursor.fetchall()

    # Get column names for proper JSON serialization
    column_names = [description[0] for description in cursor.description]

    # Convert rows to a list of dictionaries
    process_data = [dict(zip(column_names, row)) for row in rows]

    # Clean up database resources
    cursor.close()
    conn.close()

    return jsonify(process_data)

@app.route('/network_traffic')
def network_traffic():
    """
    Retrieves network traffic data from the NetworkTraffic table.
    
    Returns:
        JSON: List of all network traffic records with:
              - source/destination IPs and ports
              - protocol information
              - packet size
              - timestamp
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Query to select all records from the NetworkTraffic table
    cursor.execute('SELECT * FROM NetworkTraffic ;')
    rows = cursor.fetchall()

    # Get column names for proper JSON serialization
    column_names = [description[0] for description in cursor.description]

    # Convert rows to a list of dictionaries
    network_data = [dict(zip(column_names, row)) for row in rows]

    # Clean up database resources
    cursor.close()
    conn.close()

    return jsonify(network_data)

if __name__ == '__main__':
    """
    Main entry point when running the application directly.
    
    Starts the Flask development server with debug mode enabled.
    Note: In production, use a proper WSGI server like Gunicorn.
    """
    app.run(debug=True)