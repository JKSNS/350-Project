import os
import time
import uuid
import json
import jwt  # Install via `pip install pyjwt`
from datetime import datetime, timedelta
import mysql.connector
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables 
load_dotenv()
DB_NAME = os.getenv("DB_DATABASE")
JWT_SECRET = os.getenv("JWT_SECRET", "default_jwt_secret")
app = Flask(__name__)
# Use either SECRET_KEY or JWT_SECRET as needed. Here we use SECRET_KEY for sessions.
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# ------------------------ BEGIN CLASSES ------------------------ #
# (None provided for now)
# ------------------------ END CLASSES ------------------------ #

# ------------------------ BEGIN DATABASE FUNCTIONS ------------------------ #
def get_db_connection():
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=DB_NAME
    )
    return conn

def check_database():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        conn.close()
        print("Database connection successful")
    except mysql.connector.Error as e:
        print(f"Error connecting to database: {e}")
        exit(1)

def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM DB_USER WHERE Username = %s", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def verify_user(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT Username, Password FROM DB_USER WHERE Username = %s", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(username, password_hash, email=None, tier_id=1, referer=None, is_admin=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "INSERT INTO DB_USER (Username, Password, Email, TierID, Refers_Username, is_admin) VALUES (%s, %s, %s, %s, %s, %s)"
    cursor.execute(query, (username, password_hash, email, tier_id, referer, is_admin))
    conn.commit()
    conn.close()
    return username

def get_all_agents():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    # Updated to include Cores and Ram
    query = """
        SELECT MachineID, IPAddress, LastCheckIn, OperatingSystem, Version, Cores, Ram, TierID 
        FROM MACHINE
    """
    cursor.execute(query)
    machine_data = cursor.fetchall()
    
    for machine in machine_data:
        # Map machine columns to keys for the front end
        machine['ID'] = machine.pop('MachineID')
        machine['IPAddress'] = machine.pop('IPAddress')
        # Assuming LastCheckIn is a datetime, convert to UNIX timestamp
        if machine['LastCheckIn']:
            machine['LastCheckin'] = int(machine['LastCheckIn'].timestamp())
        else:
            machine['LastCheckin'] = 0
        machine['Os'] = machine.pop('OperatingSystem')
        machine['OsVersion'] = machine.pop('Version')
        machine['TierID'] = machine.pop('TierID')
        # Ensure Cores and Ram are included
        # They remain with same keys from DB.
        machine['Cores'] = machine.get('Cores', 0)
        machine['Ram'] = machine.get('Ram', 0)
        # For tasks, you may need to refine this based on your schema:
        machine['Tasks'] = []
        # Example: If TASKS are linked by the same machine (though typically by user)
        task_cursor = conn.cursor(dictionary=True)
        task_query = "SELECT TaskID, TaskType, Username FROM TASKS WHERE Username = %s"
        task_cursor.execute(task_query, (machine['ID'],))
        tasks = task_cursor.fetchall()
        for task in tasks:
            machine['Tasks'].append({
                'TaskID': task['TaskID'],
                'Description': task['TaskType'],
                'AssignedBy': task['Username']
            })
    conn.close()
    return machine_data

def save_agent(agent_uuid, ip_address, status, os_name=None, os_version=None, web_shell_active=False):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    query = "SELECT id FROM agents WHERE uuid = %s"
    cursor.execute(query, (agent_uuid,))
    result = cursor.fetchone()
    if result:
        query = """
        UPDATE agents 
        SET ip_address = %s, last_checkin = %s, status = %s, os = %s, os_version = %s, web_shell_active = %s
        WHERE uuid = %s
        """
        cursor.execute(query, (ip_address, int(time.time()), status, os_name, os_version, web_shell_active, agent_uuid))
        agent_id = result['id']
    else:
        query = """
        INSERT INTO agents (uuid, ip_address, last_checkin, status, os, os_version, web_shell_active)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (agent_uuid, ip_address, int(time.time()), status, os_name, os_version, web_shell_active))
        agent_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return agent_id

def add_task(agent_id, task_id, description, status="Pending"):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = """
    INSERT INTO tasks (task_id, description, status, assigned_at, agent_id)
    VALUES (%s, %s, %s, %s, %s)
    """
    cursor.execute(query, (task_id, description, status, int(time.time()), agent_id))
    conn.commit()
    conn.close()

def update_task_status(task_id, status):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "UPDATE tasks SET status = %s WHERE task_id = %s"
    cursor.execute(query, (status, task_id))
    conn.commit()
    conn.close()
# ------------------------ END DATABASE FUNCTIONS ------------------------ #

# ------------------------ JWT FUNCTIONS ------------------------ #
def create_jwt(username, tier_id):
    """
    Generate a JWT with an expiration of 1 hour
    """
    payload = {
        'sub': username,
        'tier_id': tier_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token
# ------------------------ END JWT FUNCTIONS ------------------------ #

# ------------------------ BEGIN ROUTES ------------------------ #
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = get_user_by_username(session['username'])
    if not user:
        return redirect(url_for('login'))
    # Create a JWT token for the user
    token = create_jwt(user['Username'], user['TierID'])
    return render_template('index.html', username=user['Username'], tier_id=user['TierID'], token=token)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        success = request.args.get('success')
        return render_template('login.html', success=success)
    username = request.form.get('username')
    password = request.form.get('password')
    user = verify_user(username)
    if user and check_password_hash(user['Password'], password):
        session['username'] = user['Username']
        # Generate JWT token upon successful login
        token = create_jwt(user['Username'], user['TierID'])
        return render_template('index.html', username=user['Username'], tier_id=user['TierID'], token=token)
    else:
        return render_template('login.html', error="Invalid username or password.")

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    username = request.form.get('username')
    password = request.form.get("password")
    email = request.form.get("email")
    tier_id = request.form.get("tier_id")
    referer = request.form.get("referer")
    if referer:
        referer_user = get_user_by_username(referer)
        if not referer_user:
            return jsonify({'message': 'Referrer username does not exist!'}), 400
    else:
        referer = None  
    is_admin = 'is_admin' in request.form
    user = get_user_by_username(username)
    if user:
        return jsonify({'message': 'Username already exists!'}), 409
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    create_user(username, hashed_password, email, tier_id, referer, is_admin)
    return redirect(url_for('login', success='User created successfully'))

@app.route('/displayagents', methods=['GET'])
def display_agents():
    agents = get_all_agents()
    return jsonify(agents)

@app.route('/checkin', methods=['POST'])
def checkin_handler():
    return jsonify({"status": "success"})

@app.route('/deviceinfo', methods=['POST'])
def get_device_info():
    if request.method == 'POST':
        data = request.json
        agent_uuid = data.get('uuid', str(uuid.uuid4()))
        ip_address = request.remote_addr
        os_name = data.get('os', '')
        os_version = data.get('os_version', '')
        save_agent(
            agent_uuid=agent_uuid,
            ip_address=ip_address,
            status="Active",
            os_name=os_name,
            os_version=os_version
        )
        return jsonify({"status": "success", "agent_id": agent_uuid})
    return jsonify({"status": "error", "message": "Method not allowed"}), 405

@app.route('/searchdevices', methods=['GET'])
def search_devices():
    return jsonify({"status": "not implemented"})

@app.route('/status', methods=['POST'])
def declare_status():
    if request.method == 'POST':
        data = request.json
        agent_uuid = data.get('uuid')
        if not agent_uuid:
            return jsonify({"status": "error", "message": "UUID required"}), 400
        status = data.get('status', 'Active')
        ip_address = request.remote_addr
        save_agent(
            agent_uuid=agent_uuid,
            ip_address=ip_address,
            status=status
        )
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Method not allowed"}), 405

@app.route('/admin')
def admin_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = get_user_by_username(session['username'])
    if not user or not user['is_admin']:
        return "Forbidden: You must be an admin", 403
    return render_template('admin.html', tier_id=user['TierID'])

@app.route('/admin/add_machine', methods=['POST'])
def add_machine():
    if 'username' not in session:
        return redirect(url_for('login'))
    admin_user = get_user_by_username(session['username'])
    if not admin_user or not admin_user['is_admin']:
        return "Forbidden: You must be an admin", 403
    ip_address = request.form.get('ip_address')
    last_checkin_str = request.form.get('last_checkin')
    operating_system = request.form.get('operating_system')
    version = request.form.get('version')
    cores_str = request.form.get('cores')
    ram_str = request.form.get('ram')
    tier_id_str = request.form.get('tier_id')
    username = request.form.get('username')
    cores  = int(cores_str)
    ram    = int(ram_str)
    tier_id = int(tier_id_str)
    conn = get_db_connection()
    cursor = conn.cursor()
    sql = """
    INSERT INTO MACHINE (
      IPAddress,
      LastCheckIn,
      OperatingSystem,
      Version,
      Cores,
      Ram,
      TierID,
      Username
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    cursor.execute(sql, (
        ip_address,
        last_checkin_str,
        operating_system,
        version,
        cores,
        ram,
        tier_id,
        username
    ))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_account', methods=['POST'])
def update_account():
    if 'username' not in session:
        return redirect(url_for('login'))
    admin_user = get_user_by_username(session['username'])
    if not admin_user or not admin_user['is_admin']:
        return "Forbidden: You must be an admin", 403
    username = request.form.get('username')
    new_email = request.form.get('email')
    new_password = request.form.get('new_password')
    existing_user = get_user_by_username(username)
    if not existing_user:
        return "No user found with that username.", 400
    if new_email:
        existing_user['Email'] = new_email
    if new_password:
        hashed_pw = generate_password_hash(new_password, method='pbkdf2:sha256')
        existing_user['Password'] = hashed_pw
    conn = get_db_connection()
    cursor = conn.cursor()
    query = """
        UPDATE DB_USER
           SET Email = %s,
               Password = %s
         WHERE Username = %s
    """
    cursor.execute(query, (
        existing_user['Email'],
        existing_user['Password'],
        username
    ))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))
# ------------------------ END ROUTES ------------------------ #

if __name__ == '__main__':
    check_database()
    app.secret_key = os.getenv("SECRET")
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 443)), ssl_context='adhoc')
