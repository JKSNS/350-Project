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
    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # now include Cores & Ram
    cursor.execute("""
        SELECT  MachineID, IPAddress, LastCheckIn,
                OperatingSystem, Version,
                Cores, Ram, TierID
          FROM  MACHINE
    """)
    machine_data = cursor.fetchall()

    for m in machine_data:
        mid = m['MachineID']

        cursor.execute(
            "SELECT TaskID, TaskType, MachineID FROM TASKS WHERE MachineID = %s",
            (mid,)
        )
        tasks = cursor.fetchall()

        # rename / reshape
        m['ID']          = m.pop('MachineID')
        m['IPAddress']   = m.pop('IPAddress')
        m['LastCheckin'] = m.pop('LastCheckIn')
        m['Os']          = m.pop('OperatingSystem')
        m['OsVersion']   = m.pop('Version')
        m['Cores']       = m.pop('Cores')     #  <-- NEW
        m['Ram']         = m.pop('Ram')       #  <-- NEW
        m['TierID']      = m.pop('TierID')
        m['Tasks']       = [
            {'TaskID': t['TaskID'], 'Description': t['TaskType']}
            for t in tasks
        ]

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





@app.route('/tasks/delete/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    sql = "DELETE FROM TASKS WHERE TaskID = %s"
    cursor.execute(sql, (task_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('tasks_page'))



# ------------------------ END DATABASE FUNCTIONS ------------------------ #



# ------------------------ BEGIN ROUTES ------------------------ #
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user_by_username(session['username'])

    # If you’re generating a JWT elsewhere, put it in `token`
    return render_template(
        'index.html',
        username=user['Username'],
        tier_id=user['TierID'],   #  <-- now available to the template
        token=None                #  <-- or your real token
    )


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

    # 1) FETCH all machines from DB so we can list them in the template
    machines = get_all_agents()  # or a separate function if you prefer

    # 2) Pass them into the admin.html
    return render_template('admin.html', machines=machines)



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

    # Use the new function to fetch tasks from the DB
    tasks = get_all_tasks_from_db()

    return render_template(
        'tasks.html',
        username=user['Username'],
        tier_id=user['TierID'],
        tasks=tasks
    )




@app.route('/admin/update_machine/<int:machine_id>', methods=['POST'])
def update_machine(machine_id):
    # Require admin
    if 'username' not in session:
        return redirect(url_for('login'))
    admin_user = get_user_by_username(session['username'])
    if not admin_user or not admin_user['is_admin']:
        return "Forbidden: You must be an admin", 403

    # Gather form data
    ip_address = request.form.get('ip_address')
    last_checkin = request.form.get('last_checkin')  # "2025-02-28T10:15"
    operating_system = request.form.get('operating_system')
    version = request.form.get('version')
    cores = int(request.form.get('cores', 0))
    ram = int(request.form.get('ram', 0))
    tier_id = int(request.form.get('tier_id', 0))
    username = request.form.get('username')

    # Update DB
    conn = get_db_connection()
    cursor = conn.cursor()
    sql = """
        UPDATE MACHINE
           SET IPAddress       = %s,
               LastCheckIn     = %s,
               OperatingSystem = %s,
               Version         = %s,
               Cores           = %s,
               Ram             = %s,
               TierID          = %s,
               Username        = %s
         WHERE MachineID       = %s
    """
    cursor.execute(sql, (
        ip_address,
        last_checkin,
        operating_system,
        version,
        cores,
        ram,
        tier_id,
        username,
        machine_id
    ))
    conn.commit()
    conn.close()

    # Redirect back to admin page or wherever you want
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_machine/<int:machine_id>', methods=['POST'])
def delete_machine(machine_id):
    # Require admin
    if 'username' not in session:
        return redirect(url_for('login'))
    admin_user = get_user_by_username(session['username'])
    if not admin_user or not admin_user['is_admin']:
        return "Forbidden: You must be an admin", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    # Delete
    sql = "DELETE FROM MACHINE WHERE MachineID = %s"
    cursor.execute(sql, (machine_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))






@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch the current user record (keys will match your DB schema)
    user = get_user_by_username(session['username'])
    if not user:
        # If no matching user is found, redirect to logout
        return redirect(url_for('logout'))

    message = None

    if request.method == 'POST':
        # Get form values; if a field is blank, use the existing value.
        new_username = request.form.get('username', '').strip() or user['Username']
        new_email = request.form.get('email', '').strip() or user['Email']
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        # 1) If the user entered a new password, ensure it matches confirmation
        if new_password:
            if new_password != confirm_password:
                message = "Passwords do not match."
                return render_template('profile.html', user=user, message=message)

        # 2) If the username has changed, check if it's already taken by another user
        if new_username != user['Username']:
            existing_user = get_user_by_username(new_username)
            if existing_user:
                message = f"Username '{new_username}' is already in use."
                return render_template('profile.html', user=user, message=message)

        # 3) Retrieve the old password hash from the user record.
        # Since your column is named "PASSWORD" in the DB, use that key.
        password_hash = user.get('PASSWORD')
        if password_hash is None:
            # DEBUG: Log the full user record if 'PASSWORD' is missing.
            print("DEBUG: 'PASSWORD' key missing from user dictionary:", user)
            message = "Error: Could not retrieve current password from your record."
            return render_template('profile.html', user=user, message=message)

        # 4) If a new password was provided, hash it and update the password hash.
        if new_password:
            password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')

        # 5) Update the user record in the database.
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE DB_USER
                   SET Username = %s,
                       Email = %s,
                       PASSWORD = %s
                 WHERE Username = %s
            """, (new_username, new_email, password_hash, user['Username']))
            conn.commit()
            conn.close()

            # If the username was changed, update it in the session.
            if new_username != user['Username']:
                session['username'] = new_username

            # Reload updated user data.
            user = get_user_by_username(new_username)
            message = "Profile updated successfully."
        except Exception as e:
            message = f"Error updating profile: {e}"

    return render_template('profile.html', user=user, message=message)






def get_all_tasks_from_db():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
         SELECT TaskID, MachineID, TaskType, LastCheckIn
           FROM TASKS
    """)
    tasks_data = cursor.fetchall()
    tasks = []
    for task in tasks_data:
         tasks.append({
             'id': task['TaskID'],              # Unique ID for each task (for update/delete)
             'machine_id': task['MachineID'],     # The machine identifier
             'command': task['TaskType'],         # The command (or task type)
             'last_checkin': task['LastCheckIn']  # The LastCheckIn date/time
         })
    conn.close()
    return tasks

@app.route('/tasks/update/<int:task_id>', methods=['POST'])
def update_task(task_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    # Use the updated field name 'last_checkin'
    machine_id   = request.form.get('machine_id')
    command      = request.form.get('command')
    last_checkin = request.form.get('last_checkin')

    conn = get_db_connection()
    cursor = conn.cursor()
    sql = """
        UPDATE TASKS
           SET MachineID   = %s,
               TaskType    = %s,
               LastCheckIn = %s
         WHERE TaskID      = %s
    """
    cursor.execute(sql, (machine_id, command, last_checkin, task_id))
    conn.commit()
    conn.close()

    return redirect(url_for('tasks_page'))

@app.route('/tasks/add_task', methods=['POST'])
def add_new_task():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Retrieve form data using the updated field name 'last_checkin'
    machine_id   = request.form.get('machine_id')
    command      = request.form.get('command')
    last_checkin = request.form.get('last_checkin')
    
    # Insert into TASKS including the LastCheckIn column
    conn = get_db_connection()
    cursor = conn.cursor()
    insert_sql = """
        INSERT INTO TASKS (TaskType, MachineID, LastCheckIn)
        VALUES (%s, %s, %s)
    """
    cursor.execute(insert_sql, (command, machine_id, last_checkin))
    conn.commit()
    conn.close()
    
    return redirect(url_for('tasks_page'))






# ------------------------ END ROUTES ------------------------ #


# ------------------------ MAIN ------------------------ #
if __name__ == '__main__':
    check_database()
    app.secret_key = os.getenv("SECRET")
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 443)), ssl_context='adhoc')
