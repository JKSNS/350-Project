#!/bin/bash

# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Setup environment file
if [ ! -f .env ]; then
    cp .env.sample .env
    echo "Please update the .env file with your actual MySQL credentials."
fi

# Create MySQL database (you'll need to adjust this for your MySQL setup)
echo "Creating MySQL database..."
echo "CREATE DATABASE IF NOT EXISTS c2db;" | mysql -u root -p

echo "Setup complete! Don't forget to update your .env file with proper credentials."
