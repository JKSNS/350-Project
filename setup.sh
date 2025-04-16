#!/bin/bash

# Create virtual environment (optional but recommended)
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    cp .env.sample .env
    echo "Please update the .env file with your actual MySQL credentials."
fi

echo "Setup complete! Don't forget to verify your .env file has the correct database credentials."
