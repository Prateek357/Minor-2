import sys
import os

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app

app.run(host = 'localhost', port = '9000',debug=True)