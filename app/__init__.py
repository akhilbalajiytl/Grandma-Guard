# app/__init__.py

# --- PHASE 1: ALL IMPORTS AT THE TOP ---
import os

from dotenv import load_dotenv
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

# --- PHASE 2: CREATE CORE APP OBJECTS ---
load_dotenv()

# Create the Flask app instance
app = Flask(__name__)

# --- Database Setup ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("No DATABASE_URL set for Flask application")

engine = create_engine(DATABASE_URL)
db_session = scoped_session(
    sessionmaker(autocommit=False, autoflush=False, bind=engine)
)

# Trigger the model pre-loading here.
# Because preload_app=True in gunicorn.conf.py, this code will run ONCE
# in the master process before any workers are created.
#print("Flask App Initializing: Triggering ML model pre-loading...")
#try:
    #from .scanner.smart_classifier import SmartClassifier
    # You can also preload other models here if needed
    # from .scanner.garak_loader import _load_dependencies
    
    # Instantiate the classifier to load it onto the GPU
    # We can store it in a global variable if we want to reuse it, or just load it.
    # For now, just loading it is enough to prove it works.
    #smart_classifier_instance = SmartClassifier()
    
    #print("✅ ML Models pre-loaded successfully in master process.")
#except Exception as e:
    #print(f"❌ CRITICAL: Failed to pre-load ML models in master process: {e}")
    # Optionally, you might want to exit if models fail to load
    # import sys
    # sys.exit(1)


# --- PHASE 3: IMPORT AND REGISTER YOUR APP'S MODULES ---
# (The rest of the file remains the same)

from . import (
    models,
)

# Use the app context to ensure tables are created correctly
#with app.app_context():
     # Add checkfirst=True to prevent errors on restart
    #models.Base.metadata.create_all(bind=engine, checkfirst=True)

# Import routes to register them with the Flask app.
from . import main

# Set up the scanner engine dependency now that db_session is ready
from .scanner import engine

engine.db_session = db_session


# --- DEFINE APP-LEVEL BEHAVIOR (like teardown) ---
@app.teardown_appcontext
def shutdown_session(exception=None):
    """This function is called when the application context ends."""
    db_session.remove()
