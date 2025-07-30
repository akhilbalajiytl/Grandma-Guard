"""GrandmaGuard Flask Application Initialization Module.

This module serves as the central initialization hub for the GrandmaGuard Flask web application,
an AI security scanning system designed to detect and prevent various forms of AI misuse,
including jailbreak attempts, prompt injections, and other security threats.

The module follows a three-phase initialization approach:
1. PHASE 1: Import all required dependencies
2. PHASE 2: Create core application objects (Flask app, database engine, sessions)
3. PHASE 3: Import and register application modules, routes, and scanner components

Key Features:
    - Flask web application initialization with database connectivity
    - SQLAlchemy ORM setup with scoped sessions for thread safety
    - Optional ML model pre-loading for performance optimization
    - Database table creation and migration support
    - Scanner engine integration with database session dependency injection
    - Proper application context teardown handling

Architecture:
    The application uses a factory pattern approach where the Flask app instance
    is created at module level, allowing for easy configuration and testing.
    Database sessions are scoped to ensure thread-safety in multi-worker deployments.

Environment Variables:
    DATABASE_URL: Required database connection string for SQLAlchemy engine

Example:
    This module is typically imported by the main application runner:
    
    >>> from app import app
    >>> app.run(debug=True)

Notes:
    - ML model pre-loading is currently commented out but can be enabled for production
    - The module automatically creates database tables on first run
    - Scanner engine is configured with database session dependency injection
"""

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
with app.app_context():
     # Add checkfirst=True to prevent errors on restart
    models.Base.metadata.create_all(bind=engine, checkfirst=True)

# Import routes to register them with the Flask app.
from . import main

# Set up the scanner engine dependency now that db_session is ready
from .scanner import engine

engine.db_session = db_session


# --- DEFINE APP-LEVEL BEHAVIOR (like teardown) ---
@app.teardown_appcontext
def shutdown_session(exception=None):
    """Clean up database session when the application context ends.
    
    This teardown handler ensures proper cleanup of SQLAlchemy database sessions
    when Flask application context ends, preventing connection leaks and ensuring
    proper resource management in multi-request scenarios.
    
    Args:
        exception (Exception, optional): Any exception that occurred during request
            processing. Defaults to None.
            
    Notes:
        - Called automatically by Flask at the end of each request
        - Removes the scoped session to return connections to the pool
        - Essential for proper database connection management
        - Works with both successful requests and error conditions
    """
    db_session.remove()
