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
# app/__init__.py (Corrected)

# --- PHASE 1: MINIMAL IMPORTS ---
import os
from dotenv import load_dotenv
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from flask_login import LoginManager

# --- PHASE 2: CORE APP OBJECTS ---
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'a-very-secret-key-in-dev')

# --- Database Setup ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("No DATABASE_URL set for Flask application")
engine = create_engine(DATABASE_URL)
db_session = scoped_session(
    sessionmaker(autocommit=False, autoflush=False, bind=engine)
)

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'main.login'

# Import the user loader function from our new auth module
from .auth import get_user

# Tell the login manager how to load a user
@login_manager.user_loader
def load_user(user_id):
    return get_user(user_id)

# --- PHASE 3: DEFERRED IMPORTS AND REGISTRATION ---
from . import models

with app.app_context():
    models.Base.metadata.create_all(bind=engine, checkfirst=True)

from .main import main as main_blueprint
app.register_blueprint(main_blueprint)



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
