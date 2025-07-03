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

print("Pre-loading Garak detectors to prevent threading issues...")
try:
    # Pre-loading can stay here as it depends only on installed packages
    from garak.detectors import dan, unsafe_content

    _ = unsafe_content.ToxicCommentModel()
    _ = dan.DAN()
    print("✅ Garak detectors pre-loaded successfully.")
except Exception as e:
    print(f"❌ Warning: Could not pre-load Garak detectors: {e}")


# --- PHASE 3: IMPORT AND REGISTER YOUR APP'S MODULES ---
# By importing these here, AFTER `app` and `db_session` are defined,
# we avoid circular import errors.

from . import (  # noqa: E402
    models,  # noqa: F401 - flake8 might think this is unused, but it's needed to register models
)

# Use the app context to ensure tables are created correctly
with app.app_context():
    models.Base.metadata.create_all(bind=engine)

# Import routes to register them with the Flask app. The 'main' module
# itself isn't used directly here, but importing it runs its code.
from . import main  # noqa: E402, F401

# Set up the scanner engine dependency now that db_session is ready
from .scanner import engine  # noqa: E402

engine.db_session = db_session


# --- DEFINE APP-LEVEL BEHAVIOR (like teardown) ---
@app.teardown_appcontext
def shutdown_session(exception=None):
    """This function is called when the application context ends."""
    db_session.remove()
