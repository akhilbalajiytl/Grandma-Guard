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

# --- NEW: Trigger the Garak model pre-loading here ---
# By importing the module, the code inside garak_loader.py will execute,
# loading the models into the GARAK_DETECTORS variable before the server starts accepting requests.
# print("Triggering Garak pre-loading...")
# from .scanner import garak_loader  # <--- THIS IS THE TRIGGER

# print("Garak pre-loading process finished.")


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
    """This function is called when the application context ends."""
    db_session.remove()
