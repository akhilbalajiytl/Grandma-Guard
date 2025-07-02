# app/__init__.py
import os

from dotenv import load_dotenv
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

load_dotenv()

# 1. DEFINE ALL CORE OBJECTS FIRST
# =================================

# Create the Flask app instance
app = Flask(__name__)

# --- Database Setup ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("No DATABASE_URL set for Flask application")

engine = create_engine(DATABASE_URL)

# Create a thread-safe session factory that can be used across the app
db_session = scoped_session(
    sessionmaker(autocommit=False, autoflush=False, bind=engine)
)


# 2. IMPORT AND REGISTER OTHER APP MODULES LAST
# ===============================================
# By the time these lines run, 'app' and 'db_session' are fully defined
# and can be successfully imported by 'main' and 'engine'.

from . import models

# Use the app context to ensure everything is set up correctly
with app.app_context():
    models.Base.metadata.create_all(bind=engine)  # Create tables if they don't exist

# Import the routes to register them with the app
from . import main

# Set up the scanner engine dependency
from .scanner import engine

engine.db_session = db_session


# 3. DEFINE APP-LEVEL BEHAVIOR
# =============================


@app.teardown_appcontext
def shutdown_session(exception=None):
    """This function is called when the application context ends."""
    db_session.remove()
