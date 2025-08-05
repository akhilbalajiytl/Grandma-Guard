# app/__init__.py (Final and Correct)

# --- PHASE 1: MINIMAL IMPORTS ---
import os
from dotenv import load_dotenv
from flask import Flask
from flask_login import LoginManager

# --- THIS IS THE CORRECT PLACEMENT FOR THE BROKER IMPORT ---
# 1. This line is the ONLY one we are adding.
# 2. It must come BEFORE `from . import tasks` is imported by any other module.
# 3. This ensures the Dramatiq broker is configured for the webapp process
#    before any tasks are defined or sent.
from . import broker

# Import the engine and session from our new db.py
from .db import engine, db_session

# --- CORE APP OBJECTS ---
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'a-very-secret-key-in-dev')

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'main.login'

from .auth import get_user
@login_manager.user_loader
def load_user(user_id):
    return get_user(user_id)

# --- IMPORTS AND REGISTRATION ---
# IMPORTANT: These imports must come AFTER the app object and broker are configured.
from . import models
from .main import main as main_blueprint
app.register_blueprint(main_blueprint)
# We no longer need to import tasks here, as `main.py` will import it directly.

# --- DEFINE APP-LEVEL BEHAVIOR (like teardown) ---
@app.teardown_appcontext
def shutdown_session(exception=None):
    """Clean up database session when the application context ends."""
    db_session.remove()