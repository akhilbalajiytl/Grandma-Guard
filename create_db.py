# create_db.py (Final, Self-Contained Version)

import os
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError
from dotenv import load_dotenv

# --- Import ONLY the Base object from the models file ---
# This is a clean import and does NOT trigger app/__init__.py
from app.models import Base 

# Load environment variables to get the DATABASE_URL
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("DB Initializer Error: DATABASE_URL not set.")
    exit(1)

print("DB Initializer: Waiting for database...")
engine = create_engine(DATABASE_URL)

# Retry loop to wait for the database to be ready
retries = 15
while retries > 0:
    try:
        connection = engine.connect()
        connection.close()
        print("DB Initializer: Database connection successful.")
        break
    except OperationalError as e:
        retries -= 1
        print(f"DB Initializer: Database not ready, retrying... ({retries} left)")
        time.sleep(5)
else:
    print("DB Initializer: Could not connect to DB. Aborting.")
    exit(1)

print("DB Initializer: Creating all tables...")
try:
    # Use the imported Base and the local engine
    Base.metadata.create_all(bind=engine)
    print("DB Initializer: Tables created successfully.")
except Exception as e:
    print(f"DB Initializer: Error creating tables: {e}")
    exit(1)