# init_db.py (Clean Version)
import os
import time

# Set a dummy DATABASE_URL if not present, to satisfy db.py
if "DATABASE_URL" not in os.environ:
    print("FATAL: DATABASE_URL is not set. Cannot initialize database.")
    exit(1)

# Import ONLY what is needed for database operations
from app.db import engine
from app.models import Base

def main():
    print("Initializing database...")
    retries = 10
    while retries > 0:
        try:
            # This line requires all models to be imported so Base knows about them.
            # We do this by importing app.models
            import app.models
            Base.metadata.create_all(bind=engine, checkfirst=True)
            print("✅ Database initialized successfully.")
            break
        except Exception as e:
            print(f"Database connection failed: {e}")
            retries -= 1
            print(f"Retrying... {retries} retries left.")
            time.sleep(5)
    
    if retries == 0:
        print("❌ Could not initialize the database after several retries.")
        exit(1)

if __name__ == "__main__":
    main()