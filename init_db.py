# init_db.py
import time
from app.db import engine
from app.models import Base

def main():
    print("Initializing database...")
    retries = 10
    while retries > 0:
        try:
            # The checkfirst=True is still a good idea here.
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