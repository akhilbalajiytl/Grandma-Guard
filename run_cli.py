#!/usr/bin/env python3
import argparse
import os

from dotenv import load_dotenv

# --- ROBUST .env LOADING ---
project_root = os.path.dirname(os.path.abspath(__file__))
dotenv_path = os.path.join(project_root, ".env")
load_dotenv(dotenv_path=dotenv_path, override=True)

# For CI, we use a temporary SQLite DB. For local, we use DATABASE_URL_LOCAL.
is_ci = os.getenv("CI") == "true"
if is_ci:
    os.environ["DATABASE_URL"] = "sqlite:///ci_scan_results.db"
else:
    # For local CLI runs, connect to the Docker MySQL database
    if "DATABASE_URL_LOCAL" not in os.environ:
        print("Error: DATABASE_URL_LOCAL not found in your .env file for local run.")
        exit(1)
    os.environ["DATABASE_URL"] = os.environ["DATABASE_URL_LOCAL"]

# Now we can safely import our app modules
from app import db_session
from app.models import TestRun
from app.scanner.engine import start_scan_thread


def main():
    parser = argparse.ArgumentParser(description="Run CI/CD Scan for the application")
    # ... (all argument parsing is fine) ...
    args = parser.parse_args()

    session = db_session()
    try:
        new_run = TestRun(model_name=args.model_name)
        session.add(new_run)
        session.commit()
        run_id = new_run.id
        print(f"Created new test run with id: {run_id}")
    except Exception as e:
        print(f"Error creating test run: {e}")
        session.rollback()
        return
    finally:
        session.close()

    # --- THIS IS THE FIX ---
    # The background scanner will now connect to the MySQL database
    # We pass wait=True to ensure the main script doesn't exit prematurely.
    start_scan_thread(
        run_id,
        args.model_name,
        args.api_endpoint,
        args.api_key,
        args.openai_model,
        wait=True,  # This will block here until the scan is finished.
    )
    print("CLI script finished.")


if __name__ == "__main__":
    main()
