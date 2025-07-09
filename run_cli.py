#!/usr/bin/env python3
# pyright: reportMissingImports=false
import argparse
import os

try:
    from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]
except ModuleNotFoundError:
    raise ModuleNotFoundError(
        "python-dotenv module is not installed. Install with 'pip install python-dotenv'."
    )

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
    parser.add_argument("--scan-name", required=True, help="Name of the test run")
    parser.add_argument(
        "--api-endpoint", required=True, help="API endpoint URL for the scan"
    )
    parser.add_argument("--api-key", required=True, help="API key for authentication")
    parser.add_argument(
        "--openai-model",
        default="gpt-3.5-turbo",
        help="OpenAI model name (default: gpt-3.5-turbo)",
    )

    # Now that the arguments are defined, this will work correctly.
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

    start_scan_thread(
        run_id,
        args.model_name,
        args.api_endpoint,
        args.api_key,
        args.openai_model,
        wait=True,
    )
    print("CLI script finished.")


if __name__ == "__main__":
    main()
