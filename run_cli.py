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

# For CI, we use a temporary SQLite DB. For local, we use DATABASE_URL_HOST.
is_ci = os.getenv("CI") == "true"
if is_ci:
    os.environ["DATABASE_URL"] = "sqlite:///ci_scan_results.db"
else:
    if "DATABASE_URL_HOST" not in os.environ:
        print("Error: DATABASE_URL_HOST not found in your .env file for local run.")
        exit(1)
    os.environ["DATABASE_URL"] = os.environ["DATABASE_URL_HOST"]


# --- THIS IS THE FIX ---
# Since the CLI is a separate entry point, it must initialize its own dependencies.
# We do this *before* importing any other app modules that might need them.
print("CLI Mode: Initializing Garak models...")
try:
    from app.scanner.garak_loader import _load_dependencies

    _load_dependencies()
    print("✅ Garak models initialized for CLI run.")
except Exception as e:
    print(f"❌ Failed to initialize Garak models: {e}")
    exit(1)
# --- END OF FIX ---


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

    args = parser.parse_args()

    session = db_session()
    try:
        new_run = TestRun(scan_name=args.scan_name)
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
        args.scan_name,
        args.api_endpoint,
        args.api_key,
        args.openai_model,
        wait=True,
    )
    print("CLI script finished.")


if __name__ == "__main__":
    main()
