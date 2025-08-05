#!/usr/bin/env python3
"""Command Line Interface for GrandmaGuard Security Scanning.

This module provides a command-line interface for running GrandmaGuard security
scans in CI/CD pipelines and automated testing environments. It initializes
the necessary dependencies, creates test runs, and executes comprehensive
security scans against specified API endpoints.

The CLI tool is designed for integration with continuous integration systems,
allowing automated security testing of AI applications and APIs. It supports
configurable scan parameters and handles both local and CI execution environments.

Features:
    - Automated dependency initialization for CLI execution
    - Database management for test run tracking
    - Configurable API endpoint and authentication
    - Support for different OpenAI model backends
    - CI/CD environment detection and configuration
    - Comprehensive error handling and logging

Example:
    Run a security scan:
        python run_cli.py --scan-name "Production API Test" \\
                         --api-endpoint "https://api.example.com/chat" \\
                         --api-key "your-api-key" \\
                         --openai-model "gpt-4"

Environment Variables:
    DATABASE_URL_HOST: Database connection string for local runs
    CI: Set to "true" for CI environment detection

Requirements:
    - Proper .env configuration for database access
    - Valid API endpoint and authentication credentials
    - Initialized Garak models for security testing

Note:
    The CLI handles environment detection automatically, using SQLite for CI
    environments and the configured database for local development.
"""
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
    # We need to add app to the path to import from it
    import sys
    sys.path.append(project_root)
    from app.scanner.garak_loader import get_analyzer
    
    get_analyzer() # This triggers the singleton loading process.
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
    parser = argparse.ArgumentParser(description="Run a security scan from the command line")
    parser.add_argument("--scan-name", required=True, help="Name of the test run")
    parser.add_argument("--api-endpoint", required=True, help="API endpoint URL of the model to test")
    parser.add_argument("--api-key", required=True, help="API key for the model to test")
    parser.add_argument("--model-id", required=True, help="Model identifier (e.g., ilmu-v1.5, gpt-4o-mini)")

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

    # Call the engine with the 'wait=True' flag for CLI execution
    start_scan_thread(
        run_id,
        args.scan_name,
        args.api_endpoint,
        args.api_key,
        args.model_id,
        wait=True,
    )
    print("CLI script finished.")

if __name__ == "__main__":
    main()
