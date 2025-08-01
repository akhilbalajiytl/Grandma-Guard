"""Gunicorn Configuration for GrandmaGuard Application.

This module contains the Gunicorn WSGI server configuration for running the
GrandmaGuard application in production. It configures worker processes, logging,
timeouts, and includes a worker initialization hook for pre-loading the Garak
ForensicAnalyzer to improve response times.

The configuration optimizes the server for the specific needs of the GrandmaGuard
security scanning application, including proper timeout handling for potentially
long-running security analysis tasks.

Configuration includes:
    - Network binding (host and port)
    - Worker process configuration
    - ASGI worker class for async support
    - Logging configuration
    - Timeout settings for security scans
    - Worker initialization for pre-loading heavy dependencies

Example:
    Start the server with this configuration:
        gunicorn -c gunicorn.conf.py asgi:app

Note:
    The post_worker_init hook pre-loads the Garak ForensicAnalyzer in each
    worker process to reduce cold start latency for security scans.
"""

# Networking
bind = "0.0.0.0:5000"
workers = 2 # You can safely increase this now

# Worker class
worker_class = "uvicorn.workers.UvicornWorker"

# Logging
loglevel = "debug"
accesslog = "-"
errorlog = "-"

# Timeouts
timeout = 300
graceful_timeout = 60

# --- The Key Part: Worker Initialization Hook ---
# This is the most robust way to load models in a multi-worker setup
# without using preload_app, which can cause fork-related issues.
def post_worker_init(worker):
    from app.scanner.garak_loader import get_analyzer
    worker.log.info(f"Worker (pid: {worker.pid}) is pre-loading the Garak ForensicAnalyzer.")
    get_analyzer() # This will trigger the safe, singleton-based loading in each worker.
    worker.log.info(f"✅ Garak ForensicAnalyzer is ready for worker (pid: {worker.pid}).")
