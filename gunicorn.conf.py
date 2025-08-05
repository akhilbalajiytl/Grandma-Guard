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
workers = 2

# Worker class
worker_class = "uvicorn.workers.UvicornWorker"

# We are disabling preloading. Each worker will be a fresh, independent process.
preload_app = False
# --------------------------------

# Logging
loglevel = "debug"
accesslog = "-"
errorlog = "-"

# Timeouts
timeout = 300
graceful_timeout = 60

# --- WE ALSO NEED THE POST_WORKER_INIT HOOK ---
# With preload=True, the models are loaded in the master.
# We still want to ensure each worker has a reference to the instance.
# So, we will define the hook here to call the loader.
# def post_worker_init(worker):
#     """Gunicorn hook to initialize shared resources."""
#     worker.log.info(f"Worker {worker.pid} initializing...")
#     from app.scanner.garak_loader import get_analyzer
#     get_analyzer() # This will ensure the singleton is populated in the master before fork.
#     worker.log.info(f"Worker {worker.pid} initialization complete.")
