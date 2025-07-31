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

# --- THE KEY PART: Worker Initialization Hook ---
# We are disabling eager loading to ensure a stable startup.
# The get_analyzer() function will now load the models on the first request ("lazy loading").
# def post_worker_init(worker):
#     """Initialize worker process with pre-loaded dependencies.
    
#     This hook runs after each worker process is forked and initialized.
#     It pre-loads the Garak ForensicAnalyzer to reduce cold start latency
#     for security analysis requests.
    
#     Args:
#         worker: The Gunicorn worker instance being initialized.
        
#     Note:
#         This function uses singleton-based loading to ensure thread-safe
#         initialization of the analyzer across worker processes.
#     """
#     from app.scanner.garak_loader import get_analyzer # We only need the get_analyzer
#     worker.log.info(f"Worker (pid: {worker.pid}) is pre-loading the Garak ForensicAnalyzer.")
#     get_analyzer() # This will trigger the safe, singleton-based loading.
#     worker.log.info(f"✅ Garak ForensicAnalyzer is ready for worker (pid: {worker.pid}).")