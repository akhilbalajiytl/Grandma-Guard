# gunicorn.conf.py
# Gunicorn configuration file

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
def post_worker_init(worker):
    from app.scanner.garak_loader import get_analyzer # We only need the get_analyzer
    worker.log.info(f"Worker (pid: {worker.pid}) is pre-loading the Garak ForensicAnalyzer.")
    get_analyzer() # This will trigger the safe, singleton-based loading.
    worker.log.info(f"✅ Garak ForensicAnalyzer is ready for worker (pid: {worker.pid}).")