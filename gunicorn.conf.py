# gunicorn.conf.py
# Gunicorn configuration file

# Networking
bind = "0.0.0.0:5000"
workers = 1  # Start with 2 workers, can increase later

# Worker class
worker_class = "uvicorn.workers.UvicornWorker"

# Logging
loglevel = "debug"
accesslog = "-"  # Log access requests to stdout
errorlog = "-"  # Log errors to stderr

# Timeouts
timeout = 300  # Long timeout for initial model loading in workers
graceful_timeout = 60  # Give workers time to finish requests on shutdown


# --- The Key Part: Worker Initialization Hook ---
def post_worker_init(worker):
    worker.log.info("Worker process (pid: %s) starting model loading.", worker.pid)
    try:
        # Call the new, more comprehensive loader function
        from app.scanner.garak_loader import _load_dependencies

        _load_dependencies()
        worker.log.info(
            "✅ Dependencies loaded successfully in worker (pid: %s).", worker.pid
        )
    except Exception as e:
        worker.log.error(
            "❌ Failed to load dependencies in worker (pid: %s). Error: %s",
            worker.pid,
            e,
        )
        raise
