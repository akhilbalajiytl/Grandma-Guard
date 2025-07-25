# gunicorn.conf.py
# Gunicorn configuration file

# Networking
bind = "0.0.0.0:5000"
workers = 1  # Start with 2 workers, can increase later

# Load the application code once in the master process before forking.
# This ensures the heavy ML models are loaded only ONCE into shared memory.
preload_app = False
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
    """
    This function is called when a Gunicorn worker process is started.
    This is the correct place to load models, as each worker gets its own process.
    """
    worker.log.info(f"Worker process (pid: {worker.pid}) starting model loading.")
    try:
        # Import and instantiate the classifier HERE.
        from app.scanner.smart_classifier import SmartClassifier
        
        # This will load the model onto the GPU for THIS worker process.
        smart_classifier_instance = SmartClassifier()
        
        worker.log.info(f"✅ Models loaded successfully in worker (pid: {worker.pid}).")
    except Exception as e:
        worker.log.error(f"❌ Failed to load models in worker (pid: {worker.pid}). Error: {e}")
        # Optionally re-raise the exception to stop a worker that fails to load
        raise
