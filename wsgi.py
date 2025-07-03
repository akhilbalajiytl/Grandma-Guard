# wsgi.py
# This file is the entry point for the Gunicorn server.

from app import app

if __name__ == "__main__":
    # This allows running the app directly with `python wsgi.py` for development
    # Note: Use Gunicorn for production, as configured in the Dockerfile
    app.run(host="0.0.0.0", port=5000, debug=True)
