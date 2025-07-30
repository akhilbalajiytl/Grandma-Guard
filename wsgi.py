"""WSGI Application Entry Point for GrandmaGuard.

This module serves as the entry point for running the GrandmaGuard application
in local development mode using Flask's built-in development server.

The module imports the Flask application instance and provides a simple way to
start the server for development and testing purposes. For production deployments,
use the ASGI entry point (asgi.py) with proper ASGI servers.

Example:
    Run the development server:
        python wsgi.py
    
    The server will start on host 0.0.0.0:5000 with debug mode enabled.

Note:
    This entry point is intended for development use only. For production
    deployments, use proper WSGI/ASGI servers like Gunicorn or Uvicorn.
"""

from app import app

if __name__ == "__main__":
    # Call .run() on the original Flask 'app' object.
    app.run(host="0.0.0.0", port=5000, debug=True)
