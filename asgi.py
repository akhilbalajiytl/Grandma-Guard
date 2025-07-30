"""ASGI Application Entry Point for GrandmaGuard.

This module creates an ASGI-compatible application object that allows the Flask-based
GrandmaGuard application to be served by ASGI servers like Uvicorn or Gunicorn with
uvicorn workers.

The module uses the WsgiToAsgi adapter to bridge the gap between WSGI (Flask) and
ASGI protocols, enabling modern async server deployment while maintaining the
existing Flask application structure.

Example:
    To run with uvicorn:
        uvicorn asgi:app --host 0.0.0.0 --port 5000
    
    To run with gunicorn:
        gunicorn asgi:app -k uvicorn.workers.UvicornWorker

Attributes:
    app: The ASGI-compatible application object wrapped from the Flask app.
"""

from asgiref.wsgi import WsgiToAsgi

from app import app as flask_app

# The WsgiToAsgi adapter takes your WSGI app (flask_app)
# and wraps it in an object that speaks the ASGI protocol.
# This 'app' object does NOT have a .run() method.
app = WsgiToAsgi(flask_app)
