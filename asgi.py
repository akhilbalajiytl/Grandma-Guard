# asgi.py
# This file creates an ASGI-compatible application object for Uvicorn/Gunicorn to run.

from asgiref.wsgi import WsgiToAsgi

from app import app as flask_app

# The WsgiToAsgi adapter takes your WSGI app (flask_app)
# and wraps it in an object that speaks the ASGI protocol.
# This 'app' object does NOT have a .run() method.
app = WsgiToAsgi(flask_app)
