# wsgi.py
# This file is the entry point for running the application in local
# development mode (e.g., python wsgi.py).

from app import app

if __name__ == "__main__":
    # Call .run() on the original Flask 'app' object.
    app.run(host="0.0.0.0", port=5000, debug=True)
